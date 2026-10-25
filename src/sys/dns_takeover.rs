//! System DNS takeover while a TUN core with a DNS module runs.
//!
//! The core's leak block drops port-53 egress outside the TUN. The resolver
//! still holds the *other* adapters' DNS servers in its server set, and those
//! queries never answer, so a name the tunnel answers with a negative result
//! costs the whole retry schedule: Windows completes a query only after every
//! configured server answered, and a NODATA from the tunnel DNS is not final.
//! Measured with a `wired` adapter that kept its DHCP server: about ten
//! seconds for one AAAA query, and the same for one TXT or NXDOMAIN query.
//!
//! The DNS client sends each query from the interface that owns the server,
//! so a route cannot move those queries into the tunnel: only the adapter's
//! own server list decides where they go. This module captures every connected
//! physical adapter with DNS servers — the resolver asks all of them, so
//! pointing only one adapter at the tunnel would still let a blocked server on
//! another stall a negative answer — and points each captured list at the
//! in-tun address for the session, for each address family the tunnel carries.
//! Loopback, the TUN, virtual switches, and disconnected adapters are left
//! alone. The captured list is restored when the session ends or an adapter
//! disconnects.
//!
//! Restoring is the safety-critical half, so the capture is written to a
//! record file *before* any change. `release` restores from that record and
//! deletes it, and the helper calls `release` at every teardown path, on its
//! own exit path, and once at startup, so a helper that dies hard leaves a
//! record that the next helper repairs instead of a machine with a dead DNS
//! server. An adapter that is absent at restore time is restored through its
//! saved registry configuration; only a failed registry write keeps its entry.
//!
//! The write API (`SetInterfaceDnsSettings`) exists from Windows 10 2004
//! (build 19041). It is resolved from `iphlpapi.dll` at first use rather than
//! imported at load time, so a build without it starts normally and simply
//! skips the takeover; the capture/restore record still works, and a record
//! from a build that had the export is repaired through the registry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{ERROR_SUCCESS, FARPROC, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{GUID, HSTRING, PCSTR, PWSTR};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};

use super::aligned::AlignedBuffer;
use super::netif::sockaddr_ip;
use crate::diag::{Diag, DiagError};
use crate::i18n::Key;

/// Registry path of the IPv4 interface configuration (`NameServer` holds the
/// static server list; an absent or empty value means the servers come from
/// DHCP).
const TCPIP4_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
/// Registry path of the IPv6 interface configuration.
const TCPIP6_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

/// The two registry roots that hold every adapter's DNS configuration. The
/// network watcher subscribes to both: `NotifyIpInterfaceChange` does not
/// report a DNS server change, but a DHCP renewal or a manual change writes
/// these keys.
pub(crate) const REGISTRY_PATHS: [&str; 2] = [TCPIP4_INTERFACES, TCPIP6_INTERFACES];

/// What one write hands a family: a server list, or the revert to whatever
/// source configured it before (DHCP or router advertisement). The interface
/// settings API has no third form — an empty string is a no-op — so "no
/// servers" is not expressible and never written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Servers<'a> {
    List(&'a [String]),
    Revert,
}

/// One adapter's DNS servers for one address family, as captured before the
/// takeover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FamilyState {
    /// The servers the adapter listed.
    servers: Vec<String>,
    /// Whether the list is a static configuration. A dynamic list (DHCP or
    /// router advertisement) is restored by reverting to that source instead
    /// of writing the captured servers back.
    static_servers: bool,
}

impl FamilyState {
    /// The server list the takeover writes for this family: the in-tun
    /// address the tunnel owns for it.
    fn takeover_servers(&self, target: IpAddr) -> Vec<String> {
        vec![target.to_string()]
    }

    /// The write a restore performs: a static list goes back as it was, a
    /// dynamic one reverts to the source that configured it.
    fn restore_write(&self) -> Servers<'_> {
        if self.static_servers {
            Servers::List(&self.servers)
        } else {
            Servers::Revert
        }
    }
}

/// One adapter captured for the takeover: its stable identity, its label for
/// the log, and the per-family state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// `GetAdaptersAddresses`' `AdapterName`: the interface GUID in braces.
    /// The registry keys and the restore match use this same spelling, and
    /// the comparison is case-insensitive because the API and the registry
    /// disagree on letter case.
    adapter: String,
    /// The friendly name, for log lines only.
    alias: String,
    /// IPv4 state, absent when the adapter listed no IPv4 server.
    v4: Option<FamilyState>,
    /// IPv6 state, absent when the adapter listed no IPv6 server.
    v6: Option<FamilyState>,
}

/// The captured pre-takeover state, persisted as the record file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
struct Record {
    entries: Vec<Entry>,
}

/// `MIB_IF_ROW2.InterfaceAndOperStatusFlags.HardwareInterface` is bit 0.
const HARDWARE_INTERFACE_BIT: u8 = 1;

/// One adapter as enumerated: the fields the capture reads, split from the
/// Windows walk so the decisions stay testable without a live system.
/// (`NET_LUID_LH` is a union without `Debug` or `PartialEq`, so this view
/// compares by its other fields.)
#[derive(Clone)]
struct AdapterView {
    adapter: String,
    alias: String,
    if_index: u32,
    if_type: u32,
    up: bool,
    /// `MIB_IF_ROW2.InterfaceAndOperStatusFlags.HardwareInterface`: a real
    /// adapter, not a virtual switch or tunnel.
    physical: bool,
    luid: windows::Win32::NetworkManagement::Ndis::NET_LUID_LH,
    dns: Vec<IpAddr>,
}

/// The static IPv4/IPv6 server lists of one adapter, or `None` when the
/// family is configured dynamically. The registry is the only source that
/// separates a static list from a DHCP-provided one.
fn static_servers(adapter: &str, ipv6: bool) -> Option<Vec<String>> {
    let root = if ipv6 {
        TCPIP6_INTERFACES
    } else {
        TCPIP4_INTERFACES
    };
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"{root}\{adapter}"))
        .ok()?;
    let value: String = key.get_value("NameServer").ok()?;
    let servers: Vec<String> = value
        .split([',', ' '])
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.trim().to_string())
        .collect();
    (!servers.is_empty()).then_some(servers)
}

/// Split the enumerated servers into the per-family capture. `None` means the
/// adapter listed no server of that family, so the family is left alone.
fn family_state(
    adapter: &str,
    servers: &[IpAddr],
    ipv6: bool,
    target: IpAddr,
) -> Option<FamilyState> {
    let matching: Vec<String> = servers
        .iter()
        .filter(|ip| ip.is_ipv6() == ipv6)
        .map(IpAddr::to_string)
        .collect();
    if matching.is_empty() {
        return None;
    }
    // A fresh capture that already lists the takeover address cannot know the
    // original servers: another session, or a record lost with its helper,
    // may have written it. Recording it as the original would restore the
    // dead tunnel address forever, so treat the family as dynamic and let the
    // restore revert it to DHCP.
    if matching
        .iter()
        .any(|server| server.parse::<IpAddr>().ok() == Some(target))
    {
        return Some(FamilyState {
            servers: Vec::new(),
            static_servers: false,
        });
    }
    Some(FamilyState {
        servers: matching,
        static_servers: static_servers(adapter, ipv6).is_some(),
    })
}

/// The entries to take over from an enumeration. Includes every connected
/// physical adapter with DNS servers — the resolver asks all of them, so
/// pointing only the current outbound at the tunnel would still let a blocked
/// server on another adapter stall a negative answer. Skips loopback, the
/// tunnel adapter itself (by friendly name when known, otherwise by index),
/// virtual adapters, and disconnected adapters. A family is captured only when
/// `targets` carries an address for it, the tunnel address that family's
/// queries will be pointed at. A family the tunnel does not serve is left
/// exactly as it is: an empty server list is not expressible through the
/// interface settings API, and a family left out of the record is a family the
/// restore must not rewrite.
fn plan(
    views: &[AdapterView],
    tun_if_index: u32,
    tun_name: Option<&str>,
    targets: Targets,
) -> Record {
    let mut entries = Vec::new();
    for view in views {
        // The friendly name is the stable identity the staged config names.
        // When it is present, prefer it over the captured index: a recreated
        // wintun adapter can reuse an index that now belongs to another NIC.
        let is_tun = tun_name.is_some_and(|name| view.alias.eq_ignore_ascii_case(name));
        if view.if_type == IF_TYPE_SOFTWARE_LOOPBACK || is_tun {
            continue;
        }
        if tun_name.is_none() && view.if_index == tun_if_index {
            continue;
        }
        if !view.up || !view.physical {
            continue;
        }
        let v4 = targets
            .v4
            .and_then(|target| family_state(&view.adapter, &view.dns, false, IpAddr::V4(target)));
        let v6 = targets
            .v6
            .and_then(|target| family_state(&view.adapter, &view.dns, true, IpAddr::V6(target)));
        if v4.is_none() && v6.is_none() {
            continue;
        }
        entries.push(Entry {
            adapter: view.adapter.clone(),
            alias: view.alias.clone(),
            v4,
            v6,
        });
    }
    Record { entries }
}

/// The tunnel addresses the takeover points the taken-over families at: the
/// addresses the runtime's in-tun DNS listeners bind, derived from the same
/// config. A family without one is not taken over — its adapters would only
/// be pointed at a server nothing answers on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Targets {
    pub(crate) v4: Option<Ipv4Addr>,
    pub(crate) v6: Option<Ipv6Addr>,
}

/// Enumerate every adapter with its DNS servers.
fn enumerate() -> Result<Vec<AdapterView>, DiagError> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    // SAFETY: See the identical two-call sizing in `netif::enumerate`: the
    // first call passes a null buffer and reports the required size, the
    // second passes the base of an `AlignedBuffer` allocated for exactly that
    // size and aligned to `align_of::<IP_ADAPTER_ADDRESSES_LH>()`, so the
    // chain the API writes stays inside it. Every node is reached only through
    // the null-terminated `Next` links the API wrote, and the unicast and DNS
    // server chains hang off those nodes in the same allocation.
    unsafe {
        let mut size: u32 = 0;
        let rc = GetAdaptersAddresses(0, flags, None, None, &mut size);
        if rc != windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0 || size == 0 {
            return Err(DiagError::new(Diag::new(Key::DnsTakeoverEnumerateFailed)));
        }
        let Some(buffer) = AlignedBuffer::<IP_ADAPTER_ADDRESSES_LH>::zeroed(size as usize) else {
            return Err(DiagError::new(Diag::new(Key::DnsTakeoverEnumerateFailed)));
        };
        let head = buffer.as_mut_ptr();
        let rc = GetAdaptersAddresses(0, flags, None, Some(head), &mut size);
        if rc != 0 {
            return Err(DiagError::new(Diag::new(Key::DnsTakeoverEnumerateFailed)));
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: on success the API filled the buffer with a
            // null-terminated chain of `IP_ADAPTER_ADDRESSES_LH`, each node
            // inside the aligned allocation `buffer` owns, so `cur` always
            // points at a valid, properly aligned struct.
            let adapter = &*cur;
            let mut dns = Vec::new();
            let mut server = adapter.FirstDnsServerAddress;
            while !server.is_null() {
                // SAFETY: `FirstDnsServerAddress` heads a null-terminated
                // chain of DNS server structs in the same live allocation.
                let node = &*server;
                if let Some(ip) = sockaddr_ip(node.Address.lpSockaddr) {
                    dns.push(ip);
                }
                server = node.Next;
            }
            let if_index = adapter.Anonymous1.Anonymous.IfIndex;
            // `GetIfEntry2` reports the hardware bit the DNS takeover uses to
            // keep virtual adapters out of the plan.
            let mut if_row = MIB_IF_ROW2 {
                InterfaceLuid: adapter.Luid,
                ..Default::default()
            };
            // SAFETY: `if_row` is a fully initialized local; the API writes
            // its fields on success and leaves the rest untouched.
            // A failed row read cannot classify the adapter; treating it as
            // physical keeps an already-captured adapter from being restored
            // and dropped on a transient API failure.
            let physical = GetIfEntry2(&mut if_row) != ERROR_SUCCESS
                || if_row.InterfaceAndOperStatusFlags._bitfield & HARDWARE_INTERFACE_BIT != 0;
            out.push(AdapterView {
                adapter: if adapter.AdapterName.is_null() {
                    String::new()
                } else {
                    adapter.AdapterName.to_string().unwrap_or_default()
                },
                alias: if adapter.FriendlyName.is_null() {
                    String::new()
                } else {
                    adapter.FriendlyName.display().to_string()
                },
                if_index: if if_index != 0 {
                    if_index
                } else {
                    adapter.Ipv6IfIndex
                },
                if_type: adapter.IfType,
                up: adapter.OperStatus == IfOperStatusUp,
                physical,
                luid: adapter.Luid,
                dns,
            });
            cur = adapter.Next;
        }
        Ok(out)
    }
}

/// The GUID `SetInterfaceDnsSettings` takes for one enumerated adapter.
fn interface_guid(luid: &windows::Win32::NetworkManagement::Ndis::NET_LUID_LH) -> Option<GUID> {
    let mut guid = GUID::zeroed();
    // SAFETY: `luid` points at a live `NET_LUID_LH` value copied out of the
    // adapter enumeration, and `guid` is a live local the API writes exactly
    // one GUID into.
    let rc = unsafe {
        windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid(luid, &mut guid)
    };
    (rc == ERROR_SUCCESS).then_some(guid)
}

/// The `iphlpapi!SetInterfaceDnsSettings` export's signature.
type SetInterfaceDnsSettingsFn =
    unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;

/// Resolve `SetInterfaceDnsSettings` from `iphlpapi.dll`, once per process.
///
/// Windows 10 2004 (build 19041) introduced the export, while the app's
/// manifest claims Windows 10/11 without a build floor. A static import would
/// make the loader fail before `main` on an older build — even when TUN and
/// the DNS takeover are never used — so the export is resolved here instead:
/// its absence leaves the takeover unavailable rather than the process
/// unloadable.
fn set_interface_dns_settings() -> Option<SetInterfaceDnsSettingsFn> {
    static RESOLVED: LazyLock<Option<SetInterfaceDnsSettingsFn>> =
        LazyLock::new(|| resolve_set_interface_dns_settings(load_iphlpapi_export));
    *RESOLVED
}

/// Map a `GetProcAddress` result onto the export's signature. `load` reports
/// `None` when the export is missing; taking it as a parameter lets a test
/// drive the pre-19041 branch without the real DLL.
fn resolve_set_interface_dns_settings(
    load: impl FnOnce() -> FARPROC,
) -> Option<SetInterfaceDnsSettingsFn> {
    let address = load()?;
    // SAFETY: `address` is the non-null payload of a `Some` from
    // `GetProcAddress`, a code pointer into a module the process keeps loaded.
    // The export's documented signature is
    // `DWORD SetInterfaceDnsSettings(const GUID*, DNS_INTERFACE_SETTINGS*)`
    // and the windows crate declares it as taking the `GUID` by value, which
    // is the signature declared above; `FARPROC` is
    // `unsafe extern "system" fn() -> isize`, so both are a single code
    // pointer entered with the `system` calling convention.
    Some(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, SetInterfaceDnsSettingsFn>(
            address,
        )
    })
}

/// Load `iphlpapi.dll` and look the export up.
fn load_iphlpapi_export() -> FARPROC {
    // SAFETY: `HSTRING` is a NUL-terminated UTF-16 module name that outlives
    // the call, and `LoadLibraryW` copies it before returning. The returned
    // handle is deliberately never released (no `FreeLibrary`), so the module
    // stays resident and the code pointer resolved from it stays valid for
    // the process lifetime — the same process-lifetime ownership the tray's
    // uxtheme load documents.
    let Ok(module) = (unsafe { LoadLibraryW(&HSTRING::from("iphlpapi.dll")) }) else {
        return None;
    };
    // SAFETY: `module` is a live handle to the loaded DLL, and the export name
    // is a static NUL-terminated ANSI string. `GetProcAddress` maps a missing
    // export (the pre-19041 case) to `None`; a found one is a code pointer
    // into that still-loaded module.
    unsafe { GetProcAddress(module, PCSTR(c"SetInterfaceDnsSettings".as_ptr().cast())) }
}

/// Write one adapter's DNS servers for one family through the resolved
/// `iphlpapi` export.
fn set_servers(
    api: SetInterfaceDnsSettingsFn,
    guid: GUID,
    ipv6: bool,
    servers: Servers<'_>,
    alias: &str,
) -> Result<(), DiagError> {
    let text: Vec<u16> = match servers {
        Servers::List(list) => list
            .join(" ")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect(),
        Servers::Revert => Vec::new(),
    };
    let settings = DNS_INTERFACE_SETTINGS {
        Version: 1,
        Flags: u64::from(DNS_SETTING_NAMESERVER | if ipv6 { DNS_SETTING_IPV6 } else { 0 }),
        NameServer: if text.is_empty() {
            PWSTR::null()
        } else {
            PWSTR(text.as_ptr() as *mut u16)
        },
        ..Default::default()
    };
    // SAFETY: `api` is the resolved `iphlpapi!SetInterfaceDnsSettings`; `guid`
    // came from `ConvertInterfaceLuidToGuid` for a live adapter, and
    // `settings` is a live local whose `NameServer` points at the
    // function-local `text` buffer, which outlives the call; the API copies
    // the string before it returns.
    let rc = unsafe { api(guid, &settings) };
    if rc != ERROR_SUCCESS {
        let code = DiagError::new(Diag::new(Key::DnsTakeoverWin32Code).arg(rc.0));
        return Err(
            DiagError::new(Diag::new(Key::DnsTakeoverRegisterFailed).arg(alias)).caused_by(code),
        );
    }
    Ok(())
}

/// Compare a family's effective servers with the list the takeover wants to
/// see. The order is not significant, and an IPv6 address may be spelled in
/// several equivalent forms.
fn servers_match(current: &[IpAddr], ipv6: bool, desired: &[String]) -> bool {
    let mut current: Vec<IpAddr> = current
        .iter()
        .copied()
        .filter(|server| server.is_ipv6() == ipv6)
        .collect();
    current.sort_unstable();
    sorted_ip_addrs(desired).is_some_and(|desired| current == desired)
}

/// Parse and sort a list of textual servers. `None` means at least one entry
/// was not an IP address, which falls back to a textual comparison.
fn sorted_ip_addrs(servers: &[String]) -> Option<Vec<IpAddr>> {
    let mut parsed: Vec<IpAddr> = servers
        .iter()
        .map(|server| server.parse::<IpAddr>().ok())
        .collect::<Option<_>>()?;
    parsed.sort_unstable();
    Some(parsed)
}

/// Whether the persisted static list is the state the restore wrote: an
/// absent list for a DHCP revert, or the exact static list.
fn static_matches(actual: Option<&[String]>, desired: Servers<'_>) -> bool {
    match desired {
        Servers::Revert => actual.is_none(),
        Servers::List(list) => actual.is_some_and(|actual| same_servers(actual, list)),
    }
}

fn same_servers(left: &[String], right: &[String]) -> bool {
    match (sorted_ip_addrs(left), sorted_ip_addrs(right)) {
        (Some(left), Some(right)) => left == right,
        _ => {
            let mut left: Vec<&str> = left.iter().map(String::as_str).collect();
            let mut right: Vec<&str> = right.iter().map(String::as_str).collect();
            left.sort_unstable();
            right.sort_unstable();
            left == right
        }
    }
}

/// Read the static list back after a write. `SetInterfaceDnsSettings` can
/// return success without applying the intended change, and a restore that
/// silently missed would delete the record and strand the adapter, so a
/// mismatch is an error and keeps the record.
fn verify_static(
    adapter: &str,
    alias: &str,
    ipv6: bool,
    desired: Servers<'_>,
) -> Result<(), DiagError> {
    let mut attempts = 0;
    loop {
        let actual = static_servers(adapter, ipv6);
        if static_matches(actual.as_deref(), desired) {
            return Ok(());
        }
        attempts += 1;
        if attempts >= 3 {
            return Err(
                DiagError::new(Diag::new(Key::DnsTakeoverRegisterFailed).arg(alias))
                    .caused_by(DiagError::new(Diag::new(Key::DnsTakeoverVerifyFailed))),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The enumerated view of the adapter an entry names. The comparison is
/// case-insensitive because `GetAdaptersAddresses` and the registry disagree
/// on the letter case of the same interface GUID.
fn find_view<'a>(views: &'a [AdapterView], entry: &Entry) -> Option<&'a AdapterView> {
    views
        .iter()
        .find(|view| view.adapter.eq_ignore_ascii_case(&entry.adapter))
}

/// Apply the takeover: point every captured adapter's DNS at the tunnel
/// address of its family.
fn apply(
    record: &Record,
    targets: Targets,
    api: SetInterfaceDnsSettingsFn,
) -> Result<usize, DiagError> {
    let views = enumerate()?;
    let mut applied = 0;
    for entry in &record.entries {
        let Some(view) = find_view(&views, entry) else {
            continue; // the adapter is gone since the capture
        };
        let Some(guid) = interface_guid(&view.luid) else {
            continue;
        };
        let mut changed = false;
        if let (Some(state), Some(target)) = (&entry.v4, targets.v4) {
            let servers = state.takeover_servers(IpAddr::V4(target));
            let already = static_matches(
                static_servers(&entry.adapter, false).as_deref(),
                Servers::List(&servers),
            ) || servers_match(&view.dns, false, &servers);
            if !already {
                set_servers(api, guid, false, Servers::List(&servers), &entry.alias)?;
                verify_static(&entry.adapter, &entry.alias, false, Servers::List(&servers))?;
                changed = true;
            }
        }
        if let (Some(state), Some(target)) = (&entry.v6, targets.v6) {
            let servers = state.takeover_servers(IpAddr::V6(target));
            let already = static_matches(
                static_servers(&entry.adapter, true).as_deref(),
                Servers::List(&servers),
            ) || servers_match(&view.dns, true, &servers);
            if !already {
                set_servers(api, guid, true, Servers::List(&servers), &entry.alias)?;
                verify_static(&entry.adapter, &entry.alias, true, Servers::List(&servers))?;
                changed = true;
            }
        }
        if changed {
            applied += 1;
        }
    }
    Ok(applied)
}

/// Restore one captured entry. An adapter that is absent from the current
/// enumeration cannot take `SetInterfaceDnsSettings`, so its saved
/// `NameServer` is restored through the registry instead; the record then
/// holds no residual entry and a later reconnect uses the original list. The
/// same registry path covers a process where the export is missing: the
/// takeover could not have written the tunnel address from this build, so the
/// saved configuration is still the original.
fn restore_entry(
    views: &[AdapterView],
    entry: &Entry,
    api: Option<SetInterfaceDnsSettingsFn>,
) -> Result<(), DiagError> {
    match find_view(views, entry) {
        Some(view) => {
            let Some(api) = api else {
                return restore_saved(entry);
            };
            let Some(guid) = interface_guid(&view.luid) else {
                return restore_saved(entry);
            };
            if view.up {
                // A live adapter must accept the API write; a failure keeps
                // the entry for the next pass instead of trusting a saved
                // value the adapter may not have picked up.
                restore_interface(api, guid, entry)?;
            } else if let Err(api_error) = restore_interface(api, guid, entry) {
                // A down adapter can reject the API; its saved value is what
                // a later reconnect uses.
                restore_saved(entry)
                    .map_err(|registry_error| api_error.caused_by(registry_error))?;
            }
        }
        None => restore_saved(entry)?,
    }
    Ok(())
}

/// Restore one present adapter through the interface settings API.
fn restore_interface(
    api: SetInterfaceDnsSettingsFn,
    guid: GUID,
    entry: &Entry,
) -> Result<(), DiagError> {
    if let Some(state) = &entry.v4 {
        let write = state.restore_write();
        set_servers(api, guid, false, write, &entry.alias)?;
        verify_static(&entry.adapter, &entry.alias, false, write)?;
    }
    if let Some(state) = &entry.v6 {
        let write = state.restore_write();
        set_servers(api, guid, true, write, &entry.alias)?;
        verify_static(&entry.adapter, &entry.alias, true, write)?;
    }
    Ok(())
}

/// Restore the saved configuration directly, for an adapter the enumeration
/// no longer contains. The registry key outlives a disconnected or unplugged
/// adapter, so the takeover value does not survive until the adapter returns.
fn restore_saved(entry: &Entry) -> Result<(), DiagError> {
    if let Some(state) = &entry.v4 {
        restore_saved_family(&entry.adapter, &entry.alias, false, state)?;
    }
    if let Some(state) = &entry.v6 {
        restore_saved_family(&entry.adapter, &entry.alias, true, state)?;
    }
    Ok(())
}

fn restore_saved_family(
    adapter: &str,
    alias: &str,
    ipv6: bool,
    state: &FamilyState,
) -> Result<(), DiagError> {
    let root = if ipv6 {
        TCPIP6_INTERFACES
    } else {
        TCPIP4_INTERFACES
    };
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(format!(r"{root}\{adapter}"), KEY_SET_VALUE)
    {
        Ok(key) => key,
        // The adapter was uninstalled; the key and its NameServer are gone,
        // so there is nothing left to restore.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(registry_error(alias, error)),
    };
    match state.restore_write() {
        Servers::List(servers) if !servers.is_empty() => {
            let value = servers.join(" ");
            key.set_value("NameServer", &value)
                .map_err(|error| registry_error(alias, error))?;
        }
        _ => match key.delete_value("NameServer") {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(registry_error(alias, error)),
        },
    }
    if !static_matches(
        static_servers(adapter, ipv6).as_deref(),
        state.restore_write(),
    ) {
        return Err(DiagError::new(Diag::new(Key::DnsTakeoverVerifyFailed)));
    }
    Ok(())
}

fn registry_error(alias: &str, error: std::io::Error) -> DiagError {
    let diag = Diag::new(Key::DnsTakeoverRegisterFailed).arg(alias);
    match error.raw_os_error() {
        Some(code) => DiagError::new(diag).caused_by(DiagError::new(
            Diag::new(Key::DnsTakeoverWin32Code).arg(code),
        )),
        None => DiagError::new(diag),
    }
}

/// Restore every adapter the record names. A failure on one entry keeps only
/// that entry in the residual record; the other adapters are still restored.
/// Returns the restored count, the residual entries, and the first failure so
/// the caller can report it and retry the remainder.
fn restore(
    record: &Record,
    api: Option<SetInterfaceDnsSettingsFn>,
) -> Result<(usize, Vec<Entry>, Option<DiagError>), DiagError> {
    let views = enumerate()?;
    Ok(restore_entries(&record.entries, |entry| {
        restore_entry(&views, entry, api)
    }))
}

/// Restore every entry independently: one failure keeps only that entry for
/// the next pass, while the others still go back.
fn restore_entries<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    mut restore_one: impl FnMut(&Entry) -> Result<(), DiagError>,
) -> (usize, Vec<Entry>, Option<DiagError>) {
    let mut restored = 0;
    let mut residual = Vec::new();
    let mut first_error = None;
    for entry in entries {
        match restore_one(entry) {
            Ok(()) => restored += 1,
            Err(error) => {
                residual.push(entry.clone());
                first_error.get_or_insert(error);
            }
        }
    }
    (restored, residual, first_error)
}

/// Delete the record. A file already gone is success: the restore ran, and a
/// concurrent release must not report failure for finishing second.
fn remove_record(record_path: &Path) -> Result<(), DiagError> {
    match std::fs::remove_file(record_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(record_error()),
    }
}

/// Read the record, or `None` when no session has taken the DNS over.
///
/// Only a missing file means "no session": any other read error is an error,
/// never a fresh start, because the capture it may hold is the only way back
/// to the original servers — the caller must keep the file and report instead
/// of overwriting it.
fn read_record(record_path: &Path) -> Result<Option<Record>, DiagError> {
    let bytes = match std::fs::read(record_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(record_error()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| record_error())
}

/// Persist the capture through [`crate::sys::durable::write_atomic`]: the bytes
/// are flushed to a sibling temp file and renamed over the record, so a crash
/// mid-write cannot leave a truncated record and a power loss cannot leave the
/// rename pointing at unflushed data. The record is the only way back to the
/// original servers once an adapter has been pointed at the tunnel.
fn write_record(record_path: &Path, record: &Record) -> Result<(), DiagError> {
    let bytes = serde_json::to_vec(record).map_err(|_| record_error())?;
    crate::sys::durable::write_atomic(record_path, &bytes).map_err(|_| record_error())
}

/// Merge a fresh capture with the record an earlier session left. For an
/// adapter the record already covers, a family the earlier capture took over
/// keeps its entry — that adapter's live servers are the takeover's own
/// addresses by now — and a family the earlier capture did not take over
/// (the tunnel carried no IPv6 then, or the adapter gained one since) is
/// still original and is captured now. Adapters only the record names stay in
/// it as pending repairs.
fn merge(existing: Option<Record>, fresh: Record) -> Record {
    let Some(existing) = existing else {
        return fresh;
    };
    let mut merged = Record {
        entries: Vec::with_capacity(existing.entries.len().max(fresh.entries.len())),
    };
    for fresh_entry in fresh.entries {
        let old = existing
            .entries
            .iter()
            .find(|old| old.adapter.eq_ignore_ascii_case(&fresh_entry.adapter));
        match old {
            Some(old) => merged.entries.push(Entry {
                adapter: old.adapter.clone(),
                alias: old.alias.clone(),
                v4: old.v4.clone().or(fresh_entry.v4),
                v6: old.v6.clone().or(fresh_entry.v6),
            }),
            None => merged.entries.push(fresh_entry),
        }
    }
    for old in existing.entries {
        if !merged
            .entries
            .iter()
            .any(|entry| entry.adapter.eq_ignore_ascii_case(&old.adapter))
        {
            merged.entries.push(old);
        }
    }
    merged
}

/// What one engage or reconcile pass changed: adapters pointed at the tunnel,
/// and adapters put back because they are no longer connected.
#[derive(Debug, Default)]
pub(crate) struct TakeoverCounts {
    pub(crate) applied: usize,
    pub(crate) restored: usize,
    /// The first restore that failed while moving the takeover off an entry.
    /// The remaining adapters are still applied; the caller reports the
    /// failure and the entry stays in the record for the next pass.
    pub(crate) restore_error: Option<DiagError>,
}

/// Merge the fresh capture with the record an earlier pass left. An entry the
/// fresh capture no longer covers is restored first — an adapter disconnected
/// or was removed, or an older record covered more adapters — and dropped once
/// the restore succeeds. An absent adapter is restored through its saved
/// configuration; a failed restore keeps the entry for the next pass.
fn split_record(existing: Record, fresh: &Record) -> (Vec<Entry>, Vec<Entry>) {
    let mut carried = Vec::new();
    let mut dropped = Vec::new();
    for entry in existing.entries {
        if fresh
            .entries
            .iter()
            .any(|new| new.adapter.eq_ignore_ascii_case(&entry.adapter))
        {
            carried.push(entry);
        } else {
            dropped.push(entry);
        }
    }
    (carried, dropped)
}

fn prepare_record(
    existing: Option<Record>,
    fresh: Record,
    views: &[AdapterView],
    api: SetInterfaceDnsSettingsFn,
) -> Result<(Record, usize, Option<DiagError>), DiagError> {
    let Some(existing) = existing else {
        return Ok((fresh, 0, None));
    };
    let (mut carried, dropped) = split_record(existing, &fresh);
    let (restored, residual, restore_error) =
        restore_entries(&dropped, |entry| restore_entry(views, entry, Some(api)));
    carried.extend(residual);
    Ok((
        merge(Some(Record { entries: carried }), fresh),
        restored,
        restore_error,
    ))
}

/// Take the system DNS over for this TUN session: capture every connected
/// physical adapter's servers, persist the capture as the record, then point
/// them at the tunnel.
///
/// The record is written before the first change, so a crash between the two
/// leaves a repair behind rather than an unrecoverable machine.
///
/// A build without the interface-settings export (before Windows 10 2004)
/// skips the whole pass and reports zero counts: it cannot point an adapter
/// at the tunnel, and a capture for adapters nothing changed would make every
/// later restore rewrite servers the takeover never touched.
///
/// A restart of the running core calls this again while the adapters are still
/// pointed at the tunnel, so the fresh capture is merged with the record
/// [`merge`] keeps. An entry the fresh capture no longer covers (a disconnected
/// or removed adapter) is restored and dropped.
pub(crate) fn engage(
    record_path: &Path,
    tun_if_index: u32,
    tun_name: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    engage_with(
        record_path,
        set_interface_dns_settings(),
        tun_if_index,
        tun_name,
        targets,
    )
}

/// [`engage`] with the resolved export, split out so a test can drive the
/// missing-export branch without a live system.
fn engage_with(
    record_path: &Path,
    api: Option<SetInterfaceDnsSettingsFn>,
    tun_if_index: u32,
    tun_name: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    let Some(api) = api else {
        return Ok(TakeoverCounts::default());
    };
    let views = enumerate()?;
    let fresh = plan(&views, tun_if_index, tun_name, targets);
    let (record, restored, restore_error) =
        prepare_record(read_record(record_path)?, fresh, &views, api)?;
    if record.entries.is_empty() {
        remove_record(record_path)?;
        return Ok(TakeoverCounts {
            applied: 0,
            restored,
            restore_error,
        });
    }
    write_record(record_path, &record)?;
    let applied = match apply(&record, targets, api) {
        Ok(applied) => applied,
        Err(error) => {
            return Err(match restore_error {
                Some(restore_error) => error.caused_by(restore_error),
                None => error,
            });
        }
    };
    Ok(TakeoverCounts {
        applied,
        restored,
        restore_error,
    })
}

/// Reconcile an active session with the connected physical adapters.
/// Returns the adapters pointed at the tunnel and the ones put back because
/// they are no longer connected.
///
/// The capture is merged with the existing record, so a newly connected
/// physical adapter is captured and pointed at the tunnel without changing an
/// original already recorded. An entry the fresh capture no longer covers is
/// restored and dropped; a failed restore keeps its entry for a later pass.
/// The record is rewritten only when it changed, and a server list that already
/// carries the target is not written again. A network monitor calls this both
/// on change notifications and on a periodic backstop, so it must stay
/// idempotent. Like [`engage`], a process without the interface-settings
/// export skips the pass and returns zero counts.
pub(crate) fn reconcile(
    record_path: &Path,
    tun_if_index: u32,
    tun_name: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    reconcile_with(
        record_path,
        set_interface_dns_settings(),
        tun_if_index,
        tun_name,
        targets,
    )
}

/// [`reconcile`] with the resolved export, split out so a test can drive the
/// missing-export branch without a live system.
fn reconcile_with(
    record_path: &Path,
    api: Option<SetInterfaceDnsSettingsFn>,
    tun_if_index: u32,
    tun_name: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    let Some(api) = api else {
        return Ok(TakeoverCounts::default());
    };
    let views = enumerate()?;
    let fresh = plan(&views, tun_if_index, tun_name, targets);
    let existing = read_record(record_path)?;
    let (record, restored, restore_error) = prepare_record(existing.clone(), fresh, &views, api)?;
    if record.entries.is_empty() {
        remove_record(record_path)?;
        return Ok(TakeoverCounts {
            applied: 0,
            restored,
            restore_error,
        });
    }
    if existing.as_ref() != Some(&record) {
        write_record(record_path, &record)?;
    }
    let applied = match apply(&record, targets, api) {
        Ok(applied) => applied,
        Err(error) => {
            return Err(match restore_error {
                Some(restore_error) => error.caused_by(restore_error),
                None => error,
            });
        }
    };
    Ok(TakeoverCounts {
        applied,
        restored,
        restore_error,
    })
}

/// Restore the DNS servers a session took over and drop the record. Returns
/// the number of adapters restored, or `None` when no record exists.
///
/// A failed restore keeps the record, so the next call (the next teardown
/// path, or the next helper start) tries again. An absent adapter is restored
/// through its saved registry configuration, so a disconnected NIC does not
/// keep the tunnel address until it returns; only a registry write failure
/// keeps its entry.
pub(crate) fn release(record_path: &Path) -> Result<Option<usize>, DiagError> {
    let Some(record) = read_record(record_path)? else {
        return Ok(None);
    };
    let (restored, residual, first_error) = restore(&record, set_interface_dns_settings())?;
    if residual.is_empty() {
        remove_record(record_path)?;
    } else {
        write_record(record_path, &Record { entries: residual })?;
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(Some(restored))
}

fn record_error() -> DiagError {
    DiagError::new(Diag::new(Key::DnsTakeoverRecordFailed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(servers: &[&str], static_servers: bool) -> FamilyState {
        FamilyState {
            servers: servers.iter().map(|s| s.to_string()).collect(),
            static_servers,
        }
    }

    fn view(adapter: &str, if_index: u32, if_type: u32, dns: &[&str]) -> AdapterView {
        AdapterView {
            adapter: adapter.to_string(),
            alias: format!("alias-{adapter}"),
            if_index,
            if_type,
            up: true,
            physical: true,
            luid: Default::default(),
            dns: dns.iter().map(|s| s.parse().expect("ip")).collect(),
        }
    }

    /// Both tunnel addresses, the shape a dual-stack TUN setting produces.
    fn both_families() -> Targets {
        Targets {
            v4: Some(Ipv4Addr::new(10, 255, 0, 1)),
            v6: Some("fd00::1".parse().expect("ip")),
        }
    }

    #[test]
    fn a_missing_export_resolves_to_unavailable_instead_of_panicking() {
        // Pre-19041 iphlpapi has no `SetInterfaceDnsSettings`. The resolver
        // must report the takeover unavailable; a static import would have
        // failed the process in the loader before `main` instead.
        assert!(
            resolve_set_interface_dns_settings(|| None).is_none(),
            "a missing export means the takeover is unavailable"
        );
        unsafe extern "system" fn found() -> isize {
            0
        }
        assert!(
            resolve_set_interface_dns_settings(|| Some(found)).is_some(),
            "a found export maps onto the declared signature"
        );
    }

    #[test]
    fn a_pass_without_the_export_skips_the_takeover_without_a_capture() {
        // Nothing can be pointed at the tunnel without the export, so the
        // pass must report zero work and leave no record behind: a capture of
        // adapters the takeover never touched would make every later restore
        // rewrite servers it never changed.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dns-takeover.json");
        let engaged = engage_with(&path, None, 9, None, both_families())
            .expect("unavailability is not an error");
        assert_eq!(engaged.applied, 0);
        assert_eq!(engaged.restored, 0);
        assert!(engaged.restore_error.is_none());
        assert!(
            !path.exists(),
            "an unavailable takeover must not leave a record"
        );

        let reconciled = reconcile_with(&path, None, 9, None, both_families())
            .expect("unavailability is not an error");
        assert_eq!(reconciled.applied, 0);
        assert!(!path.exists(), "a reconcile pass must not create a record");
    }

    #[test]
    fn a_dynamic_family_reverts_and_a_static_family_round_trips() {
        // The restore writes back only what a static adapter carried; a
        // dynamic list must revert to its source, because writing the
        // captured DHCP servers back would pin them as static.
        assert_eq!(state(&["1.1.1.1"], false).restore_write(), Servers::Revert);
        let pinned = state(&["1.1.1.1", "8.8.8.8"], true);
        assert_eq!(pinned.restore_write(), Servers::List(&pinned.servers));
    }

    #[test]
    fn the_takeover_writes_the_tunnel_address_for_each_carried_family() {
        let v4 = state(&["192.0.2.1"], false);
        assert_eq!(
            v4.takeover_servers(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))),
            vec!["10.255.0.1".to_string()]
        );
        let v6 = state(&["2001:db8::53", "2001:db8::54"], true);
        assert_eq!(
            v6.takeover_servers(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            vec!["::1".to_string()]
        );
    }

    #[test]
    fn a_tunnel_without_ipv6_leaves_the_ipv6_family_alone() {
        // The interface settings API cannot express an empty server list (an
        // empty string is a no-op), so a family the tunnel cannot serve must
        // stay out of the takeover *and* out of the record: the restore would
        // otherwise rewrite a family the session never touched.
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["192.0.2.1", "2001:db8::53"]),
        ];
        let record = plan(
            &views,
            9,
            None,
            Targets {
                v4: Some(Ipv4Addr::new(10, 255, 0, 1)),
                v6: None,
            },
        );
        assert_eq!(record.entries.len(), 1);
        assert!(record.entries[0].v4.is_some(), "IPv4 is always carried");
        assert_eq!(
            record.entries[0].v6, None,
            "an IPv6 family the tunnel cannot serve stays untouched"
        );
    }

    #[test]
    fn the_plan_skips_loopback_and_the_tunnel_and_keeps_only_adapters_with_servers() {
        let views = vec![
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view(
                "{loop}",
                1,
                IF_TYPE_SOFTWARE_LOOPBACK,
                &["fec0:0:0:ffff::1"],
            ),
            view("{wired}", 4, 6, &["192.0.2.1"]),
            view("{quiet}", 5, 6, &[]),
        ];
        let record = plan(&views, 9, None, both_families());
        assert_eq!(
            record.entries.len(),
            1,
            "only the wired adapter is taken over"
        );
        assert_eq!(record.entries[0].adapter, "{wired}");
        assert_eq!(
            record.entries[0].v4.as_ref().map(|s| s.servers.clone()),
            Some(vec!["192.0.2.1".to_string()])
        );
        assert_eq!(
            record.entries[0].v6, None,
            "no IPv6 servers, so the family is untouched"
        );
    }

    #[test]
    fn the_plan_takes_over_every_connected_physical_adapter() {
        // The resolver asks every adapter's servers, so the takeover covers
        // all connected physical NICs, not just the current outbound.
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["192.0.2.1"]),
            view("{wifi}", 5, 71, &["198.51.100.1"]),
        ];
        let record = plan(&views, 9, None, both_families());
        assert_eq!(record.entries.len(), 2);
        assert_eq!(record.entries[0].adapter, "{wired}");
        assert_eq!(record.entries[1].adapter, "{wifi}");
    }

    #[test]
    fn the_plan_skips_disconnected_and_virtual_adapters() {
        let mut virtual_view = view("{virtual}", 5, 6, &["198.51.100.1"]);
        virtual_view.physical = false;
        let mut down = view("{down}", 6, 6, &["198.51.100.2"]);
        down.up = false;
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            virtual_view,
            down,
            view("{wired}", 4, 6, &["192.0.2.1"]),
        ];
        let record = plan(&views, 9, None, both_families());
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].adapter, "{wired}");
    }

    #[test]
    fn the_plan_captures_the_ipv6_family_the_tunnel_serves() {
        // An adapter carries IPv6 servers and the tunnel has an IPv6 gateway,
        // so the takeover owns that family too — it is the family the resolver
        // would otherwise send to a server the leak block drops.
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["192.0.2.1", "2001:db8::1"]),
        ];
        let record = plan(&views, 9, None, both_families());
        assert_eq!(
            record.entries[0]
                .v6
                .as_ref()
                .map(|state| state.servers.clone()),
            Some(vec!["2001:db8::1".to_string()])
        );
    }

    #[test]
    fn the_plan_does_not_record_the_tunnel_address_as_an_original() {
        // A fresh capture that already lists the takeover address cannot know
        // the original servers: another session, or a lost record, may have
        // written it. Recording it would restore the dead tunnel address
        // forever, so the family is captured as dynamic and reverts to DHCP.
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["10.255.0.1", "fd00::1"]),
        ];
        let record = plan(&views, 9, None, both_families());
        let entry = &record.entries[0];
        let v4 = entry.v4.as_ref().expect("the v4 family is captured");
        assert_eq!(v4.servers, Vec::<String>::new());
        assert!(!v4.static_servers, "a target-only capture must revert");
        let v6 = entry.v6.as_ref().expect("the v6 family is captured");
        assert_eq!(v6.servers, Vec::<String>::new());
        assert!(!v6.static_servers, "a target-only capture must revert");
    }

    #[test]
    fn the_plan_skips_the_tun_adapter_by_name_when_its_index_changed() {
        // Wintun can recreate the adapter with a new index; matching only the
        // captured index would capture the new TUN adapter as a normal one.
        let views = [
            view("{tun}", 42, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["192.0.2.1"]),
        ];
        let record = plan(&views, 9, Some("alias-{tun}"), both_families());
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].adapter, "{wired}");
    }

    #[test]
    fn a_record_entry_the_plan_no_longer_covers_is_dropped() {
        let entry = |adapter: &str| Entry {
            adapter: adapter.to_string(),
            alias: adapter.trim_matches(['{', '}']).to_string(),
            v4: None,
            v6: None,
        };
        let existing = Record {
            entries: vec![entry("{wired}"), entry("{wifi}")],
        };
        let fresh = Record {
            entries: vec![entry("{wifi}")],
        };
        let (carried, dropped) = split_record(existing, &fresh);
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].adapter, "{wifi}");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].adapter, "{wired}");
    }

    #[test]
    fn a_failed_restore_keeps_only_that_entry() {
        let ok = Entry {
            adapter: "{ok}".to_string(),
            alias: "ok".to_string(),
            v4: None,
            v6: None,
        };
        let bad = Entry {
            adapter: "{bad}".to_string(),
            alias: "bad".to_string(),
            v4: None,
            v6: None,
        };
        let entries = [ok, bad];
        let (restored, residual, error) = restore_entries(&entries, |entry| {
            if entry.adapter == "{bad}" {
                Err(DiagError::new(Diag::new(Key::DnsTakeoverVerifyFailed)))
            } else {
                Ok(())
            }
        });
        assert_eq!(restored, 1);
        assert_eq!(residual.len(), 1);
        assert_eq!(residual[0].adapter, "{bad}");
        assert!(error.is_some());
        assert_eq!(entries[0].adapter, "{ok}");
    }

    #[test]
    fn server_comparison_ignores_order_and_ipv6_spelling() {
        let current: Vec<IpAddr> = ["1.1.1.1", "8.8.8.8"]
            .iter()
            .map(|server| server.parse().expect("ip"))
            .collect();
        assert!(servers_match(
            &current,
            false,
            &["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        ));
        assert!(!servers_match(&current, false, &["1.1.1.1".to_string()]));
        let v6: Vec<IpAddr> = ["FD00:0:0:0:0:0:0:1"]
            .iter()
            .map(|server| server.parse().expect("ip"))
            .collect();
        assert!(servers_match(&v6, true, &["fd00::1".to_string()]));
    }

    #[test]
    fn verification_requires_the_written_list_or_no_list_for_a_revert() {
        assert!(static_matches(None, Servers::Revert));
        assert!(!static_matches(
            Some(&["198.51.100.1".to_string()]),
            Servers::Revert
        ));
        assert!(static_matches(
            Some(&["1.1.1.1".to_string()]),
            Servers::List(&["1.1.1.1".to_string()])
        ));
        assert!(!static_matches(
            Some(&["1.1.1.1".to_string()]),
            Servers::List(&["8.8.8.8".to_string()])
        ));
    }

    #[test]
    fn the_record_round_trips_through_its_wire_form() {
        let record = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.0.2.1"], true)),
                v6: None,
            }],
        };
        let bytes = serde_json::to_vec(&record).expect("serialize");
        let back: Record = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, record);
    }

    #[test]
    fn a_restart_keeps_the_original_capture_and_adds_new_adapters() {
        // Second session start: the adapters already carry the takeover's
        // own address as a static list. The fresh capture must not become
        // their "original" state, and an adapter that appeared since the
        // first capture must still be taken over.
        let old = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.0.2.1"], false)),
                v6: None,
            }],
        };
        let fresh = Record {
            entries: vec![
                Entry {
                    adapter: "{wireD}".to_string(),
                    alias: "wired".to_string(),
                    v4: Some(state(&["10.255.0.1"], true)),
                    v6: None,
                },
                Entry {
                    adapter: "{wifi}".to_string(),
                    alias: "wifi".to_string(),
                    v4: Some(state(&["198.51.100.2"], false)),
                    v6: None,
                },
            ],
        };
        let merged = merge(Some(old), fresh);
        let wired = merged
            .entries
            .iter()
            .find(|entry| entry.adapter == "{wired}")
            .expect("the original entry survives");
        assert_eq!(
            wired.v4.as_ref().map(|state| state.servers.clone()),
            Some(vec!["192.0.2.1".to_string()]),
            "the original servers must survive a restart, not the takeover's address"
        );
        assert_eq!(merged.entries.len(), 2, "the new adapter is captured too");
        assert!(merged.entries.iter().any(|entry| entry.adapter == "{wifi}"));
    }

    #[test]
    fn the_record_file_round_trips_and_a_missing_record_reports_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dns-takeover.json");
        assert_eq!(release(&path).expect("no record"), None);
        let record = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.0.2.1"], false)),
                v6: None,
            }],
        };
        write_record(&path, &record).expect("write");
        assert_eq!(read_record(&path).expect("read"), Some(record));
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file must not survive the rename"
        );
    }

    #[test]
    fn the_record_is_written_completely_over_a_stale_one() {
        // The record is the only copy of the original servers, so the whole
        // capture must be on disk under the final name (the write syncs the
        // temp file before the rename). `write_record` is the sole writer
        // `engage`, `reconcile`, and `release` use; driving a real `engage`
        // here would rewrite this machine's DNS, so the file it leaves is
        // inspected at that one level. The oversized stale file proves the
        // write replaces a shorter record instead of leaving a tail behind.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dns-takeover.json");
        std::fs::write(&path, vec![b'x'; 4096]).expect("stale record");
        let record = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.0.2.1"], true)),
                v6: None,
            }],
        };

        write_record(&path, &record).expect("write");

        assert_eq!(
            std::fs::read(&path).expect("read back"),
            serde_json::to_vec(&record).expect("serialize"),
            "the record must reach disk as the complete capture"
        );
        assert_eq!(read_record(&path).expect("read"), Some(record));
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file must not survive the rename"
        );
    }

    #[test]
    fn a_restart_fills_a_family_the_earlier_capture_lacks() {
        // The earlier session ran without IPv6 on the tunnel, so it captured
        // no IPv6 family. The adapter's IPv6 servers are still the originals,
        // and the new session must take them over instead of inheriting the
        // family-free entry and leaving that family's stall in place.
        let old = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.0.2.1"], false)),
                v6: None,
            }],
        };
        let fresh = Record {
            entries: vec![Entry {
                adapter: "{WIRED}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["10.255.0.1"], true)),
                v6: Some(state(&["2001:db8::53"], false)),
            }],
        };
        let merged = merge(Some(old), fresh);
        let entry = &merged.entries[0];
        assert_eq!(
            entry.v4.as_ref().map(|state| state.servers.clone()),
            Some(vec!["192.0.2.1".to_string()]),
            "the taken-over family keeps the original servers"
        );
        assert_eq!(
            entry.v6.as_ref().map(|state| state.servers.clone()),
            Some(vec!["2001:db8::53".to_string()]),
            "the family the earlier capture lacks is captured now"
        );
    }

    #[test]
    fn a_record_that_cannot_be_read_is_reported_and_kept() {
        // Only a missing file means "no session". A record this call cannot
        // read still holds the capture, so it must be reported and left in
        // place instead of being replaced by a fresh capture.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dns-takeover.json");
        std::fs::create_dir(&path).expect("directory at the record path");
        assert!(read_record(&path).is_err());
        assert!(release(&path).is_err());
        assert!(
            path.exists(),
            "the unreadable record must stay for the repair"
        );
    }

    #[test]
    fn a_record_that_cannot_be_parsed_is_kept_and_reported() {
        // The capture is the only way back to the original servers, so an
        // unreadable record must fail loudly instead of being overwritten or
        // silently dropped.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dns-takeover.json");
        std::fs::write(&path, b"{not json").expect("write junk");
        assert!(read_record(&path).is_err());
        assert!(release(&path).is_err());
        assert!(
            path.exists(),
            "the unreadable record must stay for the repair"
        );
    }

    #[test]
    fn adapter_identity_matches_case_insensitively() {
        // The API spells the GUID in one case and the registry in another;
        // the restore finds an adapter by this lookup, so it must not depend
        // on the spelling.
        let views = [view(
            "{C21DC854-03F2-AEA0-84D2-9C7AC601C070}",
            4,
            6,
            &["1.1.1.1"],
        )];
        let entry = Entry {
            adapter: "{c21dc854-03f2-aea0-84d2-9c7ac601c070}".to_string(),
            alias: "tun".to_string(),
            v4: Some(state(&["1.1.1.1"], false)),
            v6: None,
        };
        assert_eq!(
            find_view(&views, &entry).map(|view| view.if_index),
            Some(4),
            "a case-different adapter must still resolve"
        );
        let gone = Entry {
            adapter: "{00000000-0000-0000-0000-000000000000}".to_string(),
            ..entry
        };
        assert!(find_view(&views, &gone).is_none());
    }
}

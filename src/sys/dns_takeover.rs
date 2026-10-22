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
//! own server list decides where they go. This module captures the adapter
//! the TUN outbound uses — a configured fixed name, or Xray's
//! `findOutboundInterface` choice over the default-route table (a wireless
//! winner overrides a better wired metric) — and points that adapter's DNS
//! list at the in-tun address for the session, for each address family the
//! tunnel carries. The core re-evaluates that choice on route and interface
//! changes for its new dials; existing sockets stay on the adapter they
//! already use, so the takeover follows the new-dial choice. A local-only adapter
//! with no default route is left exactly as it was: it is not the outbound,
//! and changing it was both unnecessary and intrusive. The captured list is
//! restored when the session ends, or when the outbound moves to a different
//! adapter.
//!
//! Restoring is the safety-critical half, so the capture is written to a
//! record file *before* any change. `release` restores from that record and
//! deletes it, and the helper calls `release` at every teardown path, on its
//! own exit path, and once at startup, so a helper that dies hard leaves a
//! record that the next helper repairs instead of a machine with a dead DNS
//! server. An adapter that is absent at restore time keeps its entry in the
//! record: the takeover's value stays in that adapter's saved configuration
//! until something writes it back, so only that entry can undo it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
    SetInterfaceDnsSettings,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::core::{GUID, PWSTR};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};

use super::netif::{AdapterBuffer, sockaddr_ip};
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

/// The adapter the TUN outbound uses, resolved from the staged
/// `autoOutboundsInterface` setting with Xray's `findOutboundInterface`
/// heuristic: `auto` (or an absent value) picks a default-route candidate,
/// with a wireless winner overriding a better wired metric, and a fixed name
/// must exist. `None` means the network state could not be read — the caller
/// must keep the record and retry — while `Some(None)` means no adapter
/// qualifies, so nothing is taken over. Local-only adapters (no default route)
/// never qualify under `auto`, which keeps their DNS settings untouched.
fn outbound_interface(
    tun_name: Option<&str>,
    tun_if_index: u32,
    setting: Option<&str>,
) -> Option<Option<String>> {
    let ifaces = crate::sys::netif::list_all_result();
    crate::sys::netif::resolved_outbound_interface(
        setting,
        tun_name,
        tun_if_index,
        ifaces.as_deref(),
    )
}

/// The entries to take over from an enumeration. Skips the loopback adapters
/// and the tunnel adapter itself — by friendly name when the caller knows it,
/// otherwise by the captured index — and keeps only the adapter the TUN
/// outbound uses, so a local-only NIC with its own DNS servers is not changed.
/// A family is captured only when `targets` carries an address for it, the
/// tunnel address that family's queries will be pointed at. A family the
/// tunnel does not serve is left exactly as it is: an empty server list is not
/// expressible through the interface settings API, and a family left out of
/// the record is a family the restore must not rewrite.
fn plan(
    views: &[AdapterView],
    tun_if_index: u32,
    tun_name: Option<&str>,
    outbound: Option<&str>,
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
        if !outbound.is_some_and(|name| view.alias.eq_ignore_ascii_case(name)) {
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
    // second passes the base of an allocation made for exactly that size and
    // aligned to `align_of::<IP_ADAPTER_ADDRESSES_LH>()`, so the chain the
    // API writes stays inside it. Every node is reached only through the
    // null-terminated `Next` links the API wrote, and the unicast and DNS
    // server chains hang off those nodes in the same allocation.
    unsafe {
        let mut size: u32 = 0;
        let rc = GetAdaptersAddresses(0, flags, None, None, &mut size);
        if rc != windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0 || size == 0 {
            return Err(DiagError::new(Diag::new(Key::DnsTakeoverEnumerateFailed)));
        }
        let Some(buffer) = AdapterBuffer::allocate(size as usize) else {
            return Err(DiagError::new(Diag::new(Key::DnsTakeoverEnumerateFailed)));
        };
        let head = buffer.head();
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

/// Write one adapter's DNS servers for one family.
fn set_servers(guid: GUID, ipv6: bool, servers: Servers<'_>, alias: &str) -> Result<(), DiagError> {
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
    // SAFETY: `guid` came from `ConvertInterfaceLuidToGuid` for a live
    // adapter, and `settings` is a live local whose `NameServer` points at
    // the function-local `text` buffer, which outlives the call; the API
    // copies the string before it returns.
    let rc = unsafe { SetInterfaceDnsSettings(guid, &settings) };
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
fn apply(record: &Record, targets: Targets) -> Result<usize, DiagError> {
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
                set_servers(guid, false, Servers::List(&servers), &entry.alias)?;
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
                set_servers(guid, true, Servers::List(&servers), &entry.alias)?;
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
/// holds no residual entry and a later reconnect uses the original list.
fn restore_entry(views: &[AdapterView], entry: &Entry) -> Result<(), DiagError> {
    match find_view(views, entry) {
        Some(view) => {
            let Some(guid) = interface_guid(&view.luid) else {
                return restore_saved(entry);
            };
            if view.up {
                // A live adapter must accept the API write; a failure keeps
                // the entry for the next pass instead of trusting a saved
                // value the adapter may not have picked up.
                restore_interface(guid, entry)?;
            } else if let Err(api_error) = restore_interface(guid, entry) {
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
fn restore_interface(guid: GUID, entry: &Entry) -> Result<(), DiagError> {
    if let Some(state) = &entry.v4 {
        let write = state.restore_write();
        set_servers(guid, false, write, &entry.alias)?;
        verify_static(&entry.adapter, &entry.alias, false, write)?;
    }
    if let Some(state) = &entry.v6 {
        let write = state.restore_write();
        set_servers(guid, true, write, &entry.alias)?;
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
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(format!(r"{root}\{adapter}"), KEY_SET_VALUE)
        .map_err(|error| registry_error(alias, error))?;
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

/// Restore the captured state of every adapter the record names. Returns the
/// number of adapters restored. A failure leaves the whole record in place for
/// the next path to retry; an absent adapter is restored through its saved
/// registry configuration, so it does not become a residual entry.
fn restore(record: &Record) -> Result<usize, DiagError> {
    let views = enumerate()?;
    let mut restored = 0;
    for entry in &record.entries {
        restore_entry(&views, entry)?;
        restored += 1;
    }
    Ok(restored)
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

/// Persist the capture. The write goes through a sibling temporary file and
/// a rename, so a crash mid-write cannot leave a truncated record.
fn write_record(record_path: &Path, record: &Record) -> Result<(), DiagError> {
    let bytes = serde_json::to_vec(record).map_err(|_| record_error())?;
    let temporary = record_path.with_extension("json.tmp");
    std::fs::write(&temporary, bytes).map_err(|_| record_error())?;
    std::fs::rename(&temporary, record_path).map_err(|_| record_error())
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
/// and adapters put back because the outbound moved away from them.
#[derive(Debug, Default)]
pub(crate) struct TakeoverCounts {
    pub(crate) applied: usize,
    pub(crate) restored: usize,
    /// The first old-outbound restore that failed while moving the takeover.
    /// The new outbound is still applied; the caller reports the failure and
    /// the entry stays in the record for the next pass.
    pub(crate) restore_error: Option<DiagError>,
}

/// Merge the fresh capture with the record an earlier pass left. An entry the
/// fresh capture no longer selects is restored first — the outbound moved, or
/// an older record covered more adapters — and dropped once the restore
/// succeeds. An absent adapter is restored through its saved configuration; a
/// failed restore keeps the entry for the next pass.
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
) -> Result<(Record, usize, Option<DiagError>), DiagError> {
    let Some(existing) = existing else {
        return Ok((fresh, 0, None));
    };
    let (mut carried, dropped) = split_record(existing, &fresh);
    let mut restored = 0;
    let mut restore_error = None;
    for entry in dropped {
        match restore_entry(views, &entry) {
            Ok(()) => restored += 1,
            Err(error) => {
                carried.push(entry);
                restore_error.get_or_insert(error);
            }
        }
    }
    Ok((
        merge(Some(Record { entries: carried }), fresh),
        restored,
        restore_error,
    ))
}

/// Take the system DNS over for this TUN session: capture the outbound
/// adapter's servers, persist the capture as the record, then point it at the
/// tunnel. `outbound_setting` is the staged config's
/// `autoOutboundsInterface` value; `None` means the config omitted it and the
/// route-table `auto` choice applies.
///
/// The record is written before the first change, so a crash between the two
/// leaves a repair behind rather than an unrecoverable machine.
///
/// A restart of the running core calls this again while the adapter is still
/// pointed at the tunnel, so the fresh capture is merged with the record
/// [`merge`] keeps. An entry the fresh capture no longer selects is restored
/// and dropped, which is what follows an outbound change.
pub(crate) fn engage(
    record_path: &Path,
    tun_if_index: u32,
    tun_name: Option<&str>,
    outbound_setting: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    let views = enumerate()?;
    let Some(outbound) = outbound_interface(tun_name, tun_if_index, outbound_setting) else {
        return Ok(TakeoverCounts::default());
    };
    let fresh = plan(&views, tun_if_index, tun_name, outbound.as_deref(), targets);
    let (record, restored, restore_error) =
        prepare_record(read_record(record_path)?, fresh, &views)?;
    if record.entries.is_empty() {
        remove_record(record_path)?;
        return Ok(TakeoverCounts {
            applied: 0,
            restored,
            restore_error,
        });
    }
    write_record(record_path, &record)?;
    let applied = match apply(&record, targets) {
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

/// Reconcile an active session with the adapter the outbound uses now.
/// Returns the adapters pointed at the tunnel and the ones put back because
/// they are no longer the outbound.
///
/// The capture is merged with the existing record, so the adapter selected
/// now is captured and pointed at the tunnel without changing an original
/// already recorded. An entry the fresh capture no longer selects is restored
/// and dropped; a failed restore keeps its entry for a later pass. The record
/// is rewritten only when it changed, and a server list that already carries
/// the target is not written again. A network monitor calls this both on
/// change notifications and on a periodic backstop, so it must stay
/// idempotent.
pub(crate) fn reconcile(
    record_path: &Path,
    tun_if_index: u32,
    tun_name: Option<&str>,
    outbound_setting: Option<&str>,
    targets: Targets,
) -> Result<TakeoverCounts, DiagError> {
    let views = enumerate()?;
    let Some(outbound) = outbound_interface(tun_name, tun_if_index, outbound_setting) else {
        return Ok(TakeoverCounts::default());
    };
    let fresh = plan(&views, tun_if_index, tun_name, outbound.as_deref(), targets);
    let existing = read_record(record_path)?;
    let (record, restored, restore_error) = prepare_record(existing.clone(), fresh, &views)?;
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
    let applied = match apply(&record, targets) {
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
    let restored = restore(&record)?;
    remove_record(record_path)?;
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
            Some("alias-{wired}"),
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
        let record = plan(&views, 9, None, Some("alias-{wired}"), both_families());
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
    fn the_plan_takes_over_only_the_actual_outbound_adapter() {
        // A local-only NIC can carry DNS servers without a default route.
        // Changing it is unnecessary and intrusive: only the adapter the TUN
        // outbound uses is captured.
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{wired}", 4, 6, &["192.0.2.1"]),
            view("{local}", 5, 6, &["198.51.100.1"]),
        ];
        let record = plan(&views, 9, None, Some("alias-{wired}"), both_families());
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].adapter, "{wired}");
    }

    #[test]
    fn no_outbound_captures_nothing() {
        let views = [
            view("{tun}", 9, 53, &["10.255.0.1"]),
            view("{local}", 5, 6, &["198.51.100.1"]),
        ];
        let record = plan(&views, 9, None, None, both_families());
        assert!(record.entries.is_empty());
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
        let record = plan(&views, 9, None, Some("alias-{wired}"), both_families());
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
        let record = plan(&views, 9, None, Some("alias-{wired}"), both_families());
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
        let record = plan(
            &views,
            9,
            Some("alias-{tun}"),
            Some("alias-{wired}"),
            both_families(),
        );
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].adapter, "{wired}");
    }

    #[test]
    fn a_record_entry_the_outbound_no_longer_selects_is_dropped() {
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

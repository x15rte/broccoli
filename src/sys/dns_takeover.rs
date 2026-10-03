//! System DNS takeover while a TUN core with a DNS module runs.
//!
//! The WFP DNS shield (`rt::wfp`) blocks port-53 egress outside the TUN. The
//! resolver still holds the *other* adapters' DNS servers in its server set,
//! and those queries never answer, so a name the tunnel answers with a
//! negative result costs the whole retry schedule: Windows completes a query
//! only after every configured server answered, and a NODATA from the tunnel
//! DNS is not final. Measured on a host whose `wired` adapter kept its DHCP
//! server: about ten seconds for one AAAA query, and the same for one TXT or
//! NXDOMAIN query.
//!
//! The DNS client sends each query from the interface that owns the server,
//! so a route cannot move those queries into the tunnel: only the adapter's
//! own server list decides where they go. This module therefore points every
//! other adapter's DNS list at the in-tun address for the session, for each
//! address family the tunnel carries, which makes the tunnel the only server
//! the resolver asks (milliseconds for the same AAAA query), and restores the
//! captured lists when the session ends.
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
use windows::core::{GUID, PWSTR};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use super::netif::{AdapterBuffer, sockaddr_ip};
use crate::diag::{Diag, DiagError};
use crate::i18n::Key;

/// Registry path of the IPv4 interface configuration (`NameServer` holds the
/// static server list; an absent or empty value means the servers come from
/// DHCP).
const TCPIP4_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
/// Registry path of the IPv6 interface configuration.
const TCPIP6_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

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
    luid: windows::Win32::NetworkManagement::Ndis::NET_LUID_LH,
    unicast: Vec<IpAddr>,
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
fn family_state(adapter: &str, servers: &[IpAddr], ipv6: bool) -> Option<FamilyState> {
    let matching: Vec<String> = servers
        .iter()
        .filter(|ip| ip.is_ipv6() == ipv6)
        .map(IpAddr::to_string)
        .collect();
    if matching.is_empty() {
        return None;
    }
    Some(FamilyState {
        servers: matching,
        static_servers: static_servers(adapter, ipv6).is_some(),
    })
}

/// The entries to take over from an enumeration, plus the tunnel adapter's
/// own IPv6 address when it has one. Skips the loopback adapters and the
/// tunnel adapter itself, and captures an IPv6 family only when the tunnel
/// carries one: a family the takeover cannot serve is left exactly as it is,
/// because an empty server list is not expressible through the interface
/// settings API and a family left out of the record is a family the restore
/// must not rewrite.
fn plan(views: &[AdapterView], tun_if_index: u32) -> (Record, Option<Ipv6Addr>) {
    let tun_v6 = views
        .iter()
        .find(|view| view.if_index == tun_if_index)
        .and_then(|view| {
            view.unicast.iter().find_map(|ip| match ip {
                IpAddr::V6(ip) if !ip.is_unicast_link_local() => Some(*ip),
                _ => None,
            })
        });
    let mut entries = Vec::new();
    for view in views {
        if view.if_type == IF_TYPE_SOFTWARE_LOOPBACK || view.if_index == tun_if_index {
            continue;
        }
        let v4 = family_state(&view.adapter, &view.dns, false);
        let v6 = tun_v6.and_then(|_| family_state(&view.adapter, &view.dns, true));
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
    (Record { entries }, tun_v6)
}

/// Enumerate every adapter with its unicast addresses and DNS servers.
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
            let mut unicast = Vec::new();
            let mut uni = adapter.FirstUnicastAddress;
            while !uni.is_null() {
                // SAFETY: `FirstUnicastAddress` heads a null-terminated chain
                // of unicast address structs in the same live allocation.
                let node = &*uni;
                if let Some(ip) = sockaddr_ip(node.Address.lpSockaddr) {
                    unicast.push(ip);
                }
                uni = node.Next;
            }
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
                luid: adapter.Luid,
                unicast,
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

/// The enumerated view of the adapter an entry names. The comparison is
/// case-insensitive because `GetAdaptersAddresses` and the registry disagree
/// on the letter case of the same interface GUID.
fn find_view<'a>(views: &'a [AdapterView], entry: &Entry) -> Option<&'a AdapterView> {
    views
        .iter()
        .find(|view| view.adapter.eq_ignore_ascii_case(&entry.adapter))
}

/// Apply the takeover: point every captured adapter's DNS at the in-tun
/// address, and clear the families the tunnel does not carry.
fn apply(record: &Record, tun_v6: Option<Ipv6Addr>, in_tun_v4: Ipv4Addr) -> Result<(), DiagError> {
    let views = enumerate()?;
    for entry in &record.entries {
        let Some(view) = find_view(&views, entry) else {
            continue; // the adapter is gone since the capture
        };
        let Some(guid) = interface_guid(&view.luid) else {
            continue;
        };
        if let Some(state) = &entry.v4 {
            let servers = state.takeover_servers(IpAddr::V4(in_tun_v4));
            set_servers(guid, false, Servers::List(&servers), &entry.alias)?;
        }
        if let Some(state) = &entry.v6
            && let Some(tun_v6) = tun_v6
        {
            let servers = state.takeover_servers(IpAddr::V6(tun_v6));
            set_servers(guid, true, Servers::List(&servers), &entry.alias)?;
        }
    }
    Ok(())
}

/// Restore the captured state of every adapter the record names. Returns the
/// number of adapters restored and the entries it could not restore.
///
/// An adapter that is absent from this enumeration (an unplugged dock, a
/// disabled adapter) keeps the takeover's value in its saved configuration,
/// so its entry is *not* done: it goes back to the caller, which must keep it
/// in the record. Dropping it would leave that adapter pointing at the tunnel
/// with nothing to restore from, and a later capture would record the
/// takeover's own address as its original.
fn restore(record: &Record) -> Result<(usize, Vec<Entry>), DiagError> {
    let views = enumerate()?;
    let mut restored = 0;
    let mut residual = Vec::new();
    for entry in &record.entries {
        let Some(guid) = find_view(&views, entry).and_then(|view| interface_guid(&view.luid))
        else {
            residual.push(entry.clone());
            continue;
        };
        if let Some(state) = &entry.v4 {
            set_servers(guid, false, state.restore_write(), &entry.alias)?;
        }
        if let Some(state) = &entry.v6 {
            set_servers(guid, true, state.restore_write(), &entry.alias)?;
        }
        restored += 1;
    }
    Ok((restored, residual))
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

/// Take the system DNS over for this TUN session: capture every other
/// adapter's servers, persist the capture as the record, then point those
/// adapters at the tunnel. Returns the number of adapters the session owns.
///
/// The record is written before the first change, so a crash between the two
/// leaves a repair behind rather than an unrecoverable machine.
///
/// A restart of the running core calls this again while the adapters are
/// still pointed at the tunnel, so the fresh capture is merged with the
/// record [`merge`] keeps.
pub(crate) fn engage(
    record_path: &Path,
    tun_if_index: u32,
    in_tun_v4: Ipv4Addr,
) -> Result<usize, DiagError> {
    let (fresh, tun_v6) = plan(&enumerate()?, tun_if_index);
    let record = merge(read_record(record_path)?, fresh);
    if record.entries.is_empty() {
        return Ok(0);
    }
    write_record(record_path, &record)?;
    apply(&record, tun_v6, in_tun_v4)?;
    Ok(record.entries.len())
}

/// Restore the DNS servers a session took over and drop the record. Returns
/// the number of adapters restored, or `None` when no record exists.
///
/// A failed restore keeps the record, so the next call (the next teardown
/// path, or the next helper start) tries again. An adapter that was absent
/// keeps its capture in the record for the same reason: its saved
/// configuration still points at the tunnel, and only that entry can undo it
/// once the adapter is back.
pub(crate) fn release(record_path: &Path) -> Result<Option<usize>, DiagError> {
    let Some(record) = read_record(record_path)? else {
        return Ok(None);
    };
    let (restored, residual) = restore(&record)?;
    if residual.is_empty() {
        // A record already gone is success: the restore ran, and a concurrent
        // release (the helper's own teardown paths can overlap) must not
        // report a failure for finishing second.
        match std::fs::remove_file(record_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(record_error()),
        }
    } else {
        write_record(record_path, &Record { entries: residual })?;
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

    fn view(
        adapter: &str,
        if_index: u32,
        if_type: u32,
        dns: &[&str],
        unicast: &[&str],
    ) -> AdapterView {
        AdapterView {
            adapter: adapter.to_string(),
            alias: format!("alias-{adapter}"),
            if_index,
            if_type,
            luid: Default::default(),
            unicast: unicast.iter().map(|s| s.parse().expect("ip")).collect(),
            dns: dns.iter().map(|s| s.parse().expect("ip")).collect(),
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
        let v4 = state(&["192.168.1.1"], false);
        assert_eq!(
            v4.takeover_servers(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))),
            vec!["10.255.0.1".to_string()]
        );
        let v6 = state(&["fd00::53", "fd00::54"], true);
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
            view("{tun}", 9, 53, &["10.255.0.1"], &["10.255.0.1"]),
            view(
                "{wired}",
                4,
                6,
                &["192.168.124.1", "fd00::53"],
                &["192.168.124.7"],
            ),
        ];
        let (record, tun_v6) = plan(&views, 9);
        assert_eq!(tun_v6, None);
        assert_eq!(record.entries.len(), 1);
        assert!(record.entries[0].v4.is_some(), "IPv4 is always carried");
        assert_eq!(record.entries[0].v6, None);
    }

    #[test]
    fn the_plan_skips_loopback_and_the_tunnel_and_keeps_only_adapters_with_servers() {
        let views = vec![
            view("{tun}", 9, 53, &["10.255.0.1"], &["10.255.0.1", "fd00::1"]),
            view(
                "{loop}",
                1,
                IF_TYPE_SOFTWARE_LOOPBACK,
                &["fec0:0:0:ffff::1"],
                &[],
            ),
            view("{wired}", 4, 6, &["192.168.124.1"], &["192.168.124.7"]),
            view("{quiet}", 5, 6, &[], &["192.168.9.9"]),
        ];
        let (record, tun_v6) = plan(&views, 9);
        assert_eq!(
            record.entries.len(),
            1,
            "only the wired adapter is taken over"
        );
        assert_eq!(record.entries[0].adapter, "{wired}");
        assert_eq!(
            record.entries[0].v4.as_ref().map(|s| s.servers.clone()),
            Some(vec!["192.168.124.1".to_string()])
        );
        assert_eq!(
            record.entries[0].v6, None,
            "no IPv6 servers, so the family is untouched"
        );
        assert_eq!(tun_v6, Some("fd00::1".parse().expect("ip")));
    }

    #[test]
    fn the_record_round_trips_through_its_wire_form() {
        let record = Record {
            entries: vec![Entry {
                adapter: "{wired}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["192.168.124.1"], true)),
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
                v4: Some(state(&["192.168.124.1"], false)),
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
                    v4: Some(state(&["10.88.222.245"], false)),
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
            Some(vec!["192.168.124.1".to_string()]),
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
                v4: Some(state(&["192.168.124.1"], false)),
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
                v4: Some(state(&["192.168.124.1"], false)),
                v6: None,
            }],
        };
        let fresh = Record {
            entries: vec![Entry {
                adapter: "{WIRED}".to_string(),
                alias: "wired".to_string(),
                v4: Some(state(&["10.255.0.1"], true)),
                v6: Some(state(&["fd00::53"], false)),
            }],
        };
        let merged = merge(Some(old), fresh);
        let entry = &merged.entries[0];
        assert_eq!(
            entry.v4.as_ref().map(|state| state.servers.clone()),
            Some(vec!["192.168.124.1".to_string()]),
            "the taken-over family keeps the original servers"
        );
        assert_eq!(
            entry.v6.as_ref().map(|state| state.servers.clone()),
            Some(vec!["fd00::53".to_string()]),
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
            &[],
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

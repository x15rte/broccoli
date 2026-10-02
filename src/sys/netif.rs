//! Network interface enumeration via `GetAdaptersAddresses`, plus the
//! forward table and per-interface metrics the `auto` outbound heuristic
//! reads. Used to pick a physical outbound interface for TUN traffic.
//!
//! The TUN uplink rule lives here too — [`fixed_name_verdict`],
//! [`resolve_probe_uplink`], and [`tun_adapter_name`] judge an enumeration
//! view the caller supplies. The view and the mode gate differ by caller,
//! deliberately: the commit guard and the TUN screen pass the
//! physical-only [`list`] view, while the probe passes the
//! tunnel-inclusive [`list_all`] view with the TUN's own adapter excluded
//! by index; and while the commit guard only judges a bound TUN (mode on),
//! the TUN screen surfaces a broken pinned pick regardless of mode — it
//! would become the outage the moment TUN switches on. Both splits are
//! behavior-visible: a tunnel-type adapter reads as missing to the guard
//! yet may resolve a probe. The `auto` branch itself reads live OS state
//! (see `xray_outbound_heuristic`), so only the fixed-name branches are
//! pure over the enumeration.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::mem::align_of;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIpForwardTable2, GetIpInterfaceEntry, IF_TYPE_IEEE80211,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

/// One network interface and its unicast addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIf {
    pub name: String,
    /// The adapter's interface index (`Ipv6IfIndex`, else `IfIndex`, as
    /// reported by `GetAdaptersAddresses`).
    pub index: u32,
    /// Whether the adapter's `IfType` is IEEE 802.11 wireless — the
    /// property Xray's outbound heuristic reads (`windows.IF_TYPE_IEEE80211`
    /// via `winipcfg`).
    pub wireless: bool,
    /// Whether the adapter's operational status is up (`OperStatus ==
    /// IfOperStatusUp` as reported by `GetAdaptersAddresses`).
    pub up: bool,
    pub ips: Vec<String>,
}

/// Owns the `GetAdaptersAddresses` output buffer. The buffer is allocated
/// with an explicit `Layout` aligned to `align_of::<IP_ADAPTER_ADDRESSES_LH>()`
/// (the struct contains 8-byte fields) and freed with the same layout on
/// drop — a `Vec<u8>` (alignment 1) cast to `*mut IP_ADAPTER_ADDRESSES_LH`
/// would be UB by contract and would only work via allocator over-alignment.
///
/// `pub(crate)` because the WFP DNS-shield adapter lookup
/// (`src/rt/wfp.rs::interface_index_by_name`) walks the same API and uses
/// the same aligned-allocation discipline instead of duplicating it.
pub(crate) struct AdapterBuffer {
    ptr: *mut u8,
    layout: Layout,
}

impl AdapterBuffer {
    /// Allocate `size` bytes aligned for `IP_ADAPTER_ADDRESSES_LH`, zeroed so
    /// no uninitialized byte is ever observed. `None` on zero size, an
    /// unrepresentable layout, or allocation failure — all are best-effort
    /// enumeration failures.
    pub(crate) fn allocate(size: usize) -> Option<Self> {
        if size == 0 {
            return None;
        }
        let layout = Layout::from_size_align(size, align_of::<IP_ADAPTER_ADDRESSES_LH>()).ok()?;
        // SAFETY: `layout` has a non-zero size (checked above) and a
        // power-of-two alignment, so `alloc_zeroed` returns a pointer valid
        // for `layout.size()` bytes of zeroed memory with `layout.align()`,
        // or null on allocation failure (filtered out below).
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }
        Some(Self { ptr, layout })
    }

    /// The buffer reinterpreted as the head of the adapter linked list. The
    /// cast is sound because the allocation's alignment (from the layout) is
    /// at least `align_of::<IP_ADAPTER_ADDRESSES_LH>()`.
    pub(crate) fn head(&self) -> *mut IP_ADAPTER_ADDRESSES_LH {
        self.ptr as *mut IP_ADAPTER_ADDRESSES_LH
    }
}

impl Drop for AdapterBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `alloc_zeroed` with exactly this
        // `layout` (stored verbatim at allocation time); it is non-null and
        // has not been freed or reallocated, so the dealloc matches.
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

/// List non-loopback, non-tunnel interfaces with their unicast IPs.
/// Returns an empty vec on any API failure (best-effort enumeration).
pub fn list() -> Vec<NetIf> {
    enumerate(true)
}

/// List non-loopback interfaces with their unicast IPs, including tunnel
/// interfaces. Mirrors Go's `net.Interfaces()` view for the Xray
/// outbound-interface heuristic (loopback is absent only because the
/// heuristic skips it by flag — outcome identical).
/// Returns an empty vec on any API failure (best-effort enumeration).
pub fn list_all() -> Vec<NetIf> {
    enumerate(false)
}

/// Shared `GetAdaptersAddresses` walk behind `list` and `list_all`.
/// `exclude_tunnel` is true for `list` (physical outbound interfaces only)
/// and false for `list_all` (the Xray heuristic's view). Loopback is always
/// excluded.
fn enumerate(exclude_tunnel: bool) -> Vec<NetIf> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // SAFETY: the family argument is 0 (`AF_UNSPEC`, every family), `flags`
    // is a valid flag set, and the adapter buffer argument is null with
    // `size` reporting 0 — the documented sizing call, which writes only the
    // required size. The second call passes `head`, the base of an
    // allocation made for exactly that size and aligned to at least
    // `align_of::<IP_ADAPTER_ADDRESSES_LH>()` (`AdapterBuffer` records the
    // layout it allocated and deallocates with it on every exit path), so the
    // chain the API writes stays inside the allocation. Every node is then
    // only reached through the null-terminated `Next` links the API wrote,
    // each dereference carrying its own SAFETY note below.
    unsafe {
        // Two-call sizing: the first call reports ERROR_BUFFER_OVERFLOW plus
        // the required buffer size.
        let mut size: u32 = 0;
        let rc = GetAdaptersAddresses(0, flags, None, None, &mut size);
        if rc != ERROR_BUFFER_OVERFLOW.0 || size == 0 {
            return Vec::new();
        }
        // Aligned heap buffer (not `Vec<u8>`): the adapter structs contain
        // 8-byte fields, and the walk must not rely on allocator
        // over-alignment. `AdapterBuffer` deallocs with the same layout on
        // every exit path (early returns, error branches, and the loop).
        let Some(buf) = AdapterBuffer::allocate(size as usize) else {
            return Vec::new();
        };
        let head = buf.head();
        let rc = GetAdaptersAddresses(0, flags, None, Some(head), &mut size);
        if rc != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: on success `GetAdaptersAddresses` filled the buffer
            // with a null-terminated chain of `IP_ADAPTER_ADDRESSES_LH`; each
            // node lives inside the allocation, and the allocation is aligned
            // to at least `align_of::<IP_ADAPTER_ADDRESSES_LH>()`, so `cur`
            // always points at a valid, properly aligned struct. The loop
            // terminates at the null `Next` the API wrote.
            let adapter = &*cur;
            if adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
                && (!exclude_tunnel || adapter.IfType != IF_TYPE_TUNNEL)
            {
                let name = if adapter.FriendlyName.is_null() {
                    String::new()
                } else {
                    // SAFETY: `FriendlyName` is a null-terminated wide string
                    // written by the API inside the adapter struct above.
                    adapter.FriendlyName.display().to_string()
                };
                let mut ips = Vec::new();
                let mut uni = adapter.FirstUnicastAddress;
                while !uni.is_null() {
                    // SAFETY: `FirstUnicastAddress` heads a null-terminated
                    // chain of unicast address structs that the API wrote in
                    // the same aligned allocation.
                    let addr = &*uni;
                    if let Some(ip) = format_sockaddr(addr.Address.lpSockaddr) {
                        ips.push(ip);
                    }
                    uni = addr.Next;
                }
                // `Anonymous1` is a union of `Alignment` (padding) and the
                // `{ Length, IfIndex }` pair the API always writes, so
                // reading `IfIndex` reads the variant in force; the union
                // member access is covered by this function's enclosing
                // unsafe block. Go's `net.Interface.Index` — the value
                // upstream's route-row skip and `InterfaceByIndex` use — is
                // `IfIndex`, with `Ipv6IfIndex` only as the fallback for an
                // adapter without one.
                let if_index = adapter.Anonymous1.Anonymous.IfIndex;
                let index = if if_index != 0 {
                    if_index
                } else {
                    adapter.Ipv6IfIndex
                };
                out.push(NetIf {
                    name,
                    index,
                    wireless: adapter.IfType == IF_TYPE_IEEE80211,
                    up: adapter.OperStatus == IfOperStatusUp,
                    ips,
                });
            }
            cur = adapter.Next;
        }
        out
    }
}

/// One prefix-length-0 row of the OS forward table: the interface it
/// belongs to and its route metric.
struct DefaultRouteRow {
    index: u32,
    metric: u32,
}

/// Every default-route (prefix-length 0) row of the OS forward table, in
/// table order — the exact row set Xray's `findOutboundInterface` iterates
/// (proxy/tun/tun_windows.go:360). `None` when the table cannot be read
/// (the caller's fail-soft branch, mirroring Go's error path).
fn default_route_rows() -> Option<Vec<DefaultRouteRow>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` starts null and the API either fails (table stays
    // null) or writes a pointer to a `MIB_IPFORWARD_TABLE2` it owns, freed
    // below by `FreeMibTable` on every path.
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if rc != ERROR_SUCCESS || table.is_null() {
        return None;
    }
    // SAFETY: `table` is a live, API-owned allocation aligned for
    // `MIB_IPFORWARD_TABLE2` (the API returns it fully formed), so `Table`
    // heads `NumEntries` contiguous, properly aligned `MIB_IPFORWARD_ROW2`s.
    // The rows are copied out before `FreeMibTable` releases the
    // allocation, so no read outlives it.
    let rows = unsafe {
        let num = (*table).NumEntries as usize;
        let first = std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
        let slice = std::slice::from_raw_parts(first, num);
        let out = slice
            .iter()
            .filter(|row| row.DestinationPrefix.PrefixLength == 0)
            .map(|row| DefaultRouteRow {
                index: row.InterfaceIndex,
                metric: row.Metric,
            })
            .collect::<Vec<_>>();
        FreeMibTable(table.cast());
        out
    };
    Some(rows)
}

/// The per-interface metric Xray's heuristic adds to the route metric
/// (`iface.Metric` via `winipcfg`'s `IPInterface`): `GetIpInterfaceEntry`
/// for the interface's IPv4 row, falling back to IPv6 (the Go code tries
/// `AF_INET` first, then `AF_INET6`). `None` when neither family resolves —
/// the Go code skips the candidate entirely in that case.
fn interface_metric(index: u32) -> Option<u32> {
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceIndex: index,
            ..MIB_IPINTERFACE_ROW::default()
        };
        // SAFETY: `row` is a fully initialized stack struct; the API
        // rewrites the fields it reports on success and leaves the rest
        // untouched.
        let rc = unsafe { GetIpInterfaceEntry(&mut row) };
        if rc == ERROR_SUCCESS {
            return Some(row.Metric);
        }
    }
    None
}

/// One scored candidate for the outbound heuristic: the interface plus its
/// combined route+interface metric.
#[derive(Clone, Copy)]
struct Candidate<'a> {
    iface: &'a NetIf,
    metric: u32,
}

/// The pure half of Xray's Windows `findOutboundInterface`
/// (proxy/tun/tun_windows.go:347-392): over the default-route candidates,
/// the lowest combined metric wins and any wireless winner overrides every
/// non-wireless one regardless of metric. Candidates come pre-filtered to
/// up interfaces and are named by interface, carrying the adapter's index
/// so the TUN's own row can be skipped — Go's
/// `r[i].InterfaceIndex == uint32(tunIndex)` skip. The I/O half
/// (`xray_outbound_heuristic`) owns the enumeration, route read and metric
/// lookups. `None` when no candidate qualifies.
fn pick_outbound_interface<'a>(
    candidates: impl IntoIterator<Item = Candidate<'a>>,
    tun_self_index: Option<u32>,
) -> Option<&'a str> {
    let mut wired: Option<Candidate> = None;
    let mut wireless: Option<Candidate> = None;
    for candidate in candidates {
        if Some(candidate.iface.index) == tun_self_index {
            continue;
        }
        // Strict `<`: Go's loop keeps the first row seen on a metric tie
        // (table order), so a later equal-metric row must not displace it.
        let slot = if candidate.iface.wireless {
            &mut wireless
        } else {
            &mut wired
        };
        if slot
            .as_ref()
            .is_none_or(|best| candidate.metric < best.metric)
        {
            *slot = Some(candidate);
        }
    }
    // Go: `if indexWifi != 0 { index = indexWifi }` — a wireless winner
    // overrides the wired pick unconditionally.
    wireless
        .or(wired)
        .map(|candidate| candidate.iface.name.as_str())
}

/// Pick the interface Xray-core's Windows `findOutboundInterface` binds
/// for an `auto` TUN outbound. Reads the live forward table and per-
/// interface metrics (the OS facts the Go implementation reads through
/// winipcfg), keeps the up interfaces other than the TUN's own, and scores
/// them with [`pick_outbound_interface`].
///
/// Returns `None` when the route table cannot be read or no candidate
/// qualifies — the probe then dials unbound, mirroring Go's nil-interface
/// fallback.
fn xray_outbound_heuristic(ifaces: &[NetIf], tun_self_index: Option<u32>) -> Option<&str> {
    let rows = default_route_rows()?;
    let candidates = rows.into_iter().filter_map(|row| {
        let iface = ifaces.iter().find(|iface| iface.index == row.index)?;
        if !iface.up {
            return None;
        }
        let metric = interface_metric(row.index)?;
        Some(Candidate {
            iface,
            metric: row.metric.saturating_add(metric),
        })
    });
    pick_outbound_interface(candidates, tun_self_index)
}

/// Xray's wire default for the TUN adapter name: a TUN inbound whose
/// settings carry no `name` makes the core create a `tun0` adapter. A
/// cleared app setting produces exactly such a name-less inbound (the wire
/// form drops the empty string), so this is the effective name wherever one
/// is derived from the setting.
pub const DEFAULT_TUN_ADAPTER_NAME: &str = "tun0";

/// Derive the TUN adapter's effective wire name from a configured
/// (settings) name: the trimmed name, or [`DEFAULT_TUN_ADAPTER_NAME`] when
/// nothing but whitespace is configured.
pub fn tun_adapter_name(configured_name: &str) -> &str {
    let trimmed = configured_name.trim();
    if trimmed.is_empty() {
        DEFAULT_TUN_ADAPTER_NAME
    } else {
        trimmed
    }
}

/// The verdict for a configured fixed TUN uplink name, checked against an
/// enumeration view (production passes the physical-only [`list`] view).
/// A pinned name makes a TUN-mode core bind every dial — the outbound chain
/// and the system-resolver bootstrap — to that adapter's index; a down or
/// vanished adapter still binds, and every socket then fails
/// unreachable-host, a total outage with routing rules looking fine. The
/// name must therefore currently exist AND be up.
///
/// The verdict is mode-independent: the commit guard applies its own
/// TUN-active precondition (nothing binds while TUN is off), the TUN screen
/// surfaces a broken pin regardless (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedNameVerdict<'a> {
    /// The setting pins no name (`""` or `"auto"`, after trimming) —
    /// nothing can bind a stale index.
    Unpinned,
    /// The pinned adapter exists and is up.
    Up,
    /// The pinned adapter exists but is down.
    Down { name: &'a str },
    /// The pinned adapter is absent from the enumeration.
    Missing { name: &'a str },
}

/// The fixed-name verdict for the TUN `autoOutboundsInterface` setting.
/// Pure — the caller supplies the enumeration view.
pub fn fixed_name_verdict<'a>(setting: &'a str, ifaces: &'a [NetIf]) -> FixedNameVerdict<'a> {
    let setting = setting.trim();
    if setting.is_empty() || setting == "auto" {
        return FixedNameVerdict::Unpinned;
    }
    match ifaces.iter().find(|iface| iface.name == setting) {
        Some(iface) if iface.up => FixedNameVerdict::Up,
        Some(_) => FixedNameVerdict::Down { name: setting },
        None => FixedNameVerdict::Missing { name: setting },
    }
}

/// The probe child's uplink resolution: which interface it binds its dials
/// to, or why the configured setting cannot be used. Production passes the
/// tunnel-inclusive [`list_all`] view; see the module docs for the split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeUplink<'a> {
    /// No binding: TUN inactive, no setting configured, or a heuristic with
    /// no qualifying candidate.
    Unbound,
    /// Bind the dials to this interface.
    Interface(&'a str),
    /// The pinned adapter is the TUN adapter itself.
    TunSelf { name: &'a str },
    /// The pinned adapter exists but is down.
    Down { name: &'a str },
    /// The pinned adapter is absent from the enumeration.
    Missing { name: &'a str },
}

/// Resolve the interface the probe child binds its dials to while the main
/// core is up with TUN: the TUN `autoOutboundsInterface` setting, resolved
/// at probe time against a fresh adapter enumeration so a rename or newly
/// enabled adapter is picked up.
///
/// - TUN not active: no capture to bypass — [`ProbeUplink::Unbound`].
/// - Setting `None`: no interface configured — unbound; the dial rides the
///   TUN, the pollution the binding is meant to prevent.
/// - Setting `""` or `"auto"`: replicate Xray's `findOutboundInterface`;
///   this branch reads the live route table and per-interface metrics (see
///   `xray_outbound_heuristic`), so it performs I/O. Unbound when no
///   candidate qualifies (proceed unbound, like Xray's nil interface).
/// - Fixed name: must exist in the enumeration and be up, else the verdict
///   names the failure — a silent fallback would re-introduce the polluted
///   measurement while looking valid. This branch reads no OS state.
///
/// `tun_self_index` is the main core's own TUN adapter index (the caller
/// resolves [`tun_adapter_name`] against the enumeration): it is excluded
/// from the heuristic and a fixed name resolving to it is rejected,
/// mirroring Go's `iface.Index == tunIndex` skip — binding to the TUN's own
/// interface would send the dial back into the tunnel, re-introducing the
/// exact pollution this resolution removes.
pub fn resolve_probe_uplink<'a>(
    setting: Option<&'a str>,
    tun_active: bool,
    tun_self_index: Option<u32>,
    ifaces: &'a [NetIf],
) -> ProbeUplink<'a> {
    if !tun_active {
        return ProbeUplink::Unbound;
    }
    let Some(setting) = setting else {
        return ProbeUplink::Unbound;
    };
    if setting.is_empty() || setting == "auto" {
        return match xray_outbound_heuristic(ifaces, tun_self_index) {
            Some(name) => ProbeUplink::Interface(name),
            None => ProbeUplink::Unbound,
        };
    }
    let fixed = ifaces.iter().find(|iface| iface.name == setting);
    if fixed.is_some_and(|iface| Some(iface.index) == tun_self_index) {
        return ProbeUplink::TunSelf { name: setting };
    }
    match fixed {
        Some(iface) if iface.up => ProbeUplink::Interface(setting),
        Some(_) => ProbeUplink::Down { name: setting },
        None => ProbeUplink::Missing { name: setting },
    }
}

/// Format a `sockaddr` the OS handed back as a string, or `None` for a
/// family this app does not recognize.
///
/// # Safety
///
/// `sa` must be null or point at a complete `SOCKADDR` whose `sa_family`
/// member accurately describes the object — the two families read here are
/// `SOCKADDR_IN` (16 bytes) and `SOCKADDR_IN6` (28 bytes), each starting with
/// the same 2-byte family member — and it must stay valid for the call.
unsafe fn format_sockaddr(sa: *const SOCKADDR) -> Option<String> {
    // SAFETY: the caller guarantees `sa` is null or points at a complete,
    // live `SOCKADDR` whose family member describes it (see `# Safety`).
    unsafe { sockaddr_ip(sa).map(|ip| ip.to_string()) }
}

/// The address a live `SOCKADDR` names, in either family this app reads
/// (`SOCKADDR_IN`, `SOCKADDR_IN6`), or `None` for the null pointer and for
/// any other family. One decoding site for every caller that needs the
/// address rather than its text.
///
/// # Safety
///
/// `sa` must be null or point at a complete `SOCKADDR` whose `sa_family`
/// member accurately describes the object — the two families read here are
/// `SOCKADDR_IN` (16 bytes) and `SOCKADDR_IN6` (28 bytes), each starting with
/// the same 2-byte family member — and it must stay valid for the call.
pub(crate) unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<std::net::IpAddr> {
    // SAFETY: the caller guarantees `sa` is null or points at a complete,
    // live `SOCKADDR` whose family member describes it (see `# Safety`). The
    // null check runs before any dereference, and the casts only re-interpret
    // that same object as the concrete struct named by `sa_family`, both of
    // which begin with the family member already read. Every field reached is
    // inside the size that struct declares, and no pointer escapes.
    unsafe {
        if sa.is_null() {
            return None;
        }
        let family = (*sa).sa_family;
        if family == AF_INET {
            let sin = &*(sa as *const SOCKADDR_IN);
            let b = sin.sin_addr.S_un.S_un_b;
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                b.s_b1, b.s_b2, b.s_b3, b.s_b4,
            )))
        } else if family == AF_INET6 {
            let sin6 = &*(sa as *const SOCKADDR_IN6);
            let bytes = sin6.sin6_addr.u.Byte;
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        } else {
            None
        }
    }
}

/// A fixture adapter view for unit tests across the crate: the enumeration
/// is a live OS call, so tests build the view by hand. `index` must be
/// nonzero (real adapters always report one); callers that never key on
/// the value pass any nonzero index.
#[cfg(test)]
pub(crate) fn test_iface(name: &str, index: u32, wireless: bool, up: bool, ips: &[&str]) -> NetIf {
    NetIf {
        name: name.to_string(),
        index,
        wireless,
        up,
        ips: ips.iter().map(|ip| (*ip).to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_enumeration_is_live() {
        // Smoke test for the aligned-buffer walk: it must complete without
        // panicking and yield at least the physical adapters on this
        // networked Windows host (loopback and tunnel are skipped). The
        // index must be populated — the heuristic keys on it.
        let adapters = list();
        assert!(
            !adapters.is_empty(),
            "expected at least one non-loopback adapter on a networked Windows host"
        );
        assert!(
            adapters.iter().all(|adapter| adapter.index != 0),
            "every enumerated adapter must carry its interface index"
        );
    }

    #[test]
    fn heuristic_picks_the_live_default_route_owner() {
        // Live oracle for the I/O half: whatever this machine's route table
        // holds, the winner must be an up enumerated interface that owns a
        // prefix-length-0 row and is not the TUN's own adapter. The scoring
        // policy itself is pinned deterministically in the picker tests
        // below.
        let all = list_all();
        let tun_index = all
            .iter()
            .find(|iface| iface.name == "broccoli0")
            .map(|iface| iface.index);
        let winner = xray_outbound_heuristic(&all, tun_index)
            .expect("a networked host has a default-route owning interface");
        let winning = all
            .iter()
            .find(|iface| iface.name == winner)
            .expect("the winner must come from the enumeration");
        assert!(winning.up, "the heuristic must never pick a down adapter");
        if let Some(tun_index) = tun_index {
            assert_ne!(
                winning.index, tun_index,
                "the TUN adapter itself must never win"
            );
        }
        let rows = default_route_rows().expect("the table read that just succeeded");
        assert!(
            rows.iter().any(|row| row.index == winning.index),
            "the winner must own a default route"
        );
    }

    fn candidate(iface: &NetIf, metric: u32) -> Candidate<'_> {
        Candidate { iface, metric }
    }

    #[test]
    fn picker_takes_the_lowest_metric_in_any_row_order() {
        let wired = test_iface("wired", 26, false, true, &["192.168.1.2"]);
        let backup = test_iface("backup", 27, false, true, &["10.0.0.2"]);
        let rows = [candidate(&wired, 25), candidate(&backup, 60)];
        assert_eq!(pick_outbound_interface(rows, None), Some("wired"));
        let rows = [candidate(&backup, 60), candidate(&wired, 25)];
        assert_eq!(pick_outbound_interface(rows, None), Some("wired"));
    }

    #[test]
    fn picker_keeps_the_first_row_on_a_metric_tie() {
        // Go's strict `<` never replaces on equality, so the earlier table
        // row wins.
        let first = test_iface("first", 26, false, true, &["192.168.1.2"]);
        let second = test_iface("second", 27, false, true, &["10.0.0.2"]);
        let rows = [candidate(&first, 25), candidate(&second, 25)];
        assert_eq!(pick_outbound_interface(rows, None), Some("first"));
    }

    #[test]
    fn picker_prefers_any_wireless_over_a_better_wired_metric() {
        // Go overrides the pick with the best wireless row unconditionally
        // (`if indexWifi != 0 { index = indexWifi }`), so a wireless
        // candidate wins even at a much higher metric.
        let wired = test_iface("wired", 26, false, true, &["192.168.1.2"]);
        let wifi = test_iface("Wi-Fi", 17, true, true, &["10.0.0.5"]);
        let rows = [candidate(&wired, 5), candidate(&wifi, 400)];
        assert_eq!(pick_outbound_interface(rows, None), Some("Wi-Fi"));
    }

    #[test]
    fn picker_skips_the_tun_adapters_own_index() {
        // A user-configured `0.0.0.0/0` in autoSystemRoutingTable puts a
        // prefix-length-0 row on the TUN adapter (beyond the /1 split
        // routes the app emits itself); Go skips that row by interface
        // index, and so must the pick.
        let tun = test_iface("broccoli0", 9, false, true, &["10.255.0.1"]);
        let wired = test_iface("wired", 26, false, true, &["192.168.1.2"]);
        let rows = [candidate(&tun, 0), candidate(&wired, 25)];
        assert_eq!(
            pick_outbound_interface(rows, None),
            Some("broccoli0"),
            "precondition: without the exclusion the TUN row would win"
        );
        assert_eq!(pick_outbound_interface(rows, Some(9)), Some("wired"));
        // The TUN row alone leaves nothing to bind.
        let only_tun = [candidate(&tun, 0)];
        assert_eq!(pick_outbound_interface(only_tun, Some(9)), None);
    }

    #[test]
    fn picker_without_candidates_returns_none() {
        assert_eq!(pick_outbound_interface(Vec::new(), None), None);
    }

    #[test]
    fn tun_adapter_name_trims_and_falls_back_to_the_wire_default() {
        // The constant is the wire contract: a name-less TUN inbound makes
        // the core create `tun0`.
        assert_eq!(DEFAULT_TUN_ADAPTER_NAME, "tun0");
        assert_eq!(tun_adapter_name("broccoli0"), "broccoli0");
        assert_eq!(tun_adapter_name("  broccoli0  "), "broccoli0");
        assert_eq!(tun_adapter_name(""), DEFAULT_TUN_ADAPTER_NAME);
        assert_eq!(tun_adapter_name(" \t "), DEFAULT_TUN_ADAPTER_NAME);
    }

    #[test]
    fn fixed_verdict_unpins_empty_and_auto_settings() {
        let ifaces = vec![test_iface("wired", 2, false, false, &[])];
        for setting in ["", "  ", "auto", " auto "] {
            assert_eq!(
                fixed_name_verdict(setting, &ifaces),
                FixedNameVerdict::Unpinned,
                "{setting:?} pins no index"
            );
            assert_eq!(
                fixed_name_verdict(setting, &[]),
                FixedNameVerdict::Unpinned,
                "{setting:?} needs no enumeration"
            );
        }
    }

    #[test]
    fn fixed_verdict_reports_up_down_and_missing_names() {
        let ifaces = vec![
            test_iface("Ethernet", 2, false, true, &["10.0.0.1"]),
            test_iface("wired", 3, false, false, &[]),
        ];
        assert_eq!(
            fixed_name_verdict("Ethernet", &ifaces),
            FixedNameVerdict::Up
        );
        assert_eq!(
            fixed_name_verdict(" Ethernet ", &ifaces),
            FixedNameVerdict::Up,
            "the setting is trimmed before the lookup"
        );
        assert_eq!(
            fixed_name_verdict("wired", &ifaces),
            FixedNameVerdict::Down { name: "wired" }
        );
        assert_eq!(
            fixed_name_verdict("ghost", &ifaces),
            FixedNameVerdict::Missing { name: "ghost" }
        );
    }

    #[test]
    fn probe_inactive_tun_stays_unbound_for_every_setting() {
        // Mode off: no capture to bypass, so no setting resolves — not even
        // a fixed name that is down, missing, or the TUN's own adapter.
        let ifaces = vec![test_iface("broccoli0", 9, false, true, &["10.255.0.1"])];
        for setting in [
            None,
            Some(""),
            Some("auto"),
            Some("ghost"),
            Some("broccoli0"),
        ] {
            assert_eq!(
                resolve_probe_uplink(setting, false, Some(9), &ifaces),
                ProbeUplink::Unbound,
                "{setting:?} must stay unbound while TUN is inactive"
            );
        }
    }

    #[test]
    fn probe_none_setting_stays_unbound_even_when_tun_is_active() {
        // An unconfigured interface must leave the probe unbound, so its
        // dial rides the TUN instead of silently binding whatever the
        // heuristic would pick.
        let ifaces = vec![test_iface("Wi-Fi", 5, true, true, &["10.0.0.5"])];
        assert_eq!(
            resolve_probe_uplink(None, true, None, &ifaces),
            ProbeUplink::Unbound
        );
    }

    #[test]
    fn probe_fixed_name_covers_interface_down_and_missing() {
        let ifaces = vec![
            test_iface("Ethernet", 2, false, true, &["10.0.0.1"]),
            test_iface("wired", 3, false, false, &[]),
            test_iface("Wi-Fi", 5, true, true, &["10.0.0.5"]),
        ];
        assert_eq!(
            resolve_probe_uplink(Some("Ethernet"), true, None, &ifaces),
            ProbeUplink::Interface("Ethernet")
        );
        assert_eq!(
            resolve_probe_uplink(Some("wired"), true, None, &ifaces),
            ProbeUplink::Down { name: "wired" }
        );
        assert_eq!(
            resolve_probe_uplink(Some("ghost"), true, None, &ifaces),
            ProbeUplink::Missing { name: "ghost" }
        );
    }

    #[test]
    fn probe_fixed_name_equal_to_the_tun_adapter_is_rejected() {
        // Present and up, yet rejected: binding to the TUN's own interface
        // would send the dial back into the tunnel.
        let ifaces = vec![
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.1"]),
        ];
        assert_eq!(
            resolve_probe_uplink(Some("broccoli0"), true, Some(9), &ifaces),
            ProbeUplink::TunSelf { name: "broccoli0" }
        );
    }

    #[test]
    fn probe_auto_with_no_enumerated_interface_is_unbound() {
        // No route row can match an empty enumeration, so the auto branch
        // resolves to nothing regardless of the host's real route table.
        assert_eq!(
            resolve_probe_uplink(Some("auto"), true, None, &[]),
            ProbeUplink::Unbound
        );
    }
}

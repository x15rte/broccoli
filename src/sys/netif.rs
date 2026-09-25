//! Network interface enumeration via `GetAdaptersAddresses`.
//! Used to pick a physical outbound interface for TUN routing rules.
//!
//! The TUN uplink rule lives here too — [`fixed_name_verdict`],
//! [`resolve_probe_uplink`], and [`tun_adapter_name`] are pure functions
//! over an enumeration view the caller supplies. The view and the mode gate
//! differ by caller, deliberately: the commit guard and the TUN screen pass
//! the physical-only [`list`] view, while the probe passes the
//! tunnel-inclusive [`list_all`] view with the TUN's own adapter excluded;
//! and while the commit guard only judges a bound TUN (mode on), the TUN
//! screen surfaces a broken pinned pick regardless of mode — it would
//! become the outage the moment TUN switches on. Both splits are
//! behavior-visible: a tunnel-type adapter reads as missing to the guard
//! yet may resolve a probe.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::mem::align_of;
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

/// One network interface and its unicast addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIf {
    pub name: String,
    pub ips: Vec<String>,
    /// Whether the adapter's operational status is up (`OperStatus ==
    /// IfOperStatusUp` as reported by `GetAdaptersAddresses`).
    pub up: bool,
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
                out.push(NetIf {
                    name,
                    ips,
                    up: adapter.OperStatus == IfOperStatusUp,
                });
            }
            cur = adapter.Next;
        }
        out
    }
}

/// Pick the best physical outbound interface for TUN traffic, replicating
/// Xray-core's `findOutboundInterface`/`scoreWindowsInterface`
/// (proxy/tun/tun_windows.go) on the `list_all` view. Candidates are the
/// up interfaces with at least one IP whose name does not contain
/// "vEthernet" (case-sensitive, as in Go) and whose name is not
/// `excluded_name` — the main core's own TUN adapter, mirroring Go's
/// `iface.Index == tunIndex` skip (the adapter's friendly name is its wire
/// `name`); loopback never appears in the input (both enumerations exclude
/// it), matching Go's flag check. Scoring mirrors Xray: +2 when the
/// lowercased name contains "wlan" or "wi-fi", +1 when any IP starts with
/// "192.168.". The highest score wins; ties go to the lexicographically
/// smaller name. Returns the winner's name, or `None` when no interface
/// qualifies.
pub fn xray_outbound_heuristic<'a>(
    ifaces: &'a [NetIf],
    excluded_name: Option<&str>,
) -> Option<&'a str> {
    let mut best: Option<(&NetIf, i32)> = None;
    for iface in ifaces {
        if Some(iface.name.as_str()) == excluded_name {
            continue;
        }
        if iface.name.contains("vEthernet") {
            continue;
        }
        if !iface.up {
            continue;
        }
        if iface.ips.is_empty() {
            continue;
        }
        let score = score_xray_interface(iface);
        match best {
            None => best = Some((iface, score)),
            Some((best_iface, best_score)) => {
                if score > best_score || (score == best_score && iface.name < best_iface.name) {
                    best = Some((iface, score));
                }
            }
        }
    }
    best.map(|(iface, _)| iface.name.as_str())
}

/// Xray-core's `scoreWindowsInterface`: +2 for a "wlan"/"wi-fi" name (after
/// lowercasing), +1 when any unicast IP starts with "192.168.".
fn score_xray_interface(iface: &NetIf) -> i32 {
    let mut score = 0;
    let name = iface.name.to_lowercase();
    if name.contains("wlan") || name.contains("wi-fi") {
        score += 2;
    }
    if iface.ips.iter().any(|ip| ip.starts_with("192.168.")) {
        score += 1;
    }
    score
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
/// enabled adapter is picked up. Pure — the enumeration is passed in.
///
/// - TUN not active: no capture to bypass — [`ProbeUplink::Unbound`].
/// - Setting `None`: no interface configured — unbound; the dial rides the
///   TUN, the pollution the binding is meant to prevent.
/// - Setting `""` or `"auto"`: replicate Xray's `findOutboundInterface`
///   heuristic; unbound when no candidate qualifies (proceed unbound, like
///   Xray's nil interface).
/// - Fixed name: must exist in the enumeration and be up, else the verdict
///   names the failure — a silent fallback would re-introduce the polluted
///   measurement while looking valid.
///
/// `tun_self_name` is the main core's own TUN adapter (its wire name, per
/// [`tun_adapter_name`]): it is excluded from the heuristic and rejected as
/// a fixed target, mirroring Go's `iface.Index == tunIndex` skip — binding
/// to the TUN's own interface would send the dial back into the tunnel,
/// re-introducing the exact pollution this resolution removes.
pub fn resolve_probe_uplink<'a>(
    setting: Option<&'a str>,
    tun_active: bool,
    tun_self_name: Option<&'a str>,
    ifaces: &'a [NetIf],
) -> ProbeUplink<'a> {
    if !tun_active {
        return ProbeUplink::Unbound;
    }
    let Some(setting) = setting else {
        return ProbeUplink::Unbound;
    };
    if setting.is_empty() || setting == "auto" {
        return match xray_outbound_heuristic(ifaces, tun_self_name) {
            Some(name) => ProbeUplink::Interface(name),
            None => ProbeUplink::Unbound,
        };
    }
    if Some(setting) == tun_self_name {
        return ProbeUplink::TunSelf { name: setting };
    }
    match ifaces.iter().find(|iface| iface.name == setting) {
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
            Some(format!("{}.{}.{}.{}", b.s_b1, b.s_b2, b.s_b3, b.s_b4))
        } else if family == AF_INET6 {
            let sin6 = &*(sa as *const SOCKADDR_IN6);
            let bytes = sin6.sin6_addr.u.Byte;
            Some(std::net::Ipv6Addr::from(bytes).to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_enumeration_is_live() {
        // Smoke test for the aligned-buffer walk: it must complete without
        // panicking and yield at least the physical adapters on this
        // networked Windows host (loopback and tunnel are skipped).
        let adapters = list();
        assert!(
            !adapters.is_empty(),
            "expected at least one non-loopback adapter on a networked Windows host"
        );
    }

    fn iface(name: &str, up: bool, ips: &[&str]) -> NetIf {
        NetIf {
            name: name.to_string(),
            up,
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn heuristic_prefers_wlan_name() {
        // Score 2 ("wlan" name) beats score 0 ("Ethernet" name).
        let ifaces = vec![
            iface("Ethernet", true, &["10.0.0.5"]),
            iface("wlan", true, &["10.0.0.6"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("wlan"));
    }

    #[test]
    fn heuristic_192_168_bonus_is_decisive() {
        // Equal name scores (0 vs 0): the 192.168.x prefix adds +1 and wins.
        let ifaces = vec![
            iface("Ethernet 2", true, &["10.0.0.5"]),
            iface("Ethernet", true, &["192.168.1.2"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("Ethernet"));
    }

    #[test]
    fn heuristic_wi_fi_matches_case_insensitively() {
        // "Wi-Fi" matches the "wi-fi" substring after lowercasing.
        let ifaces = vec![
            iface("Ethernet", true, &["10.0.0.5"]),
            iface("Wi-Fi", true, &["10.0.0.6"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("Wi-Fi"));
    }

    #[test]
    fn heuristic_skips_vethernet() {
        // "vEthernet" would score 3 but is skipped; the skip is
        // case-sensitive, so "VEthernet" is not skipped and wins.
        let ifaces = vec![
            iface("vEthernet (WSL)", true, &["192.168.1.1"]),
            iface("Ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("Ethernet"));

        let ifaces = vec![
            iface("VEthernet", true, &["192.168.1.1"]),
            iface("Ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("VEthernet"));
    }

    #[test]
    fn heuristic_skips_down_interfaces() {
        // Down "Wi-Fi" with a 192.168.x address (would score 3) is skipped.
        let ifaces = vec![
            iface("Wi-Fi", false, &["192.168.1.2"]),
            iface("Ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("Ethernet"));
    }

    #[test]
    fn heuristic_skips_interfaces_without_ips() {
        let ifaces = vec![
            iface("Wi-Fi", true, &[]),
            iface("Ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("Ethernet"));
    }

    #[test]
    fn heuristic_tie_breaks_lexicographically() {
        // Equal scores (2 vs 2): the lexicographically smaller name wins.
        let ifaces = vec![
            iface("wlan-b", true, &["10.0.0.6"]),
            iface("wlan-a", true, &["10.0.0.7"]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), Some("wlan-a"));
    }

    #[test]
    fn heuristic_all_skipped_returns_none() {
        let ifaces = vec![
            iface("vEthernet (WSL)", true, &["192.168.1.1"]),
            iface("Wi-Fi", false, &["192.168.1.2"]),
            iface("Ethernet", true, &[]),
        ];
        assert_eq!(xray_outbound_heuristic(&ifaces, None), None);
        assert_eq!(xray_outbound_heuristic(&[], None), None);
    }

    #[test]
    fn heuristic_excludes_the_tun_adapter_itself() {
        // Go's findOutboundInterface skips iface.Index == tunIndex; the TUN
        // adapter ("broccoli0", up, one IP, score 0) must never win a tie
        // against a physical adapter or be selected on its own.
        let ifaces = vec![
            iface("broccoli0", true, &["10.255.0.1"]),
            iface("ethernet", true, &["10.0.0.1"]),
        ];
        // Without exclusion the score-0 tie goes to "broccoli0" (byte-wise
        // name order: "broccoli0" < "ethernet").
        assert_eq!(
            xray_outbound_heuristic(&ifaces, None),
            Some("broccoli0"),
            "precondition: without exclusion the TUN adapter would win"
        );
        assert_eq!(
            xray_outbound_heuristic(&ifaces, Some("broccoli0")),
            Some("ethernet"),
            "the TUN adapter must be excluded by name"
        );
        // Excluding the only candidate leaves nothing.
        let only_tun = vec![iface("broccoli0", true, &["10.255.0.1"])];
        assert_eq!(xray_outbound_heuristic(&only_tun, Some("broccoli0")), None);
        // A non-matching exclusion name changes nothing.
        assert_eq!(
            xray_outbound_heuristic(&ifaces, Some("vEthernet (Default Switch)")),
            Some("broccoli0")
        );
    }

    #[test]
    fn heuristic_is_deterministic() {
        let ifaces = vec![
            iface("Wi-Fi", true, &["10.0.0.6"]),
            iface("Ethernet", true, &["192.168.1.2"]),
            iface("wlan", false, &["10.0.0.9"]),
        ];
        let first = xray_outbound_heuristic(&ifaces, None);
        let second = xray_outbound_heuristic(&ifaces, None);
        assert_eq!(first, second);

        // The winner is chosen by score/name, not input order: a reversed
        // input yields the same result.
        let mut reversed = ifaces.clone();
        reversed.reverse();
        assert_eq!(xray_outbound_heuristic(&reversed, None), first);
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
        let ifaces = vec![iface("wired", false, &[])];
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
            iface("Ethernet", true, &["10.0.0.1"]),
            iface("wired", false, &[]),
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
        let ifaces = vec![iface("broccoli0", true, &["10.255.0.1"])];
        for setting in [
            None,
            Some(""),
            Some("auto"),
            Some("ghost"),
            Some("broccoli0"),
        ] {
            assert_eq!(
                resolve_probe_uplink(setting, false, Some("broccoli0"), &ifaces),
                ProbeUplink::Unbound,
                "{setting:?} must stay unbound while TUN is inactive"
            );
        }
    }

    #[test]
    fn probe_unpinned_settings_resolve_the_heuristic_winner() {
        // Score 2 ("Wi-Fi" name) beats score 1 ("Ethernet" with 192.168.x).
        let ifaces = vec![
            iface("Ethernet", true, &["192.168.1.5"]),
            iface("Wi-Fi", true, &["10.0.0.5"]),
        ];
        for setting in [Some(""), Some("auto")] {
            assert_eq!(
                resolve_probe_uplink(setting, true, None, &ifaces),
                ProbeUplink::Interface("Wi-Fi"),
                "{setting:?} resolves like auto"
            );
        }
        assert_eq!(
            resolve_probe_uplink(Some("auto"), true, None, &[]),
            ProbeUplink::Unbound,
            "no candidate is not an error"
        );
    }

    #[test]
    fn probe_none_setting_stays_unbound_even_when_tun_is_active() {
        // An unconfigured interface must leave the probe unbound, so its
        // dial rides the TUN instead of silently binding whatever the
        // heuristic would pick.
        let ifaces = vec![iface("Wi-Fi", true, &["10.0.0.5"])];
        assert_eq!(
            resolve_probe_uplink(None, true, None, &ifaces),
            ProbeUplink::Unbound
        );
    }

    #[test]
    fn probe_fixed_name_covers_interface_down_and_missing() {
        let ifaces = vec![
            iface("Ethernet", true, &["10.0.0.1"]),
            iface("wired", false, &[]),
            iface("Wi-Fi", true, &["10.0.0.5"]),
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
    fn probe_auto_excludes_the_tun_adapter_itself() {
        // The TUN adapter ("broccoli0", up, one IP, score 0) ties with a
        // plain "ethernet" and wins by byte-wise name order — exactly the
        // case Go's `iface.Index == tunIndex` skip prevents.
        let ifaces = vec![
            iface("broccoli0", true, &["10.255.0.1"]),
            iface("ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(
            resolve_probe_uplink(Some("auto"), true, None, &ifaces),
            ProbeUplink::Interface("broccoli0"),
            "precondition: without the exclusion the TUN adapter would win"
        );
        assert_eq!(
            resolve_probe_uplink(Some("auto"), true, Some("broccoli0"), &ifaces),
            ProbeUplink::Interface("ethernet"),
            "the TUN adapter must be excluded by name"
        );
    }

    #[test]
    fn probe_fixed_name_equal_to_the_tun_adapter_is_rejected() {
        // Present and up, yet rejected: binding to the TUN's own interface
        // would send the dial back into the tunnel.
        let ifaces = vec![
            iface("broccoli0", true, &["10.255.0.1"]),
            iface("Ethernet", true, &["10.0.0.1"]),
        ];
        assert_eq!(
            resolve_probe_uplink(Some("broccoli0"), true, Some("broccoli0"), &ifaces),
            ProbeUplink::TunSelf { name: "broccoli0" }
        );
    }
}

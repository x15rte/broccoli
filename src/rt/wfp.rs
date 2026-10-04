//! WFP egress shield (best-effort): while a TUN core with a DNS module runs,
//! block direct outbound connections to remote port 53 unless they egress
//! the TUN interface (the in-tun DNS listener at the gateway address) or
//! originate from the xray process itself (its own upstream dials). This
//! kills the physical-adapter on-link gateway DNS vector that never enters
//! the TUN (Windows multi-homed resolution would otherwise leak queries
//! outside the tunnel). An address family the tunnel does not carry gets
//! blocked whole, so its traffic cannot escape through the physical
//! adapters either; neighbor discovery stays permitted so the link keeps
//! working.
//!
//! Weight order in the broccoli sublayer, highest first: the core's app-id
//! permit (13) > un-carried-family block (12) > TUN-interface permit (11) >
//! port-53 block (10). No address exemptions, so the resolver's DNS path
//! works exactly when it routes into the tunnel, and nothing else.
//!
//! The block half needs no adapter, so the helper installs it before the
//! TUN interface index is known (fail closed across startup) and adds the
//! TUN-interface permits in a second install once the adapter exists.
//! Filters live in a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) so
//! the kernel removes them when the helper process exits (crash-safe).
//! Best-effort: the caller logs failures, never fatal.

use crate::diag::{Diag, DiagError};
use crate::r#gen::keys;
use crate::i18n::Key;
use crate::sys::netif::AdapterBuffer;
use std::path::Path;
use std::sync::Mutex;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE,
    FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_FILTER_FLAGS, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows::core::{GUID, PCWSTR, PWSTR};

/// The sublayer one install's filters live in — never the default sublayer,
/// so nothing else can be confused by them. WFP keys sublayers system-wide
/// rather than per session, so every install needs its own key: the
/// fail-closed install's session is still alive when the full install
/// replaces it, and reusing the key would fail the second sublayer add
/// (`FWP_E_ALREADY_EXISTS`), which would tear the whole shield down. The
/// previous session is closed as soon as the new one is stored, so the two
/// sublayers overlap only for that replace.
fn sublayer_key() -> GUID {
    GUID::from_u128(uuid::Uuid::new_v4().as_u128())
}

const DNS_PORT: u16 = 53;

/// Permit weight for the core's own dials (any interface) — above every
/// block.
const WEIGHT_PERMIT_XRAY: u8 = 13;
/// Permit weight for neighbor discovery on an IPv6 family the tunnel does
/// not carry — above that family's block, so the physical link stays alive.
const WEIGHT_PERMIT_NDP: u8 = 13;
/// Block weight for the whole address family the tunnel does not carry:
/// below the permits, above the TUN-interface permit.
const WEIGHT_BLOCK_UNSUPPORTED: u8 = 12;
/// Permit weight for traffic egressing the TUN interface (the in-tun DNS
/// listener) — between the family block and the port-53 block.
const WEIGHT_PERMIT_TUN: u8 = 11;
const WEIGHT_BLOCK_DNS: u8 = 10;

/// The IPv6 protocol number (RFC 8200) the neighbor-discovery permits match.
const IPPROTO_ICMPV6: u8 = 58;
/// Router solicitation (RFC 4861) is sent to the all-routers link-local
/// multicast address, so its permit is narrowed to that destination.
const NDP_ROUTER_SOLICITATION: u16 = 133;
/// ICMPv6 neighbor-discovery types (RFC 4861) that must survive the
/// un-carried-family block: without them the machine's IPv6 link loses its
/// routers and neighbors even though the family is otherwise unreachable.
const NDP_TYPES: [u16; 3] = [NDP_ROUTER_SOLICITATION, 135, 136];
const ALL_ROUTERS_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// At the ALE connect layers an ICMPv6 message's type and code travel in the
/// local and remote port fields, so the neighbor-discovery permits match
/// them through the port condition keys (the ALE layers carry no condition
/// of their own for an ICMP field).
const CONDITION_ICMPV6_TYPE: GUID = FWPM_CONDITION_IP_LOCAL_PORT;
const CONDITION_ICMPV6_CODE: GUID = FWPM_CONDITION_IP_REMOTE_PORT;

/// The address family one filter belongs to: every filter exists in both ALE
/// connect layers, one instance per family the shield has an opinion about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    V4,
    V6,
}

impl Family {
    const BOTH: [Family; 2] = [Family::V4, Family::V6];

    fn layer(self) -> GUID {
        match self {
            Family::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Family::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }

    /// The word the filter's display name carries, so a `wf.msc` reader can
    /// tell the two families' filters apart.
    fn suffix(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
}

/// What one filter does. Its weight and WFP action follow from the kind, so
/// the ordering that decides which traffic survives has one home.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// Permit the staged core's own dials, on either family and any
    /// interface: the core's transport leaves through the physical adapters
    /// whatever the tunnel carries.
    AppIdPermit,
    /// Permit one neighbor-discovery message (the payload is the ICMPv6
    /// type) so an un-carried IPv6 family keeps its link.
    NdpPermit(u16),
    /// Block the whole address family the tunnel does not carry.
    UnsupportedFamilyBlock,
    /// Permit traffic egressing the TUN interface (the in-tun DNS listener).
    TunInterfacePermit,
    /// Block direct DNS (remote port 53) outside the tunnel.
    DnsBlock,
}

impl Kind {
    fn weight(self) -> u8 {
        match self {
            Kind::AppIdPermit => WEIGHT_PERMIT_XRAY,
            Kind::NdpPermit(_) => WEIGHT_PERMIT_NDP,
            Kind::UnsupportedFamilyBlock => WEIGHT_BLOCK_UNSUPPORTED,
            Kind::TunInterfacePermit => WEIGHT_PERMIT_TUN,
            Kind::DnsBlock => WEIGHT_BLOCK_DNS,
        }
    }

    fn action(self) -> FWP_ACTION_TYPE {
        match self {
            Kind::AppIdPermit | Kind::NdpPermit(_) | Kind::TunInterfacePermit => FWP_ACTION_PERMIT,
            Kind::UnsupportedFamilyBlock | Kind::DnsBlock => FWP_ACTION_BLOCK,
        }
    }

    /// Whether the filter is a hard permit: it carries
    /// `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, so no later sublayer's block
    /// can soften it. Only the core's own dials need that strength.
    fn clear_action_right(self) -> bool {
        matches!(self, Kind::AppIdPermit)
    }

    /// The filter's display name and description, so a `wf.msc` or audit
    /// reader sees what each filter is for.
    fn display(self) -> (&'static str, &'static str) {
        match self {
            Kind::AppIdPermit => ("broccoli permit xray", "permit the staged core's own dials"),
            Kind::NdpPermit(NDP_ROUTER_SOLICITATION) => (
                "broccoli permit router solicitation",
                "permit IPv6 router solicitation on a family the tunnel does not carry",
            ),
            Kind::NdpPermit(_) => (
                "broccoli permit neighbor discovery",
                "permit IPv6 neighbor discovery on a family the tunnel does not carry",
            ),
            Kind::UnsupportedFamilyBlock => (
                "broccoli block unsupported family",
                "block the address family the tunnel does not carry",
            ),
            Kind::TunInterfacePermit => (
                "broccoli permit tun",
                "permit traffic egressing the TUN interface",
            ),
            Kind::DnsBlock => ("broccoli block dns", "block direct DNS outside the tunnel"),
        }
    }
}

/// One filter the shield installs: the pure shape, so the ordering that
/// decides which traffic survives is testable without a WFP engine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FilterSpec {
    family: Family,
    kind: Kind,
}

/// The filters one install adds. `carries_ipv6` is whether the emitted TUN
/// config assigns an IPv6 gateway; the model requires an IPv4 gateway
/// whenever TUN mode is on, so IPv4 is always carried and only the IPv6
/// family can be un-carried. `tun_ifindex` is whether the adapter index is
/// known yet: the fail-closed first install runs without it and adds no
/// TUN-interface permits.
///
/// A carried family gets the core's app-id permit, the TUN-interface permit
/// (once the index is known) and the port-53 block. An un-carried family
/// gets the app-id permit, a catch-all block and its neighbor-discovery
/// permits — never the port-53 block, which the catch-all subsumes.
fn plan(carries_ipv6: bool, tun_ifindex: bool) -> Vec<FilterSpec> {
    let mut specs = Vec::new();
    for family in Family::BOTH {
        let carried = family == Family::V4 || carries_ipv6;
        specs.push(FilterSpec {
            family,
            kind: Kind::AppIdPermit,
        });
        if carried {
            if tun_ifindex {
                specs.push(FilterSpec {
                    family,
                    kind: Kind::TunInterfacePermit,
                });
            }
            specs.push(FilterSpec {
                family,
                kind: Kind::DnsBlock,
            });
        } else {
            specs.push(FilterSpec {
                family,
                kind: Kind::UnsupportedFamilyBlock,
            });
            specs.extend(NDP_TYPES.map(|icmp_type| FilterSpec {
                family,
                kind: Kind::NdpPermit(icmp_type),
            }));
        }
    }
    specs
}

/// One filter's materialized pieces, owned for the whole add loop: the
/// [`FWPM_FILTER0`] built from an entry borrows its display strings and its
/// condition array, so both must outlive the `FwpmFilterAdd0` that uses them.
struct FilterEntry {
    spec: FilterSpec,
    name: Vec<u16>,
    description: Vec<u16>,
    conditions: Vec<FWPM_FILTER_CONDITION0>,
}

/// The values an install's conditions point at. `app_id` is freed by the
/// caller after every add; `all_routers` is a local of the same call, so its
/// address is stable for the whole add loop.
struct ConditionValues {
    app_id: *mut FWP_BYTE_BLOB,
    tun_ifindex: u32,
    all_routers: FWP_BYTE_ARRAY16,
}

/// One equality condition on a WFP field.
fn condition(
    field_key: GUID,
    value_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

/// The conditions one filter matches, pointing at `values` (which must
/// outlive every add that uses the result).
fn conditions_for(spec: FilterSpec, values: &ConditionValues) -> Vec<FWPM_FILTER_CONDITION0> {
    match spec.kind {
        Kind::AppIdPermit => vec![condition(
            FWPM_CONDITION_ALE_APP_ID,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 {
                byteBlob: values.app_id,
            },
        )],
        Kind::TunInterfacePermit => vec![condition(
            // The index of the interface the connection is sent on. The Win32
            // name for this GUID is `FWPM_CONDITION_LOCAL_INTERFACE_INDEX`;
            // `fwpmu.h` aliases it to `FWPM_CONDITION_INTERFACE_INDEX`, the
            // name the windows crate exports.
            FWPM_CONDITION_INTERFACE_INDEX,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: values.tun_ifindex,
            },
        )],
        Kind::DnsBlock => vec![condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: DNS_PORT },
        )],
        Kind::UnsupportedFamilyBlock => Vec::new(),
        Kind::NdpPermit(icmp_type) => {
            let mut conditions = vec![
                condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 {
                        uint8: IPPROTO_ICMPV6,
                    },
                ),
                condition(
                    CONDITION_ICMPV6_TYPE,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: icmp_type },
                ),
                condition(
                    CONDITION_ICMPV6_CODE,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: 0 },
                ),
            ];
            if icmp_type == NDP_ROUTER_SOLICITATION {
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_BYTE_ARRAY16_TYPE,
                    FWP_CONDITION_VALUE0_0 {
                        byteArray16: &values.all_routers as *const _ as *mut _,
                    },
                ));
            }
            conditions
        }
    }
}

/// NUL-terminated UTF-16 copy of `value`. WFP objects reject null display
/// names (FWP_E_NULL_DISPLAY_NAME), so every sublayer and filter gets one.
fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Display data pointing into the `name`/`description` buffers; the buffers
/// must outlive every WFP call the display data is passed to.
fn display_data(name: &[u16], description: &[u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR::from_raw(name.as_ptr() as *mut u16),
        description: PWSTR::from_raw(description.as_ptr() as *mut u16),
    }
}

/// Human-readable name for a Fwpm* status, so the helper log shows the
/// failing condition instead of an opaque number. Codes from the official
/// WFP error table (FWP facility 0x32), plus the plain Win32 codes the
/// `Fwpm*` calls return directly for a denied caller.
fn wfp_status_name(status: u32) -> &'static str {
    match status {
        0 => "ERROR_SUCCESS",
        // The unelevated sublayer add: opening the engine can succeed, the
        // write is what the token denies.
        5 => "ERROR_ACCESS_DENIED",
        0x8007_0005 => "E_ACCESSDENIED",
        0x8032_0008 => "FWP_E_NOT_FOUND",
        0x8032_0009 => "FWP_E_ALREADY_EXISTS",
        0x8032_0023 => "FWP_E_NULL_DISPLAY_NAME",
        0x8032_0025 => "FWP_E_INVALID_WEIGHT",
        0x8032_0026 => "FWP_E_MATCH_TYPE_MISMATCH",
        0x8032_0027 => "FWP_E_TYPE_MISMATCH",
        0x8032_002a => "FWP_E_DUPLICATE_CONDITION",
        0x8032_002c => "FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER",
        0x8032_002d => "FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER",
        0x8032_0033 => "FWP_E_NEVER_MATCH",
        _ => "unknown",
    }
}

/// Open WFP engine handle owning a dynamic session. Dropping closes the
/// engine; the kernel removes the session's filters (crash-safe).
struct DnsShield {
    engine: HANDLE,
}

impl Drop for DnsShield {
    fn drop(&mut self) {
        // SAFETY: `engine` is either a valid handle returned by the
        // FwpmEngineOpen0 below or a zeroed handle; FwpmEngineClose0 is
        // thread-safe and failing on an invalid handle is an ignored error
        // status. The handle is exclusively owned by this DnsShield
        // (created only in `install`, moved under the SHIELD mutex), so no
        // other thread can use it while it is being closed.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

// SAFETY: the raw engine handle is only ever touched while holding the
// SHIELD mutex below (the `windows` crate leaves HANDLE !Send because it
// wraps `*mut c_void`). FwpmEngineClose0 is thread-safe, the handle is a
// process-local kernel object valid regardless of which thread closes it,
// and the dynamic session is cleaned up by the kernel at process exit even
// if the value is never dropped.
unsafe impl Send for DnsShield {}

/// Process-global shield; installed/removed by the elevated helper. Never
/// dropped on process exit — the dynamic session handles that.
static SHIELD: Mutex<Option<DnsShield>> = Mutex::new(None);

/// Whether the config runs a TUN inbound.
fn has_tun_inbound(config: &serde_json::Value) -> bool {
    config
        .get(keys::INBOUNDS)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                inbound
                    .get(keys::PROTOCOL)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|protocol| protocol == "tun")
            })
        })
}

/// Whether a config runs a TUN core with the DNS module on: the tun inbound
/// owns the adapter DNS, and the module (the top-level `dns` object) is what
/// answers it — the runtime adds the module's in-tun listener to the running
/// core (src/rt/dns_in.rs). Either half without the other has no tunnel DNS
/// to protect.
pub fn config_needs_dns_shield(config: &serde_json::Value) -> bool {
    has_tun_inbound(config) && config.get(keys::DNS).is_some()
}

/// Whether the emitted TUN config assigns an IPv6 gateway. Every gateway
/// entry becomes an adapter address and the in-tun IPv6 DNS listener exists
/// only for a carried family; the shield blocks the IPv6 family whole when
/// this is false, so IPv6 traffic cannot leave through the physical
/// adapters. A config with no TUN inbound, no `settings`, or a gateway list
/// without an IPv6 entry answers false.
pub fn config_carries_ipv6(config: &serde_json::Value) -> bool {
    config
        .get(keys::INBOUNDS)
        .and_then(serde_json::Value::as_array)
        .and_then(|inbounds| {
            inbounds.iter().find(|inbound| {
                inbound
                    .get(keys::PROTOCOL)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|protocol| protocol == "tun")
            })
        })
        .and_then(|inbound| inbound.get(keys::SETTINGS))
        .and_then(|settings| settings.get(keys::GATEWAY))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|gateways| {
            gateways
                .iter()
                .any(|gateway| gateway.as_str().is_some_and(|entry| entry.contains(':')))
        })
}

/// What a caller asks the shield to do. The install half carries everything
/// the filters need; removal needs nothing, so it cannot be asked to invent
/// values for parameters it never reads.
pub enum ShieldCommand<'a> {
    /// Install the shield, or reinstall it for the next phase: `tun_ifindex`
    /// is `None` for the fail-closed first install (the block half needs no
    /// adapter) and `Some` once the adapter exists (which adds the
    /// TUN-interface permits); `carries_ipv6` selects whether the IPv6 family
    /// is permitted with its DNS blocked, or blocked whole.
    Install {
        xray_exe: &'a Path,
        tun_ifindex: Option<u32>,
        carries_ipv6: bool,
    },
    /// Remove the installed shield, if any.
    Remove,
}

/// Apply one shield command.
pub fn set_dns_shield(command: ShieldCommand<'_>) -> Result<(), DiagError> {
    let mut guard = SHIELD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match command {
        ShieldCommand::Install {
            xray_exe,
            tun_ifindex,
            carries_ipv6,
        } => match DnsShield::install(xray_exe, tun_ifindex, carries_ipv6) {
            Ok(shield) => {
                *guard = Some(shield);
                Ok(())
            }
            Err(error) => {
                // A failed (re)install must not leave the previous shield in
                // place: every start stages xray.exe under a fresh uuid
                // directory, so the old shield's app-id permit names a dead
                // path and only its block filters survive to drop the new
                // core's direct port-53 dials. Best-effort means a shield
                // failure degrades to no shield (leak tolerated), never to a
                // broken core.
                *guard = None;
                Err(error)
            }
        },
        ShieldCommand::Remove => {
            *guard = None;
            Ok(())
        }
    }
}

/// Resolve a network adapter's interface index by its friendly name via
/// GetAdaptersAddresses (iphlpapi). The elevated helper uses this to find
/// the TUN adapter the staged core created, so the shield can permit DNS
/// egressing that interface. Returns None when the name is absent or the
/// enumeration fails.
pub fn interface_index_by_name(name: &str) -> Option<u32> {
    // Family 0 = AF_UNSPEC: enumerate both address families.
    let mut size = 0u32;
    // SAFETY: the first call passes a null buffer and asks for the required
    // size; the returned `size` bounds the buffer allocated below.
    unsafe {
        GetAdaptersAddresses(0, Default::default(), None, None, &mut size);
    }
    if size == 0 {
        return None;
    }
    // Aligned heap buffer, not `Vec<u8>`: the adapter structs contain 8-byte
    // fields, and dereferencing them through an align-1 allocation would be
    // UB by contract, working only via allocator over-alignment (netif.rs's
    // doctrine, shared here). `AdapterBuffer` allocates with an explicit
    // `Layout` of `align_of::<IP_ADAPTER_ADDRESSES_LH>()`, zeroes it, and
    // deallocs with the same layout on drop — exactly once on every path.
    let buffer = AdapterBuffer::allocate(size as usize)?;
    let head = buffer.head();
    // SAFETY: `head` points at a live, zeroed allocation of exactly the size
    // the sizing call reported, aligned to at least
    // `align_of::<IP_ADAPTER_ADDRESSES_LH>()` by its layout; the kernel
    // writes the adapter chain into that allocation, bounded by the reported
    // size, and `buffer` stays alive for the whole call.
    let status =
        unsafe { GetAdaptersAddresses(0, Default::default(), None, Some(head), &mut size) };
    if status != 0 {
        return None;
    }
    // SAFETY: on success the kernel leaves a linked list of valid
    // IP_ADAPTER_ADDRESSES_LH structs inside the live, aligned `buffer`;
    // each `Next` pointer is either null or points into the same buffer,
    // which is only freed after the loop (at `buffer`'s drop).
    let mut current = head;
    while !current.is_null() {
        // SAFETY: `current` points at a valid struct written by the kernel
        // inside the aligned `buffer` allocation, which outlives this read.
        let friendly = unsafe { (*current).FriendlyName };
        if !friendly.is_null() {
            // SAFETY: `friendly` points at a NUL-terminated wide string
            // written by the kernel; reading until NUL stays in bounds.
            let candidate = unsafe { friendly.to_string() }.ok()?;
            if candidate == name {
                // SAFETY: `current` is the same valid struct as above;
                // `IfIndex` is a plain u32 field of its union.
                return Some(unsafe { (*current).Anonymous1.Anonymous.IfIndex });
            }
        }
        // SAFETY: `Next` is null or points into the same kernel-written
        // chain inside `buffer`; advancing stays within it.
        current = unsafe { (*current).Next };
    }
    None
}

impl DnsShield {
    /// Install the shield for one phase: `tun_ifindex` is `None` for the
    /// fail-closed first install (the block half needs no adapter), `Some`
    /// once the adapter exists (which adds the TUN-interface permits).
    fn install(
        xray_exe: &Path,
        tun_ifindex: Option<u32>,
        carries_ipv6: bool,
    ) -> Result<Self, DiagError> {
        // Step 1 — dynamic session + engine: the session's filters disappear
        // with the engine handle, so a crash or normal exit cleans up.
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = HANDLE::default();
        // SAFETY: `session` is a fully-initialized FWPM_SESSION0 with a
        // stack-local address valid for the call; `engine` is a valid
        // out-pointer the callee writes; `servername`/`authidentity` are
        // None (local engine, default credentials). The returned handle is
        // only used while this DnsShield owns it.
        let status = unsafe {
            FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                Some(&session),
                &mut engine,
            )
        };
        if status != 0 {
            return Err(DiagError::new(
                Diag::new(Key::WfpEngineOpenFailed)
                    .arg(status)
                    .arg(wfp_status_name(status)),
            ));
        }
        let shield = Self { engine };

        // Step 2 — sublayer, pinned at the very top of the weight range so
        // nothing else can outrank our filters. The display name is
        // mandatory (FWP_E_NULL_DISPLAY_NAME otherwise).
        let sublayer_name = wide_str("broccoli");
        let sublayer_desc = wide_str("Broccoli DNS shield sublayer");
        let sublayer_key = sublayer_key();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            displayData: display_data(&sublayer_name, &sublayer_desc),
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: `sublayer` is a fully-initialized FWPM_SUBLAYER0 whose
        // pointer fields are null (Default) except displayData, which points
        // into the `sublayer_name`/`sublayer_desc` buffers alive for the
        // call; the kernel copies the struct during the call, and `engine`
        // is the valid handle from above.
        let status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };
        if status != 0 {
            return Err(DiagError::new(
                Diag::new(Key::WfpSubLayerAddFailed)
                    .arg(status)
                    .arg(wfp_status_name(status)),
            ));
        }

        // Step 3 — app id of the staged xray.exe (wide path). Freed below
        // after all filter adds, on success and failure alike.
        let wide: Vec<u16> = xray_exe
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path valid for the
        // call; `app_id` is a valid out-pointer the callee writes on
        // success and is freed exactly once below via FwpmFreeMemory0.
        let status =
            unsafe { FwpmGetAppIdFromFileName0(PCWSTR::from_raw(wide.as_ptr()), &mut app_id) };
        if status != 0 {
            return Err(DiagError::new(
                Diag::new(Key::WfpAppIdReadFailed)
                    .arg(status)
                    .arg(wfp_status_name(status)),
            ));
        }

        // Step 4 — the filter plan. Every value a condition points at lives
        // here and outlives the whole add loop (the kernel copies the values
        // during each FwpmFilterAdd0).
        let values = ConditionValues {
            app_id,
            // Only a `Some` index reaches a TUN-interface permit, so the
            // sentinel below is never read.
            tun_ifindex: tun_ifindex.unwrap_or(0),
            all_routers: FWP_BYTE_ARRAY16 {
                byteArray16: ALL_ROUTERS_V6,
            },
        };
        // Every filter carries a display name (FWP_E_NULL_DISPLAY_NAME
        // otherwise); these buffers stay alive through the add loop below.
        let mut entries: Vec<FilterEntry> = Vec::new();
        for spec in plan(carries_ipv6, tun_ifindex.is_some()) {
            let (name, description) = spec.kind.display();
            entries.push(FilterEntry {
                spec,
                name: wide_str(&format!("{} {}", name, spec.family.suffix())),
                description: wide_str(description),
                conditions: conditions_for(spec, &values),
            });
        }

        let result = (|| -> Result<(), DiagError> {
            for entry in &mut entries {
                let conditions = entry.conditions.as_mut_ptr();
                let filter = FWPM_FILTER0 {
                    layerKey: entry.spec.family.layer(),
                    subLayerKey: sublayer_key,
                    displayData: display_data(&entry.name, &entry.description),
                    flags: if entry.spec.kind.clear_action_right() {
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
                    } else {
                        FWPM_FILTER_FLAGS::default()
                    },
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 {
                            uint8: entry.spec.kind.weight(),
                        },
                    },
                    numFilterConditions: entry.conditions.len() as u32,
                    filterCondition: conditions,
                    action: FWPM_ACTION0 {
                        r#type: entry.spec.kind.action(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut id: u64 = 0;
                // SAFETY: `filter` borrows this entry's display strings and
                // condition array, which live in `entries` for the whole
                // loop; every pointer inside those conditions points at
                // `values`, a live local of this call. `id` is a valid
                // out-pointer and `engine` the valid handle from above.
                let status = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut id)) };
                if status != 0 {
                    return Err(DiagError::new(
                        Diag::new(Key::WfpFilterAddFailed)
                            .arg(status)
                            .arg(wfp_status_name(status)),
                    ));
                }
            }
            Ok(())
        })();
        // Step 5 — free the app id after ALL adds, on success and failure.
        // SAFETY: `app_id` was returned by FwpmGetAppIdFromFileName0 and is
        // freed exactly once at this single call site (on both the success
        // and failure paths of the adds above).
        unsafe {
            FwpmFreeMemory0(&mut app_id as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void)
        };
        result?;

        Ok(shield)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::inbound::DNS_INBOUND_TAG;
    use serde_json::json;

    /// A full install on a dual-stack tunnel: each carried family gets the
    /// app-id permit, the TUN-interface permit and the port-53 block, and
    /// nothing else — no family block, no neighbor-discovery permits.
    #[test]
    fn a_carried_family_gets_the_dns_pair_and_no_family_block() {
        let specs = plan(true, true);
        assert_eq!(specs.len(), 6, "{specs:#?}");
        for family in Family::BOTH {
            for kind in [Kind::AppIdPermit, Kind::TunInterfacePermit, Kind::DnsBlock] {
                assert!(
                    specs.contains(&FilterSpec { family, kind }),
                    "{family:?} must carry {kind:?}: {specs:#?}"
                );
            }
        }
        assert!(
            specs.iter().all(|spec| !matches!(
                spec.kind,
                Kind::UnsupportedFamilyBlock | Kind::NdpPermit(_)
            ))
        );
    }

    /// An IPv6 family the tunnel does not carry is blocked whole, with only
    /// the core's own dials and neighbor discovery above the block. IPv4 is
    /// unaffected: the model requires an IPv4 gateway.
    #[test]
    fn an_un_carried_family_is_blocked_whole() {
        let specs = plan(false, true);
        let v6: Vec<Kind> = specs
            .iter()
            .filter(|spec| spec.family == Family::V6)
            .map(|spec| spec.kind)
            .collect();
        assert!(v6.contains(&Kind::AppIdPermit), "{v6:#?}");
        assert!(v6.contains(&Kind::UnsupportedFamilyBlock), "{v6:#?}");
        for icmp_type in NDP_TYPES {
            assert!(v6.contains(&Kind::NdpPermit(icmp_type)), "{v6:#?}");
        }
        assert!(
            !v6.contains(&Kind::DnsBlock),
            "the family block subsumes the port-53 block: {v6:#?}"
        );
        assert!(!v6.contains(&Kind::TunInterfacePermit), "{v6:#?}");

        // The IPv4 half is untouched: a carried family still gets its pair.
        assert!(specs.contains(&FilterSpec {
            family: Family::V4,
            kind: Kind::DnsBlock
        }));
        assert!(specs.contains(&FilterSpec {
            family: Family::V4,
            kind: Kind::TunInterfacePermit
        }));
    }

    /// The fail-closed first install runs before the adapter exists, so it
    /// must produce the block half and no TUN-interface permits.
    #[test]
    fn the_fail_closed_install_omits_the_tun_permits() {
        let specs = plan(true, false);
        assert!(
            specs
                .iter()
                .all(|spec| spec.kind != Kind::TunInterfacePermit),
            "{specs:#?}"
        );
        // The block half is whole: both families keep their app-id permit
        // and their port-53 block.
        for family in Family::BOTH {
            assert!(specs.contains(&FilterSpec {
                family,
                kind: Kind::AppIdPermit
            }));
            assert!(specs.contains(&FilterSpec {
                family,
                kind: Kind::DnsBlock
            }));
        }
    }

    /// The weight order is the behavior: the core's dials outrank every
    /// block, neighbor discovery outranks the family block, and the
    /// TUN-interface permit outranks the port-53 block. A weight swap here
    /// would kill the resolver or the core's own transport.
    #[test]
    fn permit_weights_outrank_the_blocks_they_must_survive() {
        assert!(Kind::AppIdPermit.weight() > Kind::UnsupportedFamilyBlock.weight());
        assert!(Kind::AppIdPermit.weight() > Kind::DnsBlock.weight());
        assert!(Kind::AppIdPermit.weight() > Kind::TunInterfacePermit.weight());
        assert!(
            Kind::NdpPermit(NDP_ROUTER_SOLICITATION).weight()
                > Kind::UnsupportedFamilyBlock.weight()
        );
        assert!(
            Kind::UnsupportedFamilyBlock.weight() > Kind::TunInterfacePermit.weight(),
            "the family block must refuse traffic that does not egress the TUN"
        );
        assert!(
            Kind::TunInterfacePermit.weight() > Kind::DnsBlock.weight(),
            "a port-53 query egressing the TUN must survive the port-53 block"
        );
    }

    /// The family question reads the emitted gateway list: an IPv6 entry
    /// anywhere in it means carried; a v4-only list, a missing settings
    /// block and a config without a tunnel all mean not carried.
    #[test]
    fn carries_ipv6_follows_the_emitted_gateway_list() {
        assert!(config_carries_ipv6(&json!({
            "inbounds": [{"protocol": "tun", "settings": {
                "gateway": ["10.255.0.1/30", "fd00::1/64"]
            }}]
        })));
        assert!(!config_carries_ipv6(&json!({
            "inbounds": [{"protocol": "tun", "settings": {
                "gateway": ["10.255.0.1/30"]
            }}]
        })));
        assert!(!config_carries_ipv6(&json!({
            "inbounds": [{"protocol": "tun"}]
        })));
        assert!(!config_carries_ipv6(&json!({
            "inbounds": [{"protocol": "socks", "settings": {
                "gateway": ["fd00::1/64"]
            }}]
        })));
        // `settings` must be an object: a non-object read answers "not
        // carried", which fails closed toward the family block.
        assert!(!config_carries_ipv6(&json!({
            "inbounds": [{"protocol": "tun", "settings": "gateway"}]
        })));
    }

    #[test]
    fn shield_needed_for_tun_with_dns_module() {
        // tun inbound + top-level dns module -> true
        let config = json!({
            "inbounds": [
                {"protocol": "tun", "tag": "tun-in"},
                {"protocol": "dokodemo-door", "tag": DNS_INBOUND_TAG}
            ],
            "dns": {"servers": ["1.1.1.1"]}
        });
        assert!(config_needs_dns_shield(&config));
    }

    #[test]
    fn shield_not_needed_for_tun_without_dns_module() {
        // tun only, no module -> false
        let config = json!({
            "inbounds": [
                {"protocol": "tun", "tag": "tun-in"},
                {"protocol": "http", "tag": "http-in"}
            ]
        });
        assert!(!config_needs_dns_shield(&config));
    }

    #[test]
    fn shield_not_needed_without_tun() {
        // module only, no tun inbound -> false
        let config = json!({
            "inbounds": [
                {"protocol": "dokodemo-door", "tag": DNS_INBOUND_TAG}
            ],
            "dns": {"servers": ["1.1.1.1"]}
        });
        assert!(!config_needs_dns_shield(&config));
    }

    #[test]
    fn shield_not_needed_without_inbounds() {
        // {"inbounds": []} and {"routing": {}} -> false
        assert!(!config_needs_dns_shield(&json!({"inbounds": []})));
        assert!(!config_needs_dns_shield(&json!({"routing": {}})));
    }

    #[test]
    fn remove_is_idempotent_unprivileged() {
        // Real WFP install needs elevation; the removal path is testable
        // anywhere.
        set_dns_shield(ShieldCommand::Remove).unwrap();
        set_dns_shield(ShieldCommand::Remove).unwrap();
    }

    /// Ground-truth check of the installed shield: with the shield active
    /// and no TUN interface permit in play (ifindex 0 matches nothing),
    /// every port-53 query must be blocked — loopback included, because the
    /// only permitted DNS paths are the xray app-id and the TUN interface.
    /// Requires an elevated token to open the WFP engine; run with
    /// `cargo test --lib rt::wfp -- --ignored --nocapture` in an elevated
    /// terminal, with BROCCOLI_PROBE_LAN_IP set to this machine's LAN address.
    #[test]
    #[ignore = "requires an elevated Windows token to open the WFP engine"]
    fn empirical_port53_is_blocked_outside_the_tun() {
        use std::net::UdpSocket;
        use std::time::Duration;

        // The probe target is per-machine, so it is never baked in: the
        // listener below binds it, and a stale default would silently probe
        // the wrong address.
        let lan_ip = std::env::var("BROCCOLI_PROBE_LAN_IP")
            .expect("set BROCCOLI_PROBE_LAN_IP to this machine's LAN address before the probe");
        let core = std::env::var("BROCCOLI_PROBE_XRAY")
            .unwrap_or_else(|_| std::env::var("APPDATA").unwrap() + r"\broccoli\core\xray.exe");
        let xray = std::path::Path::new(&core);
        assert!(xray.exists(), "probe xray.exe missing at {core}");

        // ifindex 0: the TUN-interface permit matches nothing, so only the
        // xray app-id permit (this test process is not xray) could pass.
        set_dns_shield(ShieldCommand::Install {
            xray_exe: xray,
            tun_ifindex: Some(0),
            carries_ipv6: true,
        })
        .expect("install shield (requires elevation)");
        // The shield is dynamic-session: it disappears when this process's
        // engine handle closes, i.e. on process exit even without the call.
        // Remove it explicitly so later probes in this run are unaffected.
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = set_dns_shield(ShieldCommand::Remove);
            }
        }
        let _guard = Guard;

        // Loopback listener: a query to 127.0.0.1:53 must NOT arrive (the
        // shield has no loopback exemption).
        let loopback_listener = UdpSocket::bind("127.0.0.1:53").expect("bind 127.0.0.1:53");
        loopback_listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set loopback timeout");
        let sender = UdpSocket::bind("0.0.0.0:0").expect("bind sender");
        sender
            .send_to(b"probe", "127.0.0.1:53")
            .expect("send loopback probe");
        let mut buf = [0u8; 64];
        assert!(
            loopback_listener.recv(&mut buf).is_err(),
            "loopback 127.0.0.1:53 query must be blocked when not egressing the TUN"
        );

        // Non-loopback local listener: a query to the machine's LAN address
        // must NOT arrive either (block filter catches it at ALE_AUTH_CONNECT).
        // Bound to the specific LAN address: 0.0.0.0:53 would collide with
        // the still-held 127.0.0.1:53 listener above.
        let lan_listener = UdpSocket::bind(format!("{lan_ip}:53")).expect("bind lan :53");
        lan_listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set lan timeout");
        let lan_target = format!("{lan_ip}:53");
        sender
            .send_to(b"probe", &lan_target)
            .expect("send lan probe");
        let mut buf = [0u8; 64];
        assert!(
            lan_listener.recv(&mut buf).is_err(),
            "non-loopback {lan_target} query must be blocked by the shield"
        );
    }
}

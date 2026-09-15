//! WFP DNS shield (best-effort): while a TUN core with a DNS module runs,
//! block direct outbound connections to remote port 53 unless they egress
//! the TUN interface (the in-tun DNS listener at the gateway address) or
//! originate from the xray process itself (its own upstream dials). This
//! kills the physical-adapter on-link gateway DNS vector that never enters
//! the TUN (Windows multi-homed resolution would otherwise leak queries
//! outside the tunnel). The filter shape mirrors sing-tun's StrictRoute
//! DNSModeHijack (tun_windows.go): app-id permit (12) > tun-interface
//! permit (11) > port-53 block (10) — no address exemptions, so the
//! resolver's DNS path works exactly when it routes into the tunnel and
//! nothing else. Filters live in a dynamic WFP session
//! (`FWPM_SESSION_FLAG_DYNAMIC`) so the kernel removes them when the helper
//! process exits (crash-safe). Best-effort: the caller logs failures, never
//! fatal.

use crate::diag::{Diag, DiagError};
use crate::i18n::Key;
use crate::sys::netif::AdapterBuffer;
use std::path::Path;
use std::sync::Mutex;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_INTERFACE_INDEX,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows::core::{GUID, PCWSTR, PWSTR};

/// Broccoli-owned WFP sublayer (fixed GUID; filters live here, not in the
/// default sublayer, so nothing else can be confused by them).
const SUBLAYER_KEY: GUID = GUID::from_u128(0xb90f44c1_6b2d_4e7a_8c93_5a1d2e3f4a5b);
const DNS_PORT: u16 = 53;
/// Permit weight for xray's own dials (any interface) — above the block.
const WEIGHT_PERMIT: u8 = 12;
/// Permit weight for traffic egressing the TUN interface (the in-tun DNS
/// listener) — between the xray permit and the block, mirroring sing-tun.
const WEIGHT_TUN_INTERFACE: u8 = 11;
const WEIGHT_BLOCK_DNS: u8 = 10;

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
/// WFP error table (FWP facility 0x32).
fn wfp_status_name(status: u32) -> &'static str {
    match status {
        0 => "ERROR_SUCCESS",
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

/// Whether a config runs a TUN core with the DNS module on: the tun inbound
/// owns the adapter DNS, and the module (the top-level `dns` object) is what
/// answers it — the runtime adds the module's in-tun listener to the running
/// core (src/rt/dns_in.rs). Either half without the other has no tunnel DNS
/// to protect.
pub fn config_needs_dns_shield(config: &serde_json::Value) -> bool {
    let Some(inbounds) = config.get("inbounds").and_then(serde_json::Value::as_array) else {
        return false;
    };
    let has_tun = inbounds.iter().any(|inbound| {
        inbound
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|protocol| protocol == "tun")
    });
    has_tun && config.get("dns").is_some()
}

pub fn set_dns_shield(
    enabled: bool,
    xray_exe: Option<&Path>,
    tun_ifindex: Option<u32>,
) -> Result<(), DiagError> {
    let mut guard = SHIELD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if enabled {
        let exe = xray_exe.ok_or_else(|| DiagError::new(Diag::new(Key::WfpMissingXrayPath)))?;
        let ifindex =
            tun_ifindex.ok_or_else(|| DiagError::new(Diag::new(Key::WfpMissingTunIfindex)))?;
        match DnsShield::install(exe, ifindex) {
            Ok(shield) => *guard = Some(shield),
            Err(error) => {
                // A failed (re)install must not leave the previous shield in
                // place: every start stages xray.exe under a fresh uuid
                // directory, so the old shield's app-id permit names a dead
                // path and only its block filters survive to drop the new
                // core's direct port-53 dials. Best-effort means a shield
                // failure degrades to no shield (leak tolerated), never to a
                // broken core.
                *guard = None;
                return Err(error);
            }
        }
    } else {
        *guard = None;
    }
    Ok(())
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
    fn install(xray_exe: &Path, tun_ifindex: u32) -> Result<Self, DiagError> {
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
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
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

        // Step 4 — four filters as locals that stay alive for the whole add
        // loop (the kernel copies the values during each FwpmFilterAdd0).
        // Permit conditions: hard permits (CLEAR_ACTION_RIGHT) for xray's own
        // dials on both address families.
        let app_id_condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        };
        // Block conditions: remote port 53. No address exemptions — the
        // permitted paths are exactly the xray app-id and the TUN interface
        // permits above; everything else on 53 is the leak vector
        // (physical-adapter on-link gateway DNS) and is blocked.
        let port_condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: DNS_PORT },
            },
        };
        // Traffic egressing the TUN interface (the in-tun DNS listener at
        // the gateway address) is permitted: the resolver's queries to the
        // adapter DNS route on-link into the TUN and must not match the
        // block. This is the interface-index permit from sing-tun's
        // StrictRoute DNSModeHijack — no address exemptions needed.
        let tun_interface_condition = FWPM_FILTER_CONDITION0 {
            // FWPM_CONDITION_INTERFACE_INDEX: the index of the interface
            // the connection is sent on (the crate's name for the GUID
            // sing-box binds as LOCAL_INTERFACE_INDEX).
            fieldKey: FWPM_CONDITION_INTERFACE_INDEX,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: tun_ifindex,
                },
            },
        };

        let mut permit_conditions_v4 = [app_id_condition];
        let mut permit_conditions_v6 = [app_id_condition];
        let mut tun_conditions_v4 = [tun_interface_condition];
        let mut tun_conditions_v6 = [tun_interface_condition];
        let mut block_conditions_v4 = [port_condition];
        let mut block_conditions_v6 = [port_condition];

        // Every filter carries a display name (FWP_E_NULL_DISPLAY_NAME
        // otherwise); the buffers stay alive through the add loop below.
        let permit_v4_name = wide_str("broccoli permit xray ipv4");
        let permit_v4_desc = wide_str("permit staged xray.exe dials (IPv4)");
        let permit_v6_name = wide_str("broccoli permit xray ipv6");
        let permit_v6_desc = wide_str("permit staged xray.exe dials (IPv6)");
        let tun_v4_name = wide_str("broccoli permit tun ipv4");
        let tun_v4_desc = wide_str("permit DNS egressing the TUN interface (IPv4)");
        let tun_v6_name = wide_str("broccoli permit tun ipv6");
        let tun_v6_desc = wide_str("permit DNS egressing the TUN interface (IPv6)");
        let block_v4_name = wide_str("broccoli block dns ipv4");
        let block_v4_desc = wide_str("block direct DNS outside the tunnel (IPv4)");
        let block_v6_name = wide_str("broccoli block dns ipv6");
        let block_v6_desc = wide_str("block direct DNS outside the tunnel (IPv6)");

        let permit_v4 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&permit_v4_name, &permit_v4_desc),
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_PERMIT,
                },
            },
            numFilterConditions: permit_conditions_v4.len() as u32,
            filterCondition: permit_conditions_v4.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let permit_v6 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&permit_v6_name, &permit_v6_desc),
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_PERMIT,
                },
            },
            numFilterConditions: permit_conditions_v6.len() as u32,
            filterCondition: permit_conditions_v6.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        // The TUN-interface permits: DNS egressing the TUN is the in-tun
        // listener path and must win over the port-53 block (11 > 10).
        let tun_v4 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&tun_v4_name, &tun_v4_desc),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_TUN_INTERFACE,
                },
            },
            numFilterConditions: tun_conditions_v4.len() as u32,
            filterCondition: tun_conditions_v4.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let tun_v6 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&tun_v6_name, &tun_v6_desc),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_TUN_INTERFACE,
                },
            },
            numFilterConditions: tun_conditions_v6.len() as u32,
            filterCondition: tun_conditions_v6.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let block_v4 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&block_v4_name, &block_v4_desc),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_BLOCK_DNS,
                },
            },
            numFilterConditions: block_conditions_v4.len() as u32,
            filterCondition: block_conditions_v4.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            ..Default::default()
        };
        let block_v6 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&block_v6_name, &block_v6_desc),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: WEIGHT_BLOCK_DNS,
                },
            },
            numFilterConditions: block_conditions_v6.len() as u32,
            filterCondition: block_conditions_v6.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            ..Default::default()
        };

        // Add permit xray v4/v6, permit tun v4/v6, block v4/v6.
        let result = (|| -> Result<(), DiagError> {
            for filter in [
                &permit_v4, &permit_v6, &tun_v4, &tun_v6, &block_v4, &block_v6,
            ] {
                let mut id: u64 = 0;
                // SAFETY: `filter` and its condition arrays are live locals
                // of this install for the whole call (the kernel copies the
                // values); `id` is a valid out-pointer; `engine` is the
                // valid handle from above.
                let status = unsafe { FwpmFilterAdd0(engine, filter, None, Some(&mut id)) };
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
    use crate::i18n::{Key, t};
    use crate::model::inbound::DNS_INBOUND_TAG;
    use crate::model::settings::Language;
    use serde_json::json;

    /// The converted shield guards render their keyed sentence before any
    /// WFP call, so the check needs no elevation.
    #[test]
    fn missing_shield_inputs_render_their_keys() {
        let missing_xray =
            set_dns_shield(true, None, None).expect_err("a shield without an exe must fail");
        assert_eq!(missing_xray.diag().key(), Key::WfpMissingXrayPath);
        assert_eq!(
            missing_xray.text(Language::En),
            t(Language::En, Key::WfpMissingXrayPath)
        );

        let xray = std::path::Path::new("xray.exe");
        let missing_index = set_dns_shield(true, Some(xray), None)
            .expect_err("a shield without an interface index must fail");
        assert_eq!(missing_index.diag().key(), Key::WfpMissingTunIfindex);
        assert_eq!(
            missing_index.text(Language::En),
            t(Language::En, Key::WfpMissingTunIfindex)
        );
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
    fn disable_is_idempotent_unprivileged() {
        // Real WFP install needs elevation; the off path is testable anywhere.
        set_dns_shield(false, None, None).unwrap();
        set_dns_shield(false, None, None).unwrap();
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
        set_dns_shield(true, Some(xray), Some(0)).expect("install shield (requires elevation)");
        // The shield is dynamic-session: it disappears when this process's
        // engine handle closes, i.e. on process exit even without the call.
        // Remove it explicitly so later probes in this run are unaffected.
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = set_dns_shield(false, None, None);
            }
        }
        let _guard = Guard;

        // Loopback listener: a query to 127.0.0.1:53 must NOT arrive (no
        // loopback exemption under the sing-box-shaped shield).
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

//! Windows Filtering Platform guard for the TUN core's control plane.
//!
//! The control plane is a loopback gRPC listener with no credentials. The
//! elevated helper runs the TUN core, so a local process that reaches that
//! port would drive an administrator process. This guard installs two filters
//! at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, in a sublayer of its own:
//!
//! - a hard permit for the broccoli image to `127.0.0.1:<port>`;
//! - a block for every other image to the same address and port.
//!
//! The engine is opened in a dynamic session and the filters are added in one
//! transaction, the shape Xray's own TUN filters use. Closing the engine (the
//! guard's `Drop`, or the helper process ending) removes the session and its
//! filters, so a crash cannot leave the guard behind.
//!
//! Only `TUN` sessions get this guard: the direct-mode core runs unelevated
//! in the GUI, where this process cannot open a WFP engine.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;
use std::ptr;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_MATCH_EQUAL, FWP_UINT8,
    FWP_UINT16, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_FILTER_FLAGS, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::diag::{Diag, DiagError};
use crate::i18n::Key;

/// The sublayer weight: the same top-of-sublayer value Xray's TUN filters use,
/// so this guard's verdicts are read before ordinary firewall filters.
const SUBLAYER_WEIGHT: u16 = 0xFFFF;
/// The permit's weight inside the sublayer. It only has to beat the block.
const PERMIT_WEIGHT: u8 = 1;
/// The block's weight inside the sublayer.
const BLOCK_WEIGHT: u8 = 0;

/// An installed control-plane guard.
///
/// Dropping it closes the WFP engine. The session is dynamic, so the filters
/// disappear with it. The helper process ending closes the handle too, which
/// is the crash path.
pub(crate) struct ApiGuard {
    engine: HANDLE,
}

// SAFETY: the wrapped `HANDLE` is an opaque kernel-object reference with value
// semantics. No process memory is dereferenced through it, and the Win32 calls
// used on it carry no thread affinity; `Drop` closes it exactly once on
// whatever thread drops the value, so no second owner holds the same handle.
unsafe impl Send for ApiGuard {}

impl ApiGuard {
    /// Permit only this executable's image to connect to `127.0.0.1:port`,
    /// and block every other image.
    ///
    /// The caller must be elevated: opening a WFP engine for filter
    /// management requires administrator rights. A failure is returned, never
    /// ignored, so the caller can refuse to start a core that would be
    /// reachable without the guard.
    pub(crate) fn new(port: u16) -> Result<Self, DiagError> {
        let exe = std::env::current_exe().map_err(|error| {
            DiagError::new(Diag::new(Key::HelperApiGuardInstallFailed).arg(port)).caused_by(
                DiagError::new(Diag::new(Key::WfpCallFailed).arg(error.to_string())),
            )
        })?;
        Self::install(port, &exe)
    }

    fn install(port: u16, exe: &std::path::Path) -> Result<Self, DiagError> {
        let install_error = |call: &str, code: u32| {
            DiagError::new(Diag::new(Key::HelperApiGuardInstallFailed).arg(port)).caused_by(
                DiagError::new(Diag::new(Key::WfpCallFailed).arg(format!("{call} ({code})"))),
            )
        };

        let mut session_name = wide("broccoli control plane");
        let session = FWPM_SESSION0 {
            displayData: display(&mut session_name),
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let mut engine = HANDLE::default();
        // SAFETY: `session` is a fully initialized `FWPM_SESSION0` that
        // outlives the call, `engine` is a valid out-parameter, and the
        // server name is absent (local engine). The result is checked before
        // the handle is used, and ownership of a successful handle moves into
        // `ApiGuard`, whose `Drop` closes it exactly once.
        let code = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut engine,
            )
        };
        if code != 0 {
            return Err(install_error("FwpmEngineOpen0", code));
        }

        // From here every failure aborts the transaction and closes the
        // engine, so a half-installed guard cannot survive.
        let mut transaction = false;
        let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let result = (|| -> Result<(), DiagError> {
            // SAFETY: `engine` is the live handle returned above; the flags
            // value is a documented flags word.
            let code = unsafe { FwpmTransactionBegin0(engine, 0) };
            if code != 0 {
                return Err(install_error("FwpmTransactionBegin0", code));
            }
            transaction = true;

            let mut sublayer_name = wide("broccoli control plane");
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: GUID::from_u128(uuid::Uuid::new_v4().as_u128()),
                displayData: display(&mut sublayer_name),
                weight: SUBLAYER_WEIGHT,
                ..Default::default()
            };
            // SAFETY: `engine` is live, `sublayer` is fully initialized and
            // outlives the call, and a null security descriptor asks for the
            // default.
            let code = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };
            if code != 0 {
                return Err(install_error("FwpmSubLayerAdd0", code));
            }

            let exe_w = wide_os(exe.as_os_str());
            // SAFETY: `exe_w` is a NUL-terminated absolute UTF-16 path that
            // outlives the call, and `app_id` is a valid out-parameter. WFP
            // allocates the returned blob; it is freed below through
            // `FwpmFreeMemory0`.
            let code = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(exe_w.as_ptr()), &mut app_id) };
            if code != 0 {
                return Err(install_error("FwpmGetAppIdFromFileName0", code));
            }

            // 127.0.0.1 in the byte order WFP reads for FWP_V4_ADDR_MASK.
            let mut loopback = FWP_V4_ADDR_AND_MASK {
                addr: u32::from_ne_bytes([127, 0, 0, 1]),
                mask: u32::MAX,
            };
            let port_value = port;

            // The permit is hard (`CLEAR_ACTION_RIGHT`): a lower sublayer's
            // block, Windows Firewall's included, must not override the app's
            // own connection to its control plane. The block needs no flag.
            let permit_conditions = vec![
                condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_V4_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: ptr::addr_of_mut!(loopback),
                    },
                ),
                condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: port_value },
                ),
                condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_BYTE_BLOB_TYPE,
                    FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                ),
            ];
            add_filter(
                engine,
                &sublayer.subLayerKey,
                "broccoli control plane: permit the app",
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                FWP_ACTION_PERMIT,
                PERMIT_WEIGHT,
                permit_conditions,
            )
            .map_err(|code| install_error("FwpmFilterAdd0 (permit)", code))?;

            let block_conditions = vec![
                condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_V4_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: ptr::addr_of_mut!(loopback),
                    },
                ),
                condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: port_value },
                ),
            ];
            add_filter(
                engine,
                &sublayer.subLayerKey,
                "broccoli control plane: block other apps",
                FWPM_FILTER_FLAGS(0),
                FWP_ACTION_BLOCK,
                BLOCK_WEIGHT,
                block_conditions,
            )
            .map_err(|code| install_error("FwpmFilterAdd0 (block)", code))?;

            // SAFETY: the engine is live and the transaction was begun above.
            let code = unsafe { FwpmTransactionCommit0(engine) };
            if code != 0 {
                return Err(install_error("FwpmTransactionCommit0", code));
            }
            transaction = false;
            Ok(())
        })();

        if !app_id.is_null() {
            // SAFETY: `app_id` is the allocation from
            // `FwpmGetAppIdFromFileName0`, freed exactly once here.
            unsafe {
                FwpmFreeMemory0(ptr::addr_of_mut!(app_id).cast());
            }
        }
        if let Err(error) = result {
            if transaction {
                // SAFETY: the engine is live and a transaction is open.
                unsafe {
                    let _ = FwpmTransactionAbort0(engine);
                }
            }
            // SAFETY: the engine handle is live and not closed yet.
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            return Err(error);
        }
        Ok(Self { engine })
    }
}

impl Drop for ApiGuard {
    fn drop(&mut self) {
        // SAFETY: `self.engine` is the handle from `FwpmEngineOpen0`, owned
        // exclusively by this guard; `Drop` runs once. The session is
        // dynamic, so its sublayer and filters are removed here.
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

/// One WFP filter condition with the given match value.
fn condition(
    field: GUID,
    value_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

/// Add one filter to the sublayer. Returns the WFP status code.
fn add_filter(
    engine: HANDLE,
    sublayer: &GUID,
    name: &str,
    flags: FWPM_FILTER_FLAGS,
    action: FWP_ACTION_TYPE,
    weight: u8,
    mut conditions: Vec<FWPM_FILTER_CONDITION0>,
) -> Result<(), u32> {
    let mut name_w = wide(name);
    let filter = FWPM_FILTER0 {
        displayData: display(&mut name_w),
        flags,
        layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        subLayerKey: *sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        ..Default::default()
    };

    // SAFETY: `engine` is live, `filter` is fully initialized and its
    // `filterCondition` points at `conditions`, which stays alive for the
    // call; the condition values point at storage that also outlives it. A
    // null security descriptor asks for the default.
    let code = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
    if code == 0 { Ok(()) } else { Err(code) }
}

fn display(name: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: PWSTR::null(),
    }
}

fn wide(value: &str) -> Vec<u16> {
    wide_os(OsStr::new(value))
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::ApiGuard;

    /// Install the guard against a live listener and prove that this image
    /// (the test process) may connect while another image may not. The second
    /// connect after the guard drops proves the dynamic session removes the
    /// filters. Requires an elevated shell; the CI and the normal suite skip
    /// it.
    #[test]
    #[ignore = "installs a WFP filter; requires an elevated shell"]
    fn the_guard_permits_only_the_app_image() {
        if !crate::sys::elevation::is_elevated() {
            return;
        }
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind the probe listener");
        let port = listener.local_addr().expect("probe address").port();
        let guard = ApiGuard::new(port).expect("install the guard");

        // This process is the permitted image.
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "the permitted image must reach the port"
        );
        // Another image is blocked.
        assert_eq!(
            connect_from_other_image(port),
            1,
            "another image must not reach the port"
        );
        drop(guard);
        assert_eq!(
            connect_from_other_image(port),
            0,
            "dropping the guard must remove the block"
        );
    }

    /// `0` when the child connected, `1` when the connection failed. The child
    /// is a different image (`powershell.exe`), so the guard's app-id
    /// condition does not match it.
    fn connect_from_other_image(port: u16) -> i32 {
        let script = format!(
            "try {{ $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', {port}); exit 0 }} catch {{ exit 1 }}"
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .expect("run the probe child");
        status.code().unwrap_or(-1)
    }
}

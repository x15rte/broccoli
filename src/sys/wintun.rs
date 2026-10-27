//! Wintun adapter lifecycle helpers for TUN restarts.
//!
//! xray derives a wintun adapter's instance GUID deterministically as
//! `md5(adapter_name)` (first three fields little-endian, matching the
//! `windows.GUID` layout in `proxy/tun/tun_windows.go`). A TUN restart that
//! creates the same-named adapter while the previous adapter's teardown is
//! still in flight stalls `WintunCreateAdapter` indefinitely (its
//! `SwDeviceCreate` waits forever), and killing a core stuck there wedges PnP
//! device creation for every wintun user — reproduced 2026-08-28. Hard-killed
//! cores also leave phantom devnodes behind that accumulate. This module
//! enumerates and removes leftover devnodes for a configured adapter name so
//! a restart never races the previous teardown.
//!
//! A devnode that still reports `DN_STARTED` may belong to another Wintun
//! VPN's live adapter, so removal is gated by ownership: the helper records
//! the adapter names it brought up in [`AdapterRecord`], and only those names'
//! devnodes are removed while started. A name the marker does not know is
//! removed only when its devnode is stopped — a legacy leftover — and recorded
//! then, so the next cleanup treats that adapter as this install's.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use md5::Digest as _;

use crate::r#gen::keys;
use crate::sys::durable::write_atomic;

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DEVNODE_STATUS_FLAGS, CM_Get_DevNode_Status, CM_LOCATE_DEVNODE_PHANTOM, CM_Locate_DevNodeW,
    CM_PROB, CR_SUCCESS, DI_REMOVEDEVICE_GLOBAL, DIF_REMOVE, DN_STARTED, GUID_DEVCLASS_NET,
    HDEVINFO, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_REMOVEDEVICE_PARAMS,
    SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsExW, SetupDiGetDeviceInstanceIdW, SetupDiSetClassInstallParamsW,
};
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::core::{GUID, HRESULT, PCWSTR, w};

/// Poll interval while waiting for a devnode to disappear.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Most adapter names the marker keeps. One configuration names one adapter;
/// the union survives a name change across sessions.
const MAX_RECORDED_ADAPTERS: usize = 64;

/// Upper bound on the marker's bytes. The file lives under an admin-only
/// directory, and a larger one reads as empty rather than being parsed.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Longest adapter name the marker accepts. Windows adapter names are far
/// shorter; a longer value cannot name a devnode this module would find.
const MAX_RECORDED_NAME_CHARS: usize = 256;

/// PnP enumerator filter for wintun devnodes. `SetupDiGetClassDevsExW`'s
/// second parameter is an enumerator (`EnumeratorName[\DeviceID]`), never a
/// hardware ID: wintun creates its devnodes through the software-device
/// enumerator, so their instance IDs are `SWD\WINTUN\{GUID}` — the shape
/// [`instance_guid_matches`] documents and this module's tests pin. The bare
/// `Wintun` string names the adapter's hardware ID and selects no devnode
/// under this filter. xray's own wintun teardown passes `SWD\WINTUN` as well.
const WINTUN_ENUMERATOR: PCWSTR = w!("SWD\\WINTUN");

/// RAII guard: SetupDi device-info lists are heap-ish handles that must be
/// destroyed, including on error paths.
struct DevInfoGuard(HDEVINFO);

impl Drop for DevInfoGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live list handle from SetupDiGetClassDevsExW
        // that was not consumed elsewhere (the guard owns it).
        unsafe {
            let _ = SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

/// The wintun adapter instance GUID xray derives for an adapter name:
/// `md5(name)` with the first three fields little-endian (the `windows.GUID`
/// layout in xray's `tun_windows.go`).
pub fn adapter_guid(name: &str) -> GUID {
    let digest: [u8; 16] = md5::Md5::digest(name.as_bytes()).into();
    GUID {
        data1: u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]),
        data2: u16::from_le_bytes([digest[4], digest[5]]),
        data3: u16::from_le_bytes([digest[6], digest[7]]),
        data4: [
            digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
            digest[15],
        ],
    }
}

/// Open the net-class devnode list for the wintun software-device enumerator
/// ([`WINTUN_ENUMERATOR`]), including non-present (phantom) devnodes — exactly
/// what must be cleaned before a TUN restart.
fn enumerate_wintun_devnodes() -> Result<HDEVINFO, String> {
    // SAFETY: `Some(&GUID_DEVCLASS_NET)` and `WINTUN_ENUMERATOR` are both
    // static NUL-terminated strings that outlive the call, and every other
    // argument is absent (no parent window, no machine name, no extra
    // parameters) — the `None`s the callee treats as defaults. Flags are
    // `Default::default()` (none), which is what keeps phantom devnodes in
    // the list. The returned `HDEVINFO` is the only owned object, and its
    // caller wraps it in `DevInfoGuard`, which destroys it on every exit.
    unsafe {
        SetupDiGetClassDevsExW(
            Some(&GUID_DEVCLASS_NET),
            WINTUN_ENUMERATOR,
            None,
            Default::default(),
            None,
            None,
            None,
        )
    }
    .map_err(|error| format!("SetupDiGetClassDevsExW failed: {error}"))
}

/// The instance ID of one enumerated devnode (trimmed at the NUL).
fn instance_id_of(devinfo: HDEVINFO, data: &SP_DEVINFO_DATA) -> Result<Option<String>, String> {
    let mut required = 0u32;
    // SAFETY: `devinfo` is a live list handle owned by the caller,
    // `data.cbSize` was set at construction (`SP_DEVINFO_DATA` demands it
    // before any enumerate call), and the null buffer with a length
    // out-pointer is the documented sizing query: the callee writes only the
    // required length into `required` and fails with
    // ERROR_INSUFFICIENT_BUFFER, which is deliberately ignored here.
    let _ = unsafe { SetupDiGetDeviceInstanceIdW(devinfo, data, None, Some(&mut required)) };
    if required == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0u16; required as usize];
    // SAFETY: same live `devinfo`/`data`, and `buffer` holds exactly the
    // `required` UTF-16 units the sizing query just reported, so the callee
    // writes at most that many units into a live, writable buffer.
    unsafe {
        SetupDiGetDeviceInstanceIdW(devinfo, data, Some(&mut buffer), None)
            .map_err(|error| format!("SetupDiGetDeviceInstanceIdW failed: {error}"))?;
    }
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..end])))
}

/// Canonical `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` form of a GUID.
fn format_guid(guid: &GUID) -> String {
    let uuid = uuid::Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4);
    format!("{{{uuid:X}}}")
}

/// Whether an instance ID (`SWD\WINTUN\{GUID}`) belongs to the adapter name's
/// deterministic GUID. Case-insensitive: the enumerator prefix casing varies
/// between APIs (`SWD\WINTUN` vs `SWD\Wintun`).
fn instance_guid_matches(instance: &str, target: &GUID) -> bool {
    let Some(open) = instance.rfind('{') else {
        return false;
    };
    let Some(close) = instance.rfind('}') else {
        return false;
    };
    if close <= open {
        return false;
    }
    instance[open..=close].eq_ignore_ascii_case(&format_guid(target))
}

/// Instance IDs of all wintun devnodes whose instance GUID matches the
/// adapter name's deterministic GUID — including phantom devnodes left by
/// hard-killed cores.
pub fn matching_instance_ids(name: &str) -> Result<Vec<String>, String> {
    let target = adapter_guid(name);
    let devinfo = enumerate_wintun_devnodes()?;
    let _guard = DevInfoGuard(devinfo);
    let mut data = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };
    let mut ids = Vec::new();
    let mut index = 0u32;
    loop {
        // SAFETY: `devinfo` is the live list the guard above owns, `index`
        // counts from zero in this loop only, and `data` is a live
        // `SP_DEVINFO_DATA` whose `cbSize` was set before the first call —
        // the callee writes the enumerated element into it and reports
        // ERROR_NO_MORE_ITEMS past the end, which ends the loop.
        match unsafe { SetupDiEnumDeviceInfo(devinfo, index, &mut data) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => break,
            Err(error) => return Err(format!("SetupDiEnumDeviceInfo failed: {error}")),
        }
        index += 1;
        if let Some(instance) = instance_id_of(devinfo, &data)?
            && instance_guid_matches(&instance, &target)
        {
            ids.push(instance);
        }
    }
    Ok(ids)
}

/// DIF_REMOVE one wintun devnode by instance ID — the same operation wintun's
/// own cleanup performs, and the same one `pnputil /remove-device` wraps.
/// Works for both present and phantom devnodes.
pub fn remove_instance(instance_id: &str) -> Result<(), String> {
    let devinfo = enumerate_wintun_devnodes()?;
    let _guard = DevInfoGuard(devinfo);
    let mut data = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };
    let mut index = 0u32;
    loop {
        // SAFETY: `devinfo` is the live list the guard above owns, `index`
        // counts from zero in this loop only, and `data` is a live
        // `SP_DEVINFO_DATA` whose `cbSize` was set before the first call.
        match unsafe { SetupDiEnumDeviceInfo(devinfo, index, &mut data) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => {
                return Err(format!("devnode {instance_id} not found"));
            }
            Err(error) => return Err(format!("SetupDiEnumDeviceInfo failed: {error}")),
        }
        index += 1;
        let Some(candidate) = instance_id_of(devinfo, &data)? else {
            continue;
        };
        if !candidate.eq_ignore_ascii_case(instance_id) {
            continue;
        }
        let mut params = SP_REMOVEDEVICE_PARAMS::default();
        params.ClassInstallHeader.cbSize = std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32;
        params.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        params.Scope = DI_REMOVEDEVICE_GLOBAL;
        // SAFETY: `devinfo` is the live list the guard above owns and `data`
        // is the live element the enumeration matched, with its `cbSize` set.
        // `params` is a fully initialized `SP_REMOVEDEVICE_PARAMS` (its own
        // `ClassInstallHeader.cbSize` set to that header's size, the install
        // function set to DIF_REMOVE), and the length passed with it is
        // exactly `size_of::<SP_REMOVEDEVICE_PARAMS>()`, so the callee reads
        // one complete structure. The header sub-object the call points at is
        // the first field of `params`, inside that same live value.
        unsafe {
            SetupDiSetClassInstallParamsW(
                devinfo,
                Some(&data),
                Some(&params.ClassInstallHeader),
                std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
            )
            .map_err(|error| format!("SetupDiSetClassInstallParamsW failed: {error}"))?;
            SetupDiCallClassInstaller(DIF_REMOVE, devinfo, Some(&data)).map_err(|error| {
                format!("SetupDiCallClassInstaller(DIF_REMOVE) failed: {error}")
            })?;
        }
        return Ok(());
    }
}

/// The protected marker of adapter names this install created, written by the
/// elevated helper into its secure stage base. Cleanup reads it to tell this
/// install's devnodes from another Wintun VPN's started adapter: a recorded
/// name may be removed even while `DN_STARTED` is set, because the devnode is
/// ours. A missing or unreadable marker means nothing is recorded — an old
/// install still cleans up through the stopped-devnode migration in
/// [`ensure_clean`].
pub struct AdapterRecord {
    path: PathBuf,
}

impl AdapterRecord {
    /// The marker at `path`. Reading and writing stay bounded and atomic; the
    /// file is never trusted for more than the names it lists.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The recorded adapter names. A missing, oversized, or unparseable marker
    /// reads as empty and never panics — a corrupt marker can only cost the
    /// started-devnode exemption, never a device removal.
    pub fn names(&self) -> Vec<String> {
        let Some(bytes) = read_bounded(&self.path) else {
            return Vec::new();
        };
        let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) else {
            return Vec::new();
        };
        names
            .into_iter()
            .filter(|name| {
                !name.trim().is_empty() && name.chars().count() <= MAX_RECORDED_NAME_CHARS
            })
            .take(MAX_RECORDED_ADAPTERS)
            .collect()
    }

    /// Add `name` to the record, writing the whole marker atomically. An
    /// already recorded name is a no-op. A name longer than any real adapter
    /// name is refused instead of truncating the identity cleanup depends on.
    pub fn record(&self, name: &str) -> Result<(), String> {
        if name.trim().is_empty() {
            return Ok(());
        }
        if name.chars().count() > MAX_RECORDED_NAME_CHARS {
            return Err(format!(
                "adapter name is longer than {MAX_RECORDED_NAME_CHARS} characters"
            ));
        }
        let mut names = self.names();
        if names.iter().any(|recorded| recorded == name) {
            return Ok(());
        }
        if names.len() >= MAX_RECORDED_ADAPTERS {
            names.remove(0);
        }
        names.push(name.to_string());
        let bytes = serde_json::to_vec(&names).map_err(|error| error.to_string())?;
        write_atomic(&self.path, &bytes).map_err(|error| error.to_string())
    }
}

/// The marker's bytes, or `None` when it is absent, unreadable, or larger
/// than [`MAX_RECORD_BYTES`]. The read is capped, so a corrupt file cannot
/// grow an unbounded buffer in the elevated helper.
fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_RECORD_BYTES).then_some(bytes)
}

/// Whether a devnode status reports a running device (`DN_STARTED`).
fn devnode_is_started(status: CM_DEVNODE_STATUS_FLAGS) -> bool {
    status.contains(DN_STARTED)
}

/// Whether an enumerated devnode may be removed: one whose adapter name this
/// install recorded is ours even while started, and one that is not started is
/// a leftover from a hard-killed core. Only an unrecorded devnode that still
/// reports started may belong to another Wintun VPN's live adapter.
fn devnode_removal_allowed(recorded: bool, started: bool) -> bool {
    recorded || !started
}

/// The configuration-manager status of `instance_id`, or `None` when the
/// devnode cannot be located or its status cannot be read. Both failures are
/// treated as live by [`ensure_clean`]: a device whose state is unknown must
/// never be destroyed.
fn instance_status(instance_id: &str) -> Option<CM_DEVNODE_STATUS_FLAGS> {
    let wide: Vec<u16> = instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut devinst = 0u32;
    // SAFETY: `wide` is a NUL-terminated copy of the instance ID that outlives
    // the call, `devinst` is a valid out-parameter, and
    // `CM_LOCATE_DEVNODE_PHANTOM` finds non-present devnodes as well as
    // present ones. The result is checked before `devinst` is used.
    if unsafe {
        CM_Locate_DevNodeW(
            &mut devinst,
            PCWSTR(wide.as_ptr()),
            CM_LOCATE_DEVNODE_PHANTOM,
        )
    } != CR_SUCCESS
    {
        return None;
    }
    let mut status = CM_DEVNODE_STATUS_FLAGS(0);
    let mut problem = CM_PROB(0);
    // SAFETY: `devinst` is the handle the successful locate above returned,
    // and both out-parameters are live locals; the status is only read when
    // the call reports success.
    if unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0) } != CR_SUCCESS {
        return None;
    }
    Some(status)
}

/// Remove leftover devnodes for the adapter name and wait (bounded) until none
/// remain. The wait is what serializes the restart against the previous
/// session's in-flight teardown. Returns `(clean, removed, log_lines)`, where
/// `removed` counts the devnodes this call actually removed.
///
/// `record` is the helper's marker of adapter names this install brought up. A
/// devnode whose name is recorded is ours, so a started one is removed too:
/// that is the stale adapter a previous session's hard kill left reporting
/// `DN_STARTED`. An unrecorded devnode that still reports started may belong
/// to another Wintun VPN's live adapter — it is left alone, reported once, and
/// keeps the wait running until the timeout. An unrecorded devnode that is not
/// started is a legacy leftover from before the marker existed: it is removed
/// and its name recorded, so the next cleanup treats that adapter as ours.
pub fn ensure_clean(
    name: &str,
    timeout: Duration,
    record: Option<&AdapterRecord>,
) -> (bool, usize, Vec<String>) {
    let deadline = Instant::now() + timeout;
    let mut removed = 0;
    let mut lines = Vec::new();
    let mut reported: Vec<String> = Vec::new();
    let mut recorded = record.is_some_and(|record| {
        let names = record.names();
        names.iter().any(|recorded| recorded == name)
    });
    loop {
        match matching_instance_ids(name) {
            Ok(ids) if ids.is_empty() => return (true, removed, lines),
            Ok(ids) => {
                for id in ids {
                    let started = match instance_status(&id) {
                        Some(status) => devnode_is_started(status),
                        None => {
                            if !reported.contains(&id) {
                                lines.push(format!(
                                    "wintun devnode {id} status is unknown; leaving it alone"
                                ));
                                reported.push(id);
                            }
                            continue;
                        }
                    };
                    if !devnode_removal_allowed(recorded, started) {
                        if !reported.contains(&id) {
                            lines.push(format!(
                                "wintun devnode {id} is a started adapter; leaving it alone"
                            ));
                            reported.push(id);
                        }
                        continue;
                    }
                    match remove_instance(&id) {
                        Ok(()) => {
                            removed += 1;
                            lines.push(format!("removed leftover wintun devnode {id}"));
                            // An unrecorded leftover proves this install owned
                            // the adapter; record the name so a later cleanup
                            // may remove a started devnode for it. A failed
                            // write only costs that exemption on the next run.
                            if !recorded && let Some(record) = record {
                                match record.record(name) {
                                    Ok(()) => recorded = true,
                                    Err(error) => lines.push(format!(
                                        "recording wintun adapter \"{name}\" failed: {error}"
                                    )),
                                }
                            }
                        }
                        Err(error) => {
                            lines.push(format!("removing {id} failed: {error}"));
                        }
                    }
                }
            }
            Err(error) => lines.push(format!("wintun devnode enumeration failed: {error}")),
        }
        if Instant::now() >= deadline {
            lines.push(format!(
                "wintun devnode cleanup for \"{name}\" timed out after {} ms",
                timeout.as_millis()
            ));
            return (false, removed, lines);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The tun adapter name a staged config creates, when it contains a TUN
/// inbound that names its adapter. Every config this app generates names it
/// ([`crate::model::inbound::TunCfg::effective_name`]); a config that does
/// not (a whole-config raw override carrying its own TUN inbound) is
/// answered with `None`, because the core fills a name-less inbound with a
/// random free `utun10`-`utun1024` name (infra/conf/tun.go) that this side
/// cannot map back to a devnode.
pub fn staged_tun_adapter_name(config_json: &str) -> Option<String> {
    let config: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let inbounds = config.get(keys::INBOUNDS)?.as_array()?;
    for inbound in inbounds {
        if inbound
            .get(keys::PROTOCOL)
            .and_then(serde_json::Value::as_str)
            != Some("tun")
        {
            continue;
        }
        let name = inbound
            .get(keys::SETTINGS)
            .and_then(|settings| settings.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())?;
        return Some(name.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A uniquely named directory under the system temp dir, removed by the
    /// test that made it.
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-wintun-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn adapter_guid_matches_observed_instances() {
        // Both observed on this machine: "broccoli0" produced
        // SWD\WINTUN\{C21DC854-03F2-AEA0-84D2-9C7AC601C070} (the phantom that
        // wedged the system on 2026-08-28).
        assert_eq!(
            format_guid(&adapter_guid("broccoli0")),
            "{C21DC854-03F2-AEA0-84D2-9C7AC601C070}"
        );
        assert_eq!(
            format_guid(&adapter_guid("tun0")),
            "{D89BE3B7-6DFA-9BED-1BA0-BAC340CA2C1C}"
        );
    }

    /// The removal gate reads the marker's ownership and the `DN_STARTED`
    /// bit: an unrecorded devnode with a problem but no started flag is a
    /// legacy leftover, while an unrecorded started one may be a running
    /// adapter this app must not tear down. A recorded name is this install's,
    /// so even a started devnode is removed.
    #[test]
    fn devnode_removal_follows_the_record_and_the_started_bit() {
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            CM_DEVNODE_STATUS_FLAGS, DN_HAS_PROBLEM,
        };

        assert!(devnode_is_started(DN_STARTED));
        assert!(devnode_is_started(CM_DEVNODE_STATUS_FLAGS(
            DN_STARTED.0 | DN_HAS_PROBLEM.0
        )));
        assert!(!devnode_is_started(CM_DEVNODE_STATUS_FLAGS(0)));
        assert!(!devnode_is_started(DN_HAS_PROBLEM));

        assert!(
            devnode_removal_allowed(true, true),
            "a recorded devnode is ours"
        );
        assert!(devnode_removal_allowed(true, false));
        assert!(
            devnode_removal_allowed(false, false),
            "a stopped leftover is removed"
        );
        assert!(
            !devnode_removal_allowed(false, true),
            "an unrecorded started devnode may belong to another Wintun VPN"
        );
    }

    /// The marker round-trips the names it held, records each name once, and
    /// reads every damage shape as "nothing recorded" — never a panic, and
    /// never a stale exemption for a started devnode.
    #[test]
    fn adapter_record_round_trips_and_reads_damage_as_empty() {
        let dir = scratch_dir("wintun-record");
        let path = dir.join("tun-adapters.json");
        let record = AdapterRecord::new(path.clone());

        assert!(
            record.names().is_empty(),
            "a missing marker records nothing"
        );
        record.record("broccoli0").expect("record");
        record.record("broccoli0").expect("record twice");
        record.record("tun1").expect("record second name");
        assert_eq!(record.names(), ["broccoli0", "tun1"]);

        record.record("   ").expect("a blank name is a no-op");
        assert!(
            record
                .record(&"n".repeat(MAX_RECORDED_NAME_CHARS + 1))
                .is_err()
        );
        assert_eq!(record.names(), ["broccoli0", "tun1"]);

        std::fs::write(&path, b"{not json").expect("corrupt marker");
        assert!(
            record.names().is_empty(),
            "a corrupt marker records nothing"
        );

        std::fs::write(&path, vec![b'x'; MAX_RECORD_BYTES as usize + 1]).expect("oversized marker");
        assert!(
            record.names().is_empty(),
            "an oversized marker records nothing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn instance_guid_match_is_case_insensitive_on_guid_part() {
        let target = adapter_guid("broccoli0");
        assert!(instance_guid_matches(
            "SWD\\WINTUN\\{C21DC854-03F2-AEA0-84D2-9C7AC601C070}",
            &target
        ));
        assert!(instance_guid_matches(
            "SWD\\Wintun\\{c21dc854-03f2-aea0-84d2-9c7ac601c070}",
            &target
        ));
        assert!(!instance_guid_matches(
            "SWD\\WINTUN\\{00000000-0000-0000-0000-000000000000}",
            &target
        ));
        assert!(!instance_guid_matches("SWD\\WINTUN\\not-a-guid", &target));
    }

    #[test]
    fn staged_config_tun_name_extraction() {
        let config = r#"{
            "inbounds": [
                {"tag": "in-socks", "protocol": "socks"},
                {"tag": "in-tun", "protocol": "tun",
                 "settings": {"name": "broccoli0", "mtu": 9000}}
            ]
        }"#;
        assert_eq!(
            staged_tun_adapter_name(config).as_deref(),
            Some("broccoli0")
        );

        let no_tun = r#"{"inbounds": [{"protocol": "socks"}]}"#;
        assert_eq!(staged_tun_adapter_name(no_tun), None);

        // A TUN inbound that names no adapter is one this side cannot map
        // back: the core fills the name itself.
        let empty_name = r#"{"inbounds": [{"protocol": "tun", "settings": {}}]}"#;
        assert_eq!(staged_tun_adapter_name(empty_name), None);

        let whitespace_name = r#"{"inbounds": [{"protocol": "tun", "settings": {"name": "  "}}]}"#;
        assert_eq!(staged_tun_adapter_name(whitespace_name), None);

        assert_eq!(staged_tun_adapter_name("not json"), None);
    }
}

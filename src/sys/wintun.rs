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

use std::time::{Duration, Instant};

use super::netif::{DEFAULT_TUN_ADAPTER_NAME, tun_adapter_name};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DI_REMOVEDEVICE_GLOBAL, DIF_REMOVE, GUID_DEVCLASS_NET, HDEVINFO, SP_CLASSINSTALL_HEADER,
    SP_DEVINFO_DATA, SP_REMOVEDEVICE_PARAMS, SetupDiCallClassInstaller,
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsExW,
    SetupDiGetDeviceInstanceIdW, SetupDiSetClassInstallParamsW,
};
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::core::{GUID, HRESULT, PCWSTR, w};

/// Poll interval while waiting for a devnode to disappear.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

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

/// RFC 1321 MD5. Used only to derive xray's deterministic wintun instance
/// GUID from the adapter name; not a security primitive here.
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (word, bytes) in m.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let next = b.wrapping_add(
                f.wrapping_add(a)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = d;
            d = c;
            c = b;
            b = next;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// The wintun adapter instance GUID xray derives for an adapter name:
/// `md5(name)` with the first three fields little-endian (the `windows.GUID`
/// layout in xray's `tun_windows.go`).
pub fn adapter_guid(name: &str) -> GUID {
    let d = md5(name.as_bytes());
    GUID {
        data1: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
        data2: u16::from_le_bytes([d[4], d[5]]),
        data3: u16::from_le_bytes([d[6], d[7]]),
        data4: [d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]],
    }
}

/// Open the net-class devnode list for the wintun software-device enumerator
/// ([`WINTUN_ENUMERATOR`]), including non-present (phantom) devnodes — exactly
/// what must be cleaned before a TUN restart.
fn enumerate_wintun_devnodes() -> Result<HDEVINFO, String> {
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
    // First call with a null buffer is the documented sizing query; it fails
    // with ERROR_INSUFFICIENT_BUFFER and fills `required`.
    let _ = unsafe { SetupDiGetDeviceInstanceIdW(devinfo, data, None, Some(&mut required)) };
    if required == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0u16; required as usize];
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
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
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

/// Remove leftover devnodes for the adapter name and wait (bounded) until none
/// remain. The wait is what serializes the restart against the previous
/// session's in-flight teardown. Returns `(clean, log_lines)`.
pub fn ensure_clean(name: &str, timeout: Duration) -> (bool, Vec<String>) {
    let deadline = Instant::now() + timeout;
    let mut lines = Vec::new();
    loop {
        match matching_instance_ids(name) {
            Ok(ids) if ids.is_empty() => return (true, lines),
            Ok(ids) => {
                for id in ids {
                    match remove_instance(&id) {
                        Ok(()) => {
                            lines.push(format!("removed leftover wintun devnode {id}"));
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
            return (false, lines);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The tun adapter name a generated config will create, if it contains a TUN
/// inbound: the shared wire-name derivation
/// ([`super::netif::tun_adapter_name`]), whose fallback covers the absent or
/// cleared name the wire form drops.
pub fn staged_tun_adapter_name(config_json: &str) -> Option<String> {
    let config: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let inbounds = config.get("inbounds")?.as_array()?;
    for inbound in inbounds {
        if inbound.get("protocol").and_then(serde_json::Value::as_str) != Some("tun") {
            continue;
        }
        let name = inbound
            .get("settings")
            .and_then(|settings| settings.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(tun_adapter_name)
            .unwrap_or(DEFAULT_TUN_ADAPTER_NAME);
        return Some(name.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: [u8; 16]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(md5(b"tun0")), "b7e39bd8fa6ded9b1ba0bac340ca2c1c");
        assert_eq!(hex(md5(b"broccoli0")), "54c81dc2f203a0ae84d29c7ac601c070");
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

        let empty_name = r#"{"inbounds": [{"protocol": "tun", "settings": {}}]}"#;
        assert_eq!(staged_tun_adapter_name(empty_name).as_deref(), Some("tun0"));

        let whitespace_name = r#"{"inbounds": [{"protocol": "tun", "settings": {"name": "  "}}]}"#;
        assert_eq!(
            staged_tun_adapter_name(whitespace_name).as_deref(),
            Some("tun0")
        );

        assert_eq!(staged_tun_adapter_name("not json"), None);
    }
}

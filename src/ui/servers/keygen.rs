//! Xray keygen/tool helpers of the servers screen: bounded, secret-redacting
//! `xray.exe` invocations off the UI thread (uuid / vless encryption /
//! wireguard secret / x25519 derive / ML-DSA-65 / tls hash & ping) and
//! stdout payload extraction. Private to the screen; the tool-apply path in
//! the parent module is the only caller.

use std::fmt::Write as _;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::i18n::{Key, t_fmt};
use crate::model::settings::Language;

// ---------- keygen helpers ----------

/// Render the tool command line for error messages, masking the argument
/// that follows `-i`. The REALITY public-key derive runs
/// `xray x25519 -i <private key>`, so a raw `args.join(" ")` would put the
/// private key bytes into failure text; no other helper invocation uses `-i`,
/// so those render unchanged.
pub(super) fn redacted_tool_args(args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for arg in args {
        if mask_next {
            parts.push("<redacted>".into());
            mask_next = false;
        } else {
            if arg == "-i" {
                mask_next = true;
            }
            parts.push(arg.clone());
        }
    }
    parts.join(" ")
}

/// Run an explicitly requested Xray helper off the UI thread. Each invocation
/// opens and retains a fresh compiled-pin-verified core handle through child
/// reaping, so a mutable AppData executable cannot be substituted after its
/// provenance check and before CreateProcess consumes it. The verification
/// mode follows the committed config, exactly like every core spawn. `budget`
/// bounds the wait loop; on its expiry the child is killed and reaped, and
/// the deadline error is rendered with redacted args. A set `stop` flag (a
/// cancelled request) ends the wait immediately: the loop falls through to
/// that same arm instead of holding the child until the budget, and the
/// caller — which sees the same flag — discards the returned verdict.
pub(super) fn run_xray_bounded(
    lang: Language,
    args: &[String],
    budget: Duration,
    stop: &AtomicBool,
) -> Result<String, String> {
    // Hold the verified handles through CreateProcess only: releasing earlier
    // would reopen the verification-to-execution replacement window, and
    // holding through reaping would transiently block a running core's geodata
    // updater from replacing the DAT files.
    let core = crate::sys::paths::core_dir();
    // The verification mode follows the committed config, like every spawn
    // path: a config carrying geodata URLs leaves the DAT pair to the core's
    // own updater, so the strict entry's drift heal must not revert it here.
    // One decision, shared with the spawns and the apply gate.
    let verified_core = crate::sys::core_dl::open_verified_for_config_at(
        &core,
        &crate::rt::apply::active_path(),
        crate::sys::core_dl::VerifyScope::Full,
    )
    .map_err(|error| {
        t_fmt(
            lang,
            Key::SrvManagedCoreVerificationFailed,
            &[&error.text(lang)],
        )
    })?;
    let mut child = crate::sys::hidden_command(core.join("xray.exe"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| t_fmt(lang, Key::SrvLaunchXrayFailed, &[&error]))?;
    // CreateProcess has consumed the verified paths; release the locks so
    // a running core's geodata updater stays unblocked.
    drop(verified_core);
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| t_fmt(lang, Key::SrvCollectOutputFailed, &[&error]))?;
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
                }
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                let suffix = if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                };
                return Err(t_fmt(
                    lang,
                    Key::SrvXrayExited,
                    &[
                        &redacted_tool_args(args),
                        &output.status.to_string(),
                        &suffix,
                    ],
                ));
            }
            // A cancelled request must not hold its child until the
            // deadline: failing this guard drops through to the arm below,
            // which kills and reaps it. The caller sees the same flag and
            // discards the verdict that arm returns.
            Ok(None) if started.elapsed() < budget && !stop.load(Ordering::Acquire) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .map_err(|error| t_fmt(lang, Key::SrvReapTimedOutFailed, &[&error]))?;
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                let suffix = if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                };
                return Err(t_fmt(
                    lang,
                    Key::SrvXrayDeadline,
                    &[&redacted_tool_args(args), &budget.as_secs(), &suffix],
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(t_fmt(
                    lang,
                    Key::SrvWaitXrayFailed,
                    &[&redacted_tool_args(args), &error],
                ));
            }
        }
    }
}

/// Extract the payload after `<prefix>:` from xray keygen stdout. Xray 26.x
/// prints e.g. `PrivateKey: …` / `Password (PublicKey): …`; older builds used
/// `Private key:` / `Public key:` — accept both.
pub(super) fn keygen_value(stdout: &str, prefixes: &[&str]) -> Option<String> {
    stdout.lines().find_map(|l| {
        let l = l.trim();
        prefixes
            .iter()
            .find_map(|p| l.strip_prefix(p).map(|v| v.trim().to_string()))
    })
}

pub(super) const PRIV_PREFIXES: &[&str] = &["PrivateKey:", "Private key:"];
pub(super) const PUB_PREFIXES: &[&str] = &["Password (PublicKey):", "PublicKey:", "Public key:"];

/// 8 random lowercase hex chars from uuid v4 bytes (REALITY shortId).
pub(super) fn gen_short_id() -> String {
    let u = uuid::Uuid::new_v4();
    u.as_bytes()[..4].iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

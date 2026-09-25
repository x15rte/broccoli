//! GUI-owned state layer mirroring the Xray JSON wire shape.
//!
//! Every config-layer struct derives serde with `rename_all = "camelCase"` +
//! `default`, skips empty/optional fields on serialize, and ends with a
//! `#[serde(flatten)] extra` map so unknown Xray keys round-trip losslessly
//! (mirrors Xray's own `json.RawMessage` escape hatch, infra/conf/xray.go).
//!
//! Two Xray wire types need custom serde:
//! - [`Int32Range`] — serializes as `"from-to"` string or a bare number
//!   (infra/conf/common.go:289-345), NOT a `{from,to}` object.
//! - [`DurationMs`] — Go `time.Duration` strings ("10s", "1m30s"),
//!   infra/conf/cfgcommon/duration/duration.go.

pub mod dns;
pub mod fingerprint;
pub mod inbound;
pub mod outbound;
pub mod routing;
pub mod safety;
pub mod servers;
pub mod settings;
pub mod stream;
pub mod validation;

pub use dns::{DnsCfg, DnsServer, FakeDnsCfg, FakeDnsPool};
pub use inbound::{
    Account, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, Sniffing, TunCfg,
    default_local_inbounds, next_local_tag,
};
pub use outbound::{
    BlackholeResponse, BlackholeSettings, DnsOutRule, DnsOutboundSettings, Fragment,
    FreedomFinalRule, FreedomSettings, HttpSettings, HysteriaSettings, LoopbackSettings, MuxModel,
    Noise, OutboundModel, Protocol, ProtocolSettings, ShadowsocksSettings, SocksSettings,
    TrojanSettings, VlessReverse, VlessSettings, VmessSettings, WireguardPeer, WireguardSettings,
};
pub use routing::{
    Balancer, BurstObservatoryCfg, LeastLoadSettings, ObservatoryCfg, PingConfig, RoutingCfg, Rule,
    StrategyCfg, StrategyCost, Webhook,
};
pub use safety::{HazardClass, SafetyCode, SafetyFinding};
pub use servers::{ServerProfile, ServersFile};
pub use settings::{Mode, PolicyCfg, PolicyLevelCfg, Settings};
pub use stream::{
    CustomSockopt, FinalmaskFragment, FinalmaskHeaderCustomTcp, FinalmaskHeaderCustomUdp,
    FinalmaskMkcpLegacy, FinalmaskModel, FinalmaskNoise, FinalmaskNoiseItem, FinalmaskPortList,
    FinalmaskQuicParams, FinalmaskRawValue, FinalmaskRealm, FinalmaskRealmPortMapping,
    FinalmaskRealmTls, FinalmaskSalamander, FinalmaskSudoku, FinalmaskTcpItem, FinalmaskTcpMask,
    FinalmaskTransform, FinalmaskTransformArg, FinalmaskUdpHop, FinalmaskUdpItem, FinalmaskUdpMask,
    FinalmaskXdns, FinalmaskXicmp, FinalmaskXmc, FinalmaskXmcProfile, GrpcSettings, HappyEyeballs,
    HttpCamouflageRequest, HttpCamouflageResponse, HttpupgradeSettings, HysteriaTransport,
    KcpSettings, Network, RawHeader, RawSettings, RealityModel, Security, SockoptModel,
    StreamModel, TlsCert, TlsModel, WsSettings, XhttpSettings, XmuxConfig,
};
pub use validation::{ValidationCode, ValidationIssue};

use crate::links::excerpt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

// Test-only imports: `SECURITY_ATTRIBUTES`/`BOOL` back the `#[cfg(test)]`
// `with_user_restricted_attributes` wrapper (the production user-only DACL
// application lives in `sys::paths`).
#[cfg(test)]
use windows::Win32::Security::SECURITY_ATTRIBUTES;
#[cfg(test)]
use windows::core::BOOL;

// ---------- skip_serializing_if helpers ----------

pub(crate) fn skip_false(b: &bool) -> bool {
    !*b
}
pub(crate) fn skip_empty_str(s: &str) -> bool {
    s.is_empty()
}
/// Skip strings that are empty or whitespace-only — for fields whose
/// accessor treats blank as "unset" (serializer and accessor agree).
pub(crate) fn skip_blank_str(s: &str) -> bool {
    s.trim().is_empty()
}
pub(crate) fn skip_empty_vec<T>(v: &[T]) -> bool {
    v.is_empty()
}
pub(crate) fn skip_empty_map(m: &Map<String, Value>) -> bool {
    m.is_empty()
}
pub(crate) fn skip_zero_u16(v: &u16) -> bool {
    *v == 0
}
pub(crate) fn skip_zero_u32(v: &u32) -> bool {
    *v == 0
}

// ---------- state file load/save (atomic, corrupt-proof) ----------

pub(crate) fn state_file(name: &str) -> PathBuf {
    crate::sys::paths::state_dir().join(name)
}

/// Why [`load_state`] failed while leaving the file in place.
/// `pub` because [`Settings::load`] and [`ServersFile::load`] are public API
/// and surface it.
#[derive(Debug)]
pub enum StateLoadError {
    /// The state file could not be read at all — a sharing violation while
    /// another process holds it, an ACL denial, a disk error. The file was
    /// NOT touched and `Default` was NOT substituted: the caller must fail
    /// visibly, because an in-memory `Default` model written over an
    /// unreadable file would destroy state the user still has on disk. Only
    /// a genuinely absent file (`NotFound`) loads defaults.
    Io(String),
    /// The file is valid JSON but its content failed to deserialize — an
    /// unknown `security`/`network` value, a field of the wrong type, etc.
    /// The file was NOT renamed or modified, and `Default` was NOT
    /// substituted. The message names the offending field path (when known)
    /// and a bounded excerpt of the offending value (serde
    /// error text is truncated at the 48-char excerpt bound before it can be
    /// logged or rendered).
    Semantic(String),
}

impl std::fmt::Display for StateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateLoadError::Io(message) | StateLoadError::Semantic(message) => f.write_str(message),
        }
    }
}

/// Load a GUI state file.
///
/// Missing → `Default`. UNREADABLE (any read failure other than a missing
/// file) → `Err` naming the path and the OS error, file untouched: a
/// transient failure must not be reported as a fresh install, because the
/// defaults that would then be in memory get written over the intact file on
/// the next save. STRUCTURAL corruption (serde_json cannot parse the
/// document: syntax/EOF errors) → renamed to `<file>.broken-<unix ts>`, wiped
/// and deleted, and `Default` returned (no plaintext quarantine copy
/// remains). SEMANTIC failure (valid JSON whose content does not fit the
/// type — unknown `security`/`network` values, wrong field types) → `Err`
/// naming the offending field path and a bounded excerpt of the value; the
/// file is NOT renamed or touched, so the user can fix it and an older
/// broccoli reading a newer broccoli's state cannot destroy it.
pub(crate) fn load_state<T>(name: &str) -> Result<T, StateLoadError>
where
    T: serde::de::DeserializeOwned + Default,
{
    let path = state_file(name);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => {
            return Err(StateLoadError::Io(format!("{}: {error}", path.display())));
        }
    };
    // `serde_json::Deserializer` implements `serde::Deserializer` only through
    // `&mut`, so the path-aware wrapper borrows it.
    let mut de = serde_json::Deserializer::from_slice(&data);
    match serde_path_to_error::deserialize::<_, T>(&mut de) {
        Ok(value) => Ok(value),
        Err(path_error) => {
            let field_path = path_error.path().to_string();
            let error = path_error.into_inner();
            // Structural corruption — serde_json could not parse the document —
            // keeps the quarantine path. Semantic failures (valid JSON, bad
            // content) leave the file intact.
            if matches!(
                error.classify(),
                serde_json::error::Category::Io
                    | serde_json::error::Category::Syntax
                    | serde_json::error::Category::Eof
            ) {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut broken = path.clone().into_os_string();
                broken.push(format!(".broken-{ts}"));
                let broken_path = PathBuf::from(broken);
                // Move the corrupt file off the live name, then wipe-then-delete
                // the quarantine so no plaintext copy (server profiles, secrets)
                // remains for recovery tooling. A rename failure
                // leaves the corrupt file at the live name (the next save
                // overwrites it); a wipe failure is logged, never silent.
                if let Err(error) = std::fs::rename(&path, &broken_path) {
                    tracing::error!(
                        "renaming corrupt state file {} failed: {error}",
                        path.display()
                    );
                }
                if let Err(error) = wipe_and_delete(&broken_path) {
                    tracing::error!(
                        "wiping corrupt quarantine {} failed: {error}",
                        broken_path.display()
                    );
                }
                Ok(T::default())
            } else {
                // Semantic failures carry the full field path plus the
                // error text. Every value echo the custom visitors produce
                // is pre-excerpted at the 48-char convention, so a leaf
                // built from constant prefixes + an excerpted token +
                // constant suffix stays bounded (~300 chars) and is kept
                // whole to preserve diagnostics ("names the value"). Only a
                // leaf beyond the cap can contain serde's own unbounded echo
                // (unknown variant / invalid type / unknown field, whose text
                // scales with the raw token), so those are head-excerpted with
                // the same 48-char helper — the bound is by construction,
                // never a double cut of an already-bounded token.
                const SEMANTIC_LEAF_MAX: usize = 512;
                let text = error.to_string();
                let bounded = if text.len() > SEMANTIC_LEAF_MAX {
                    excerpt(&text)
                } else {
                    text
                };
                let message = if field_path.is_empty() {
                    bounded
                } else {
                    format!("{field_path}: {bounded}")
                };
                Err(StateLoadError::Semantic(message))
            }
        }
    }
}

/// Crash-durable atomic write of one state file: flush `<file>.tmp`, then
/// replace the target (Rust uses Win32 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`).
///
/// The temp file holds the full plaintext state (passwords, UUIDs, the
/// WireGuard key), so every failure path removes it best-effort before
/// returning the error: a failed save must not leave a stray `<file>.tmp`
/// next to the live file. The writer handle is closed by then, so the removal
/// is not blocked by the open file.
fn write_state_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let result = flush_and_replace(&tmp, path, bytes);
    if result.is_err()
        && let Err(error) = std::fs::remove_file(&tmp)
    {
        tracing::debug!(
            "removing unwritten state temp file {} failed: {error}",
            tmp.display()
        );
    }
    result
}

/// [`write_state_atomic`]'s fallible body: a partial file stays behind on any
/// error, so the caller owns dropping it.
fn flush_and_replace(tmp: &Path, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = File::create(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Crash-durable atomic save of a state file. Fails closed: the app-data
/// roots (state/config included) are created and hardened with the user-only
/// DACL by `ensure_dirs` before this write (the single enforcement point),
/// so a state file only ever lands in a
/// current-user-only directory, and the file inherits that ACE on creation.
pub(crate) fn save_state<T: Serialize>(name: &str, value: &T) -> anyhow::Result<()> {
    crate::sys::paths::ensure_dirs()?;
    write_state_atomic(&state_file(name), &serde_json::to_vec_pretty(value)?)
}

// ---------- wipe-then-delete of `.broken-*` quarantines ----------

/// Overwrite `path`'s contents in place with zero bytes, preserving length,
/// so recovery tooling cannot resurrect the plaintext. The zeros
/// are flushed to disk before returning; the file is left in place.
fn zero_file(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    let zeros = vec![0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    Ok(())
}

/// Wipe-then-delete `path`: zero the content and flush, then
/// remove the file. A missing file is success. The file is never deleted
/// unless the wipe succeeded — a failed wipe leaves the (possibly zeroed)
/// file in place and returns the error.
fn wipe_and_delete(path: &Path) -> std::io::Result<()> {
    match zero_file(path) {
        Ok(()) => std::fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

// ---------- restrictive DACL on state/config dirs ----------
//
// The current-user-only, inheritable, protected DACL that guards state and
// config files is applied at directory-creation time by
// `sys::paths::ensure_dirs` (single enforcement point: every ensured root
// carries it before any file can be written into it, and
// pre-existing unprotected roots are re-hardened on every startup run).
// Files created inside the protected dirs inherit the user-only ACE, so a
// save needs no per-save ACL application. The descriptor itself is built by
// `sys::security::with_user_restricted_security_descriptor` — the single
// implementation of this shape (the historical per-module copies migrated
// here; see the `sys::security` module docs). Owner/group stay
// unset: the kernel assigns the creator.

/// Wrap the user-restricted descriptor in a `SECURITY_ATTRIBUTES` and hand it
/// to `operation`. Test-only: production DACL application lives in
/// `sys::paths` (`secure_dir_user_only`, reached through `ensure_dirs`); this
/// wrapper mirrors the mutex-acquisition shape in `src/sys/single_instance.rs`
/// so the DACL construction is exercised through a real `SECURITY_ATTRIBUTES`.
/// The descriptor comes from the shared `sys::security` builder (which owns
/// the token/SID/DACL machinery); `sys::security`'s own
/// `with_user_restricted_attributes` is the mutex shape, so this wrapper
/// keeps exercising the inheritable+protected directory shape through a
/// `SECURITY_ATTRIBUTES`.
#[cfg(test)]
fn with_user_restricted_attributes<T>(
    access: u32,
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T,
) -> Option<T> {
    crate::sys::security::with_user_restricted_security_descriptor(access, |descriptor| {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        operation(&attributes)
    })
    .ok()
}

// ---------- Int32Range ----------

// ---------- Int32Range ----------

/// Xray `Int32Range` (infra/conf/common.go:289-345): marshals as `"from-to"`
/// or a bare number when from == to. Parses both forms incl. negatives
/// ("-114-514" → from -114, to 514).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Int32Range {
    pub from: i32,
    pub to: i32,
}

impl Int32Range {
    pub fn single(v: i32) -> Self {
        Self { from: v, to: v }
    }
    pub fn new(from: i32, to: i32) -> Self {
        Self { from, to }
    }
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        // Split from the second dash so negatives work (Go splitFromSecondDash).
        let search_from = if s.starts_with('-') { 1 } else { 0 };
        match s[search_from..].find('-').map(|i| i + search_from) {
            Some(i) => Some(Self {
                from: s[..i].parse().ok()?,
                to: s[i + 1..].parse().ok()?,
            }),
            None => {
                let v: i32 = s.parse().ok()?;
                Some(Self::single(v))
            }
        }
    }
}

impl From<i32> for Int32Range {
    fn from(v: i32) -> Self {
        Self::single(v)
    }
}

impl Serialize for Int32Range {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.from == self.to {
            s.serialize_i32(self.from)
        } else {
            s.collect_str(&format_args!("{}-{}", self.from, self.to))
        }
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Int32Range;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(r#"an integer or a range string of form "1-2""#)
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                i32::try_from(v)
                    .map(Int32Range::single)
                    .map_err(|_| E::custom(format!("Int32Range integer {v} is outside i32")))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                i32::try_from(v)
                    .map(Int32Range::single)
                    .map_err(|_| E::custom(format!("Int32Range integer {v} is outside i32")))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Int32Range::parse(v)
                    .ok_or_else(|| E::custom(format!("invalid Int32Range: {:?}", excerpt(v))))
            }
        }
        d.deserialize_any(V)
    }
}

// ---------- DurationMs ----------

/// Go `time.Duration` as milliseconds. Serializes to Go duration strings
/// ("10s", "1m30s", "500ms"); deserializes from those strings (a bare number
/// is accepted as milliseconds, our own extension — Xray never emits one).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationMs(pub u64);

impl DurationMs {
    pub fn millis(ms: u64) -> Self {
        Self(ms)
    }
    pub fn secs(s: u64) -> Self {
        Self(s * 1000)
    }
    pub fn as_millis(self) -> u64 {
        self.0
    }
    /// Go `time.Duration.String()` canonical form.
    pub fn to_go_string(self) -> String {
        let ms = self.0;
        if ms == 0 {
            return "0s".into();
        }
        if ms < 1000 {
            return format!("{ms}ms");
        }
        let s = ms / 1000;
        let frac = ms % 1000;
        let h = s / 3600;
        let m = (s % 3600) / 60;
        let sec = s % 60;
        let mut frac_str = String::new();
        if frac > 0 {
            frac_str = format!(".{frac:03}");
            while frac_str.ends_with('0') {
                frac_str.pop();
            }
        }
        if h > 0 {
            format!("{h}h{m}m{sec}{frac_str}s")
        } else if m > 0 {
            format!("{m}m{sec}{frac_str}s")
        } else {
            format!("{sec}{frac_str}s")
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() || s.starts_with('-') {
            return None;
        }
        if s == "0" {
            return Some(Self(0));
        }
        let b = s.as_bytes();
        let mut i = 0;
        let mut total_ms = 0f64;
        while i < b.len() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            if start == i {
                return None;
            }
            let num: f64 = s[start..i].parse().ok()?;
            let unit_start = i;
            while i < b.len() && !b[i].is_ascii_digit() && b[i] != b'.' {
                i += 1;
            }
            let mult = match &s[unit_start..i] {
                "ns" => 1e-6,
                "us" | "µs" | "μs" => 1e-3,
                "ms" => 1.0,
                "s" => 1e3,
                "m" => 6e4,
                "h" => 3.6e6,
                _ => return None,
            };
            let component_ms = num * mult;
            if !num.is_finite()
                || num < 0.0
                || !component_ms.is_finite()
                || component_ms < 0.0
                || total_ms > u64::MAX as f64 - component_ms
            {
                return None;
            }
            total_ms += component_ms;
        }
        let rounded = total_ms.round();
        if !rounded.is_finite() || rounded < 0.0 || rounded >= u64::MAX as f64 {
            return None;
        }
        Some(Self(rounded as u64))
    }
}

impl Serialize for DurationMs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self.to_go_string())
    }
}

impl<'de> Deserialize<'de> for DurationMs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = DurationMs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(r#"a Go duration string like "10s""#)
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(DurationMs(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map(DurationMs)
                    .map_err(|_| E::custom("duration milliseconds cannot be negative"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                DurationMs::parse(v)
                    .ok_or_else(|| E::custom(format!("invalid duration: {:?}", excerpt(v))))
            }
        }
        d.deserialize_any(V)
    }
}

pub(crate) fn skip_duration_zero(d: &DurationMs) -> bool {
    d.0 == 0
}

#[cfg(test)]
mod tests;

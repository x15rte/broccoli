//! Xray-core download, verification and crash-safe installation.
//!
//! Downloads and extraction happen in uniquely named staging directories.
//! A completed tree is validated before the managed `core` directory is
//! replaced with sibling-directory renames; `core.bak` is the rollback point
//! and is recovered on the next launch if a process dies between the renames.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Seek as _, SeekFrom, Write as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::diag::{Diag, DiagError, DiagResult};
use crate::r#gen::keys;
use crate::i18n::Key;
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

use super::paths::{broccoli_root, core_dir};

const XRAY_VERSION: &str = env!("BROCCOLI_XRAY_VERSION");
const ZIP_ASSET: &str = env!("BROCCOLI_XRAY_ARCHIVE");
const ZIP_SHA256: &str = env!("BROCCOLI_XRAY_SHA256");
const XRAY_EXE_SHA256: &str = env!("BROCCOLI_XRAY_EXE_SHA256");
const WINTUN_SHA256: &str = env!("BROCCOLI_WINTUN_SHA256");
const GEOIP_SHA256: &str = env!("BROCCOLI_GEOIP_SHA256");
const GEOSITE_SHA256: &str = env!("BROCCOLI_GEOSITE_SHA256");
const RELEASE_DIGEST_FILE: &str = ".broccoli-official-release.json";
const SWAP_MARKER: &str = ".core-update.pending";
const METADATA_SCHEMA: u32 = 3;
const CORE_DOWNLOAD_MAX_BYTES: u64 = 128 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// A just-exited process can retain a file handle briefly on Windows. This is
/// bounded so a filesystem/AV fault remains a terminal update error.
const ROLLBACK_RENAME_ATTEMPTS: usize = 8;
const ROLLBACK_RENAME_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Files kept from the release zip; everything else is dropped.
const KEEP: &[&str] = &[
    "xray.exe",
    "geoip.dat",
    "geosite.dat",
    "wintun.dll",
    "LICENSE",
    "LICENSE-Wintun",
];

/// `(payload file, compiled release pin)` pairs verified before a
/// traffic-carrying spawn: xray.exe executes the config, wintun.dll backs
/// the TUN inbound, and the DAT files feed routing-rule geo conditions.
const RUNTIME_PAYLOAD_PINS: &[(&str, &str)] = &[
    ("xray.exe", XRAY_EXE_SHA256),
    ("wintun.dll", WINTUN_SHA256),
    ("geoip.dat", GEOIP_SHA256),
    ("geosite.dat", GEOSITE_SHA256),
];

/// Geo data payload files that a user-configured `geodata` updater
/// replaces on its cron while the core runs. Only these two
/// compares are ever suspendable; xray.exe, wintun.dll, and the
/// release metadata are never geo data and stay hard-pinned in every mode.
const GEO_DATA_PAYLOADS: &[&str] = &["geoip.dat", "geosite.dat"];

/// True when `name` is a geo data payload whose byte compare the
/// user-managed state suspends. Payload identity, not scope,
/// decides — the executable and the wintun driver are strict under every
/// entry, and an exe-only scope contains no geo data payload to suspend.
pub(crate) fn is_geo_data_payload(name: &str) -> bool {
    GEO_DATA_PAYLOADS.contains(&name)
}

/// Which pinned runtime payloads a caller needs verified before it executes
/// xray.exe.
///
/// Every traffic-carrying main-core spawn (connect, apply restart, backoff
/// retry, TUN candidate staging) runs under a full routing config and loads
/// wintun.dll plus the geodata DATs, so [`VerifyScope::Full`] re-hashes all
/// four payloads. A latency-probe spawn executes only xray.exe against an
/// outbound-only config that references no wintun/geodata payload (pinned by
/// the probe-config shape test in `rt::latency`), so
/// [`VerifyScope::XrayExeOnly`] hashes just the exe — the four-payload
/// SHA-256 on every probe click was overhead on files the probe child never
/// loads. The integrity guarantee that matters is on the core that carries
/// traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyScope {
    /// Every runtime payload: xray.exe, wintun.dll, geoip.dat, geosite.dat.
    Full,
    /// xray.exe only — the sole payload a latency-probe child executes.
    XrayExeOnly,
}

impl VerifyScope {
    /// The `(payload, compiled SHA-256 pin)` pairs this scope verifies.
    /// Crate-visible so the verification-site tests can assert which payloads
    /// a scope covers and which of them are suspendable geo data.
    pub(crate) fn payload_pins(self) -> &'static [(&'static str, &'static str)] {
        match self {
            VerifyScope::Full => RUNTIME_PAYLOAD_PINS,
            // xray.exe is the first pin of the full set.
            VerifyScope::XrayExeOnly => &RUNTIME_PAYLOAD_PINS[..1],
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OfficialReleaseMetadata {
    schema: u32,
    archive_asset: String,
    archive_sha256: String,
    xray_sha256: String,
    wintun_sha256: String,
    geoip_sha256: String,
    geosite_sha256: String,
    version: String,
}

struct LockedPayload {
    name: &'static str,
    expected_sha256: String,
    source: File,
}

/// Locked, verified runtime payloads used to materialize the elevated stage.
/// Every source handle denies write/delete until its bytes have been copied
/// and checked again in the protected destination.
pub struct VerifiedCore {
    version: String,
    payloads: Vec<LockedPayload>,
    _metadata: File,
}

impl VerifiedCore {
    /// Copy only the elevated runtime allowlist into an already-secured empty
    /// directory. Returned destination handles deny write/delete and must stay
    /// alive through validation and `CreateProcess` of the staged child; the
    /// caller releases them once the child is spawned so its geodata updater
    /// can replace the DAT files.
    pub fn copy_runtime_payloads(&mut self, destination: &Path) -> Result<Vec<File>, DiagError> {
        let mut locks = Vec::with_capacity(self.payloads.len());
        for payload in &mut self.payloads {
            payload
                .source
                .seek(SeekFrom::Start(0))
                .diag_with(Diag::new(Key::CoreDlPayloadRewindFailed).arg(payload.name))?;
            let target = destination.join(payload.name);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ.0)
                .open(&target)
                .diag_with(Diag::new(Key::CoreDlPayloadCreateFailed).arg(target.display()))?;
            std::io::copy(&mut payload.source, &mut output)
                .diag_with(Diag::new(Key::CoreDlPayloadCopyFailed).arg(payload.name))?;
            output
                .sync_all()
                .diag_with(Diag::new(Key::CoreDlPayloadFlushFailed).arg(payload.name))?;
            drop(output);
            let actual = sha256_hex(&target)?;
            if !actual.eq_ignore_ascii_case(&payload.expected_sha256) {
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlPayloadProofFailed)
                        .arg(payload.name)
                        .arg(&payload.expected_sha256)
                        .arg(&actual),
                ));
            }
            // The tamper lock must be a READ-only handle with share=READ: it
            // blocks write/delete opens (share lacks FILE_SHARE_WRITE and
            // FILE_SHARE_DELETE) while permitting the read+execute opens
            // CreateProcess and the loader need. A write-mode handle with
            // share=READ makes spawning the staged xray (and loading its
            // imports) fail with ERROR_SHARING_VIOLATION (os error 32) —
            // reproduced empirically on this machine.
            let lock = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0)
                .open(&target)
                .diag_with(Diag::new(Key::CoreDlPayloadLockFailed).arg(target.display()))?;
            locks.push(lock);
        }
        Ok(locks)
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

pub(crate) fn user_agent() -> &'static str {
    concat!("broccoli/", env!("CARGO_PKG_VERSION"))
}

/// Recover an interrupted rename transaction without discarding the only
/// known-good core. A complete candidate plus backup remains pending until the
/// runtime acknowledges first readiness.
pub fn recover_installation() -> Result<(), DiagError> {
    recover_interrupted_swap(&broccoli_root())
}

/// Finalize a staged core/DAT update only after Xray answered its first
/// readiness probe. Ordering is backup removal then marker removal, so a crash
/// between them leaves a harmless marker that recovery can clear.
pub fn acknowledge_core_health() -> Result<(), DiagError> {
    acknowledge_core_health_at(&broccoli_root())
}

/// Restore the retained last-good tree after a newly installed core or DAT
/// pair fails before readiness. Returns `false` when no health-pending swap
/// exists, which keeps unrelated startup failures out of the update path.
pub fn rollback_unhealthy_update() -> Result<bool, DiagError> {
    rollback_pending_update_at(&broccoli_root())
}

pub fn update_pending_health() -> bool {
    let root = broccoli_root();
    recover_interrupted_swap(&root).is_ok()
        && root.join("core.bak").is_dir()
        && marker_path(&root).is_file()
}

/// Open a managed core only after checking that its directory, metadata, and
/// every runtime payload path are ordinary files and that their bytes match
/// Broccoli's compiled release pins. This is the full four-payload verify
/// traffic-carrying spawns need; spawns whose child executes only xray.exe
/// (the latency probe) use `open_verified_core_with_scope` with the
/// `XrayExeOnly` scope instead. The returned value owns deny-write/
/// delete handles for the verified payloads; callers executing Xray MUST
/// retain it until CreateProcess consumes the verified paths, then release
/// it so the core's geodata updater can replace the DAT files while the
/// child runs.
pub fn open_verified_core(core: &Path) -> Result<VerifiedCore, DiagError> {
    open_verified_core_with_scope(core, VerifyScope::Full)
}

/// Open a managed core under the payload set [`VerifyScope`] names.
///
/// [`VerifyScope::XrayExeOnly`] serves latency-probe spawns: the probe child
/// executes only xray.exe from an outbound-only config that never touches
/// wintun.dll or the geodata DATs (the config shape is pinned by the
/// probe-config test in `rt::latency`), so re-hashing 60–120 MB of payloads
/// it cannot load on every probe click was pure spawn latency. The tamper
/// guard on the payload that does execute — xray.exe — is identical to the
/// full scope, and every traffic-carrying spawn still goes through
/// [`VerifyScope::Full`]. Metadata is checked on both scopes: it is mutable
/// AppData bookkeeping only and never introduces a new trusted release or
/// digest. The compare is strict in every scope here: the geo data
/// suspension is a separate, config-driven decision the call sites make
/// with [`dat_pins_suspended_at`], never part of the scope.
pub(crate) fn open_verified_core_with_scope(
    core: &Path,
    scope: VerifyScope,
) -> Result<VerifiedCore, DiagError> {
    open_verified_core_checked(core, scope, false)
}

/// True when a config Value carries the top-level `geodata` block that a
/// configured geo data auto-update emits — the user's opt-in
/// statement that the geo data files are updater-managed, which suspends
/// their release-pin compare.
///
/// The predicate mirrors the generator's emission contract by construction:
/// `gen::generate_with_api_port` emits the `geodata` block iff
/// `GeodataCfg::is_configured()` — at least one non-empty geo data URL —
/// and every non-empty URL becomes an `assets[].url` entry, so an emitted
/// config suspends iff this predicate returns true. Shapes the generator
/// never emits (missing `geodata` key, non-object block, empty `assets`, an
/// entry whose `url` is absent, null, non-string, or empty) return false:
/// unconfigured or unparseable fails closed toward the hard pins.
pub fn geodata_updater_configured(config: &serde_json::Value) -> bool {
    let Some(assets) = config
        .get(keys::GEODATA)
        .and_then(serde_json::Value::as_object)
        .and_then(|geodata| geodata.get(keys::ASSETS))
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    assets.iter().any(|entry| {
        entry
            .get(keys::URL)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|url| !url.is_empty())
    })
}

/// Read the config at `config_path` and decide, with the one shared
/// predicate [`geodata_updater_configured`], whether its `geodata` block
/// suspends the geo data pin compare for the verification that is about to
/// run that exact config. The three verification sites (the direct core
/// spawn, the apply/`-test` gate, and the elevated-helper stage copy) all
/// derive their decision from here or from the predicate — it is never
/// re-implemented locally. Any I/O or parse failure answers `false` (fail
/// closed): only a parsed config that carries a `geodata` asset URL lifts
/// the pins.
pub fn dat_pins_suspended_at(config_path: &Path) -> bool {
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let config = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(config) => config,
        Err(_) => return false,
    };
    geodata_updater_configured(&config)
}

/// Open a managed core under the full payload set with the geo data
/// compares suspended: a pair replaced by a user-configured `geodata`
/// updater is user-managed state, and its drift is expected —
/// not a verification error.
///
/// Only the SHA-256 *compare* of the two geo data files changes. They are
/// still shape-checked as ordinary files, opened deny-write, and hashed,
/// but each one's recorded expectation is its observed hash (self-hash), so
/// the elevated-stage copy proof in [`VerifiedCore::copy_runtime_payloads`]
/// remains a byte-fidelity check. xray.exe, wintun.dll, and the release
/// metadata are compared against their compiled pins exactly as in
/// [`open_verified_core`], in both modes.
pub fn open_verified_core_user_managed_dats(core: &Path) -> Result<VerifiedCore, DiagError> {
    open_verified_core_checked(core, VerifyScope::Full, true)
}

/// Strict form of the shared verify used by the download/install path below
/// to validate freshly staged release trees: the geo data compare is never
/// suspended for a staged tree.
fn open_verified_core_at(core: &Path, scope: VerifyScope) -> Result<VerifiedCore, DiagError> {
    open_verified_core_checked(core, scope, false)
}

/// Shared verify implementation behind [`open_verified_core`],
/// [`open_verified_core_with_scope`], and
/// [`open_verified_core_user_managed_dats`].
///
/// With `dat_pins_suspended` set, the geo data files' SHA-256 compares are
/// replaced by a self-hash (see [`open_verified_core_user_managed_dats`]);
/// everything else — the ordinary-file shape pre-scan over the core
/// directory, the release metadata, and the scope's full payload set, the
/// deny-write locking, and the strict executable/driver/metadata compares —
/// is identical in both modes. Metadata is mutable AppData bookkeeping only;
/// it never introduces a new trusted release or digest.
///
/// The one behavioral difference between the modes is the strict entry's
/// answer to geo data drift. Under the suspended entry a drifted pair is
/// the expected user-managed state and verifies as-is, with no restore
/// attempted. Under the strict entry (no configured geodata URLs) a drifted
/// geo data payload is healed, never terminal on its own: the drift is
/// logged loudly with the failed pin compare,
/// the retained pin-verified pristine pair is restored
/// ([`restore_pristine_geo_data`]), and the replaced file is re-opened and
/// re-hashed against the pin. At most one restore is attempted per open;
/// the open fails terminally, naming the payload and both hashes, only when
/// the restore itself fails (missing or corrupt pristine pair) or the
/// restored bytes still mismatch the pin. Because this is the single shared
/// choke, the three verification sites — the direct core spawn, the
/// apply/`-test` gate, and the elevated-helper stage copy — and the
/// install-funnel validation below all heal identically (a staged tree
/// carries its own freshly seeded pair, so its strict open heals from it;
/// nothing here reorders or repeats the funnel's restore).
fn open_verified_core_checked(
    core: &Path,
    scope: VerifyScope,
    dat_pins_suspended: bool,
) -> Result<VerifiedCore, DiagError> {
    if !core.is_absolute() {
        return Err(DiagError::new(Diag::new(Key::CoreDlCorePathNotAbsolute)));
    }
    // The shape pre-scan always covers the scope's full payload set: a
    // suspended geo data file is still required to be an ordinary file.
    for (path, directory) in std::iter::once((core.to_path_buf(), true)).chain(
        std::iter::once((core.join(RELEASE_DIGEST_FILE), false)).chain(
            scope
                .payload_pins()
                .iter()
                .map(|(name, _)| (core.join(name), false)),
        ),
    ) {
        let metadata = fs::symlink_metadata(&path)
            .diag_with(Diag::new(Key::CoreDlSourceInspectFailed).arg(path.display()))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            let key = if directory {
                Key::CoreDlSourceNotDirectory
            } else {
                Key::CoreDlSourceNotFile
            };
            return Err(DiagError::new(Diag::new(key).arg(path.display())));
        }
    }

    let metadata_path = core.join(RELEASE_DIGEST_FILE);
    let metadata_file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(&metadata_path)
        .diag_with(Diag::new(Key::CoreDlMetadataOpenFailed).arg(metadata_path.display()))?;
    let metadata: OfficialReleaseMetadata = serde_json::from_reader(&metadata_file)
        .diag_with(Diag::new(Key::CoreDlMetadataParseFailed).arg(metadata_path.display()))?;
    let expected_version = pinned_banner_version()?;
    if !metadata_matches_compiled_pins(&metadata, &expected_version) {
        return Err(DiagError::new(Diag::new(Key::CoreDlMetadataMismatch)));
    }

    let pins = scope.payload_pins();
    // Index of the first geo data payload in the scope's pin set. The
    // strict-mode auto-restore below replaces BOTH geo data files — the
    // retained pristine pair is restored as a pair, see
    // `restore_pristine_geo_data` — so a heal must release every
    // geo-data deny-write lock taken so far and rewind to re-verify and
    // re-lock both files. `pins.len()` when the scope carries no geo data
    // payload (`VerifyScope::XrayExeOnly`), which makes the heal branch
    // unreachable for that scope.
    let first_geo_data_pin = pins
        .iter()
        .position(|(name, _)| is_geo_data_payload(name))
        .unwrap_or(pins.len());
    // One auto-restore attempt per open: a geo
    // data file that still does not match its pin after a successful
    // restore — a racing concurrent writer, or pristine bytes that changed
    // between restore's own pin check and this re-verify — is terminal
    // with the reason named, never re-healed in a loop.
    let mut auto_restored = false;
    let mut payloads = Vec::with_capacity(pins.len());
    let mut index = 0;
    while index < pins.len() {
        let (name, expected_sha256) = pins[index];
        let path = core.join(name);
        let mut source = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&path)
            .diag_with(Diag::new(Key::CoreDlPayloadOpenFailed).arg(path.display()))?;
        let actual = sha256_reader(&mut source)?;
        // The user-managed state suspends only the geo data byte compare:
        // the file was still shape-checked above and is opened deny-write
        // here, and its observed hash is recorded as the lock's expectation,
        // so the elevated-stage copy proof keeps checking byte fidelity.
        // Drift after a user-configured refresh is the expected
        // user-managed state, not a terminal error; xray.exe,
        // wintun.dll, and the release metadata never suspend.
        let geo_data_suspended = dat_pins_suspended && is_geo_data_payload(name);
        if !geo_data_suspended && !actual.eq_ignore_ascii_case(expected_sha256) {
            if !is_geo_data_payload(name) {
                // The executable and the wintun driver are never geo data:
                // their drift stays terminal with the identical message in
                // every mode, as does the release metadata,
                // which is verified before this loop.
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlPayloadVerifyFailed)
                        .arg(name)
                        .arg(expected_sha256)
                        .arg(&actual),
                ));
            }
            // Geo data drift under the strict entry heals instead of dying:
            // restoring the retained pin-verified pristine pair turns
            // removal-after-refresh and tamper/corruption — byte-identical
            // observable states without persisted provenance — back into
            // the pinned release state, so the open can proceed. The heal
            // is logged loudly with the failed release-verification data:
            // under the GUI process this reaches app.log (init_tracing in
            // app.rs); the elevated `--core-helper` process (main.rs
            // dispatches `run_helper` before any init_tracing) installs no
            // subscriber, so events are dropped there — no tracing init is
            // added here because helper failures still surface over the
            // pipe and in its stderr.
            if auto_restored {
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlPayloadStillDrifted)
                        .arg(name)
                        .arg(expected_sha256)
                        .arg(&actual),
                ));
            }
            auto_restored = true;
            tracing::warn!(
                "managed {name} drift: release verification expected {expected_sha256}, got {actual}; restoring the pin-verified pristine geo data pair and re-verifying"
            );
            // CRITICAL Windows detail: the deny-write `source` handle
            // opened above shares nothing (FILE_SHARE_READ only), so the
            // restore's MOVEFILE_REPLACE_EXISTING rename over the open file
            // would fail with a sharing violation. It must be dropped
            // first — and because the restore replaces both geo data files
            // whenever either is drifted, any earlier geo-data lock
            // (`geoip.dat` when the drift shows up on `geosite.dat`) must
            // go too. `payloads.truncate` closes those handles by dropping
            // the locked entries; the rewind below re-verifies and
            // re-locks the whole geo data pair.
            drop(source);
            payloads.truncate(first_geo_data_pin);
            if let Err(restore_error) = restore_pristine_geo_data(core) {
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlPayloadRestoreFailed)
                        .arg(name)
                        .arg(expected_sha256)
                        .arg(&actual),
                )
                .caused_by(restore_error));
            }
            // The managed geo data now hashes to the pins: restore proved
            // every pristine file against the compiled pins before
            // replacing anything, so the rewind re-verify passes unless a
            // writer races it, which the `auto_restored` bail above turns
            // into a terminal-with-reason error.
            index = first_geo_data_pin;
            continue;
        }
        payloads.push(LockedPayload {
            name,
            expected_sha256: if geo_data_suspended {
                actual
            } else {
                expected_sha256.to_owned()
            },
            source,
        });
        index += 1;
    }
    Ok(VerifiedCore {
        version: expected_version,
        payloads,
        _metadata: metadata_file,
    })
}

fn metadata_matches_compiled_pins(
    metadata: &OfficialReleaseMetadata,
    expected_version: &str,
) -> bool {
    metadata.schema == METADATA_SCHEMA
        && metadata.archive_asset == ZIP_ASSET
        && metadata.archive_sha256.eq_ignore_ascii_case(ZIP_SHA256)
        && metadata.xray_sha256.eq_ignore_ascii_case(XRAY_EXE_SHA256)
        && metadata.wintun_sha256.eq_ignore_ascii_case(WINTUN_SHA256)
        && metadata.geoip_sha256.eq_ignore_ascii_case(GEOIP_SHA256)
        && metadata.geosite_sha256.eq_ignore_ascii_case(GEOSITE_SHA256)
        && metadata.version == expected_version
}

fn pinned_banner_version() -> Result<String, DiagError> {
    let version = XRAY_VERSION
        .strip_prefix('v')
        .ok_or_else(|| DiagError::new(Diag::new(Key::CoreDlVersionPrefixMissing)))?;
    if !is_stable_xray_version(version) {
        return Err(DiagError::new(Diag::new(Key::CoreDlVersionInvalid)));
    }
    Ok(version.to_owned())
}

fn is_stable_xray_version(value: &str) -> bool {
    let mut fields = value.split('.');
    (0..3).all(|_| {
        fields.next().is_some_and(|field| {
            !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) && fields.next().is_none()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Open the configured managed core under compiled-pin verification and retain
/// its payload locks for the caller. Execution paths use this instead of a
/// check-then-spawn sequence.
pub fn open_verified_managed_core() -> Result<VerifiedCore, DiagError> {
    open_verified_core(&core_dir())
}

/// Reject an absent, tampered, or foreign managed core without executing it.
pub fn ensure_managed_core() -> Result<(), DiagError> {
    drop(open_verified_managed_core()?);
    Ok(())
}

/// A short-lived, process-local result for the expensive pinned-payload
/// verification. Render passes only consume this cache; launch and validation
/// still call [`open_verified_managed_core`] and rehash every payload.
const PRESENCE_CACHE_TTL: Duration = Duration::from_secs(2);

/// The managed core tree as one verification pass saw it.
///
/// The core setup surface needs all three answers: a tree that verified, a
/// tree that is present but did not verify — with the version that tree names
/// and the verification error's own message, so a stale install reads as an
/// update instead of a missing core — and no tree at all.
#[derive(Clone)]
pub enum CorePresence {
    /// No managed core tree to verify: the `core` directory is absent or
    /// empty, so the pinned release has never been installed. Nothing is
    /// verified in this state — an empty scaffold left by an interrupted
    /// transaction is not a failed install.
    Missing,
    /// The tree passed full pinned-payload verification.
    Verified { version: String },
    /// The tree is present but did not verify: stale (its release metadata
    /// names another build's release), tampered, or unreadable. `installed`
    /// carries the version the tree's own metadata names when that file is
    /// readable, so the surface can report both versions; `failure` is the
    /// verification error.
    Unverified {
        installed: Option<String>,
        failure: Arc<DiagError>,
    },
}

#[derive(Clone)]
struct PresenceCache {
    checked_at: SystemTime,
    root: PathBuf,
    dat_pins_suspended: bool,
    presence: CorePresence,
}

impl PresenceCache {
    /// Whether this memo answers a query for `root` in mode
    /// `dat_pins_suspended` and is still inside [`PRESENCE_CACHE_TTL`].
    /// The mode is part of the memo's identity: the two modes verify a
    /// drifted geo data pair differently (the suspended one accepts it as
    /// user-managed, the strict one heals it), so one mode's result must
    /// never be served to the other.
    fn answers(&self, root: &Path, dat_pins_suspended: bool) -> bool {
        self.root == root
            && self.dat_pins_suspended == dat_pins_suspended
            && self
                .checked_at
                .elapsed()
                .is_ok_and(|elapsed| elapsed < PRESENCE_CACHE_TTL)
    }
}

static PRESENCE_CACHE: LazyLock<Mutex<Option<PresenceCache>>> = LazyLock::new(|| Mutex::new(None));

/// Return the managed core tree's presence state, verifying the tree once
/// when no recent answer is available.
///
/// This deliberately caches both absence and verification failure: an egui
/// render frame must not SHA-256 several large payloads repeatedly while the
/// first-run wizard is visible. Managed-core transactions forget the cache
/// through their own invalidation guard, while every execution path retains
/// its own verified handles.
///
/// `dat_pins_suspended` selects the entry the verification uses and is part
/// of the memo's identity: true (a config carrying geodata URLs) opens the
/// tree through [`open_verified_core_user_managed_dats`] so a
/// user-refreshed pair is never reverted, while false keeps the strict
/// entry's heal of a drifted pair. The caller derives it from the same
/// settings predicate the config generator uses.
pub fn cached_core_presence(dat_pins_suspended: bool) -> CorePresence {
    let root = broccoli_root();
    if let Ok(guard) = PRESENCE_CACHE.lock()
        && let Some(entry) = guard
            .as_ref()
            .filter(|entry| entry.answers(&root, dat_pins_suspended))
    {
        return entry.presence.clone();
    }

    let presence = inspect_core(dat_pins_suspended);
    if let Ok(mut guard) = PRESENCE_CACHE.lock() {
        *guard = Some(PresenceCache {
            checked_at: SystemTime::now(),
            root,
            dat_pins_suspended,
            presence: presence.clone(),
        });
    }
    presence
}

/// Verify the managed tree now, bypassing the render memo — the core setup
/// surface's Verify action, where a user asks for a fresh answer instead of
/// the last one. The memo is replaced with this pass's answer.
pub fn verify_core_presence(dat_pins_suspended: bool) -> CorePresence {
    invalidate_presence_cache();
    cached_core_presence(dat_pins_suspended)
}

/// One verification pass over the managed tree. The installed version is read
/// before the verification, which consumes the release metadata file.
fn inspect_core(dat_pins_suspended: bool) -> CorePresence {
    let core = core_dir();
    if !tree_present(&core) {
        return CorePresence::Missing;
    }
    let installed = installed_release_version(&core);
    let verified = if dat_pins_suspended {
        open_verified_core_user_managed_dats(&core)
    } else {
        open_verified_core(&core)
    };
    match verified {
        Ok(verified) => CorePresence::Verified {
            version: verified.version,
        },
        Err(failure) => CorePresence::Unverified {
            installed,
            failure: Arc::new(failure),
        },
    }
}

/// Whether a managed core tree exists at all: the directory holds at least
/// one entry. An empty scaffold left by an interrupted transaction reads as
/// missing, not as a tree that failed verification.
fn tree_present(core: &Path) -> bool {
    fs::read_dir(core).is_ok_and(|mut entries| entries.next().is_some())
}

/// The release version the tree's own metadata names, without comparing it
/// to the compiled pins: a stale tree must still name what is installed.
/// `None` when the metadata file is absent or unreadable.
fn installed_release_version(core: &Path) -> Option<String> {
    let file = File::open(core.join(RELEASE_DIGEST_FILE)).ok()?;
    let metadata: OfficialReleaseMetadata = serde_json::from_reader(file).ok()?;
    Some(metadata.version)
}

/// Forget the cached presence result when one managed-core transaction leaves
/// scope.
///
/// Every transaction entry point constructs one before touching the tree, so
/// every outcome — success, failure, an early return, or an unwind out of the
/// write legs — forgets the cache. A failed transaction can leave the tree
/// partially modified (a rename or copy leg that failed midway, a quarantine
/// that was not restored), so a presence memo captured before it must never
/// outlive it. The next [`cached_core_presence`] verifies the final tree once.
struct PresenceInvalidation;

impl Drop for PresenceInvalidation {
    fn drop(&mut self) {
        invalidate_presence_cache();
    }
}

/// Forget a cached presence result as part of a managed-core transaction. The
/// next UI query verifies the final tree once. Private by design: callers
/// cannot hand-invalidate — the transaction that changes the tree owns the
/// invalidation through [`PresenceInvalidation`].
fn invalidate_presence_cache() {
    if let Ok(mut guard) = PRESENCE_CACHE.lock() {
        *guard = None;
    }
}

/// Return Broccoli's compile-time pinned Xray version, including its leading `v`.
pub fn pinned_release_version() -> &'static str {
    XRAY_VERSION
}

/// Return the compiled pin in the release metadata's spelling — no leading
/// `v` — so a surface that shows the installed and the required version side
/// by side reads as one pair.
pub fn pinned_core_version() -> &'static str {
    XRAY_VERSION.strip_prefix('v').unwrap_or(XRAY_VERSION)
}

/// Return Broccoli's compile-time pinned Xray archive asset name.
pub fn pinned_release_archive() -> &'static str {
    ZIP_ASSET
}

/// Return Broccoli's compile-time Xray release asset URL.
///
/// The URL is emitted into the binary from the release metadata and never
/// follows a moving GitHub release alias.
pub fn pinned_release_url() -> &'static str {
    concat!(
        "https://github.com/XTLS/Xray-core/releases/download/",
        env!("BROCCOLI_XRAY_VERSION"),
        "/",
        env!("BROCCOLI_XRAY_ARCHIVE")
    )
}

fn verify_pinned_archive(file: &Path, expected: &str) -> Result<(), DiagError> {
    if !is_sha256(expected) {
        return Err(DiagError::new(Diag::new(Key::CoreDlArchivePinInvalid)));
    }
    let actual = sha256_hex(file)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(DiagError::new(
            Diag::new(Key::CoreDlArchiveMismatch)
                .arg(expected)
                .arg(&actual),
        ));
    }
    Ok(())
}

/// RAII ownership of `download_core`'s unique staging directory. The tree is
/// removed when the guard drops, so an aborted download future cleans up just
/// like a completed or failed one. A missing directory is tolerated (removal
/// is a no-op), which makes double-drop and early failures safe.
#[must_use]
struct StagingGuard(PathBuf);

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Download and install the one stable Xray release compiled into this Broccoli
/// binary. Network metadata and same-channel digest sidecars never select or
/// authenticate code. The returned version has no leading `v`.
pub async fn download_core(
    client: &reqwest::Client,
    progress: impl Fn(u64, u64, &Diag) + Send,
) -> Result<String, DiagError> {
    let work = std::env::temp_dir().join(format!(
        "broccoli-core-dl-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&work)
        .diag_with(Diag::new(Key::CoreDlDirectoryCreateFailed).arg(work.display()))?;
    let zip_path = work.join(ZIP_ASSET);
    let _staging = StagingGuard::new(work);
    // Only the install transaction touches the managed tree, and it owns the
    // presence-cache invalidation; a download or pin-verify failure before it
    // leaves the tree unchanged, so the cached presence stays valid.
    async {
        stream_download(
            client,
            pinned_release_url(),
            &zip_path,
            &Diag::new(Key::CoreDlStageDownload),
            CORE_DOWNLOAD_MAX_BYTES,
            &progress,
        )
        .await?;
        progress(0, 0, &Diag::new(Key::CoreDlStageVerifyPin));
        verify_pinned_archive(&zip_path, ZIP_SHA256)?;
        progress(0, 0, &Diag::new(Key::CoreDlStageInstall));
        install_pinned_core_archive(&zip_path)
    }
    .await
}

/// Install an archive only after it matches Broccoli's compiled release pin.
/// Kept separate from network I/O so wrong-pin rejection is unit-testable.
pub fn install_pinned_core_archive(zip: &Path) -> Result<String, DiagError> {
    let _presence = PresenceInvalidation;
    verify_pinned_archive(zip, ZIP_SHA256)?;
    let root = broccoli_root();
    fs::create_dir_all(&root)
        .diag_with(Diag::new(Key::CoreDlDirectoryCreateFailed).arg(root.display()))?;
    recover_interrupted_swap(&root)?;
    ensure_no_pending_update(&root)?;
    let staging = unique_staging(&root, "release");
    let result = (|| -> Result<String, DiagError> {
        fs::create_dir_all(&staging)
            .diag_with(Diag::new(Key::CoreDlDirectoryCreateFailed).arg(staging.display()))?;
        extract_release_zip(zip, &staging)?;
        let xray_sha256 = sha256_hex(&staging.join("xray.exe"))?;
        let wintun_sha256 = sha256_hex(&staging.join("wintun.dll"))?;
        let geoip_sha256 = sha256_hex(&staging.join("geoip.dat"))?;
        let geosite_sha256 = sha256_hex(&staging.join("geosite.dat"))?;
        if !xray_sha256.eq_ignore_ascii_case(XRAY_EXE_SHA256)
            || !wintun_sha256.eq_ignore_ascii_case(WINTUN_SHA256)
            || !geoip_sha256.eq_ignore_ascii_case(GEOIP_SHA256)
            || !geosite_sha256.eq_ignore_ascii_case(GEOSITE_SHA256)
        {
            return Err(DiagError::new(Diag::new(
                Key::CoreDlArchivePayloadsMismatch,
            )));
        }
        // Seed the staging tree's pristine geo data pair before it is
        // committed, so the installed core carries pin-verified release
        // bytes matching its own release by construction. An upgrade
        // replaces the pair because each new tree seeds itself; a rollback
        // restores the old tree together with its matching pair.
        seed_pristine_from_tree(&staging)?;
        let version = pinned_banner_version()?;
        let metadata = OfficialReleaseMetadata {
            schema: METADATA_SCHEMA,
            archive_asset: ZIP_ASSET.to_string(),
            archive_sha256: ZIP_SHA256.to_string(),
            xray_sha256,
            wintun_sha256,
            geoip_sha256,
            geosite_sha256,
            version: version.clone(),
        };
        write_json_synced(&staging.join(RELEASE_DIGEST_FILE), &metadata)?;
        drop(open_verified_core_at(&staging, VerifyScope::Full)?);
        commit_staging(&root, &staging, |dir| {
            drop(open_verified_core_at(dir, VerifyScope::Full)?);
            Ok(())
        })?;
        Ok(version)
    })();
    if staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn unique_staging(root: &Path, purpose: &str) -> PathBuf {
    root.join(format!(
        ".core-{purpose}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ))
}

fn marker_path(root: &Path) -> PathBuf {
    root.join(SWAP_MARKER)
}

fn write_marker(root: &Path) -> Result<(), DiagError> {
    let path = marker_path(root);
    let mut file = File::create(&path)
        .diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(path.display()))?;
    file.write_all(b"broccoli-core-swap-v1\n")
        .diag_with(Diag::new(Key::CoreDlFileWriteFailed).arg(path.display()))?;
    file.sync_all()
        .diag_with(Diag::new(Key::CoreDlFileFlushFailed).arg(path.display()))
}

fn remove_marker(root: &Path) -> Result<(), DiagError> {
    let path = marker_path(root);
    if path.exists() {
        fs::remove_file(&path)
            .diag_with(Diag::new(Key::CoreDlFileRemoveFailed).arg(path.display()))?;
    }
    Ok(())
}

/// Recover every interrupted rename point. `core + core.bak + marker` is not
/// an interruption: it is a complete candidate awaiting runtime health ACK.
fn recover_interrupted_swap(root: &Path) -> Result<(), DiagError> {
    let _presence = PresenceInvalidation;
    let core = root.join("core");
    let backup = root.join("core.bak");
    let marker = marker_path(root);
    if core.exists() && !core.is_dir() {
        return Err(DiagError::new(Diag::new(Key::CoreDlCoreNotDirectory)));
    }
    if backup.exists() && !backup.is_dir() {
        return Err(DiagError::new(Diag::new(Key::CoreDlBackupNotDirectory)));
    }
    if marker.exists() {
        let valid = fs::read(&marker)
            .map(|bytes| bytes == b"broccoli-core-swap-v1\n")
            .unwrap_or(false);
        if !valid {
            if !core.exists() && backup.is_dir() {
                fs::rename(&backup, &core).diag(Key::CoreDlRecoverBackupFailed)?;
                remove_marker(root)?;
                return Ok(());
            }
            if core.is_dir() && !backup.exists() {
                // Marker creation tore before the first rename; live core was
                // never exposed to the transaction.
                remove_marker(root)?;
                return Ok(());
            }
            return Err(DiagError::new(Diag::new(Key::CoreDlMarkerCorrupt)));
        }
    }

    match (core.is_dir(), backup.is_dir()) {
        (false, true) => {
            fs::rename(&backup, &core).diag(Key::CoreDlRecoverInterruptedFailed)?;
            remove_marker(root)?;
        }
        (true, true) => {
            // Old builds could leave both directories without a marker. Adopt
            // the backup instead of deleting a potentially last-good tree.
            if !marker.exists() {
                write_marker(root)?;
            }
        }
        (true, false) => {
            // Crash before the first rename (or first install with no prior
            // core): the marker has no rollback object and is stale.
            remove_marker(root)?;
        }
        (false, false) => {
            if marker.exists() {
                remove_marker(root)?;
                return Err(DiagError::new(Diag::new(Key::CoreDlInterruptedWithoutCore)));
            }
        }
    }
    Ok(())
}

fn ensure_no_pending_update(root: &Path) -> Result<(), DiagError> {
    recover_interrupted_swap(root)?;
    if root.join("core.bak").is_dir() || marker_path(root).exists() {
        return Err(DiagError::new(Diag::new(Key::CoreDlUpdatePendingHealth)));
    }
    Ok(())
}

fn acknowledge_core_health_at(root: &Path) -> Result<(), DiagError> {
    let _presence = PresenceInvalidation;
    recover_interrupted_swap(root)?;
    let backup = root.join("core.bak");
    if backup.is_dir() {
        fs::remove_dir_all(&backup).diag(Key::CoreDlBackupRemoveFailed)?;
    }
    remove_marker(root)
}

fn rename_with_retry(
    source: &Path,
    destination: &Path,
    action: Key,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), DiagError> {
    for attempt in 0..ROLLBACK_RENAME_ATTEMPTS {
        match rename(source, destination) {
            Ok(()) => return Ok(()),
            Err(error)
                if error.kind() == ErrorKind::PermissionDenied
                    && attempt + 1 < ROLLBACK_RENAME_ATTEMPTS =>
            {
                thread::sleep(ROLLBACK_RENAME_RETRY_DELAY);
            }
            Err(error) => return Err(error).diag(action),
        }
    }
    unreachable!("every rollback rename retry iteration returns")
}

fn rollback_pending_update_with(
    root: &Path,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<bool, DiagError> {
    let _presence = PresenceInvalidation;
    recover_interrupted_swap(root)?;
    let core = root.join("core");
    let backup = root.join("core.bak");
    if !core.is_dir() || !backup.is_dir() || !marker_path(root).is_file() {
        return Ok(false);
    }
    let rejected = unique_staging(root, "rejected");
    rename_with_retry(&core, &rejected, Key::CoreDlQuarantineFailed, &mut rename)?;
    if let Err(error) = rename_with_retry(
        &backup,
        &core,
        Key::CoreDlRestoreLastgoodFailed,
        &mut rename,
    ) {
        let _ = rename_with_retry(
            &rejected,
            &core,
            Key::CoreDlRestoreCandidateFailed,
            &mut rename,
        );
        return Err(error);
    }
    let _ = fs::remove_dir_all(&rejected);
    remove_marker(root)?;
    Ok(true)
}

fn rollback_pending_update_at(root: &Path) -> Result<bool, DiagError> {
    rollback_pending_update_with(root, |source, destination| fs::rename(source, destination))
}
/// Replace `root/core` with a fully prepared sibling directory. There are no
/// await points in this commit window. Every error restores the old tree;
/// success retains it until [`acknowledge_core_health`].
fn commit_staging(
    root: &Path,
    staging: &Path,
    validate: impl Fn(&Path) -> Result<(), DiagError>,
) -> Result<(), DiagError> {
    if staging.parent() != Some(root) || !staging.is_dir() {
        return Err(DiagError::new(Diag::new(Key::CoreDlStagingMissing)));
    }
    ensure_no_pending_update(root)?;
    let core = root.join("core");
    let backup = root.join("core.bak");
    let had_old = core.is_dir();
    if had_old {
        write_marker(root)?;
        if let Err(error) = fs::rename(&core, &backup).diag(Key::CoreDlBackupStagingFailed) {
            let _ = remove_marker(root);
            return Err(error);
        }
    }
    if let Err(error) = fs::rename(staging, &core).diag(Key::CoreDlInstallFailed) {
        if had_old && fs::rename(&backup, &core).is_ok() {
            let _ = remove_marker(root);
        }
        return Err(error);
    }
    if let Err(error) = validate(&core) {
        let _ = fs::remove_dir_all(&core);
        if had_old {
            fs::rename(&backup, &core).diag(Key::CoreDlRestoreAfterValidationFailed)?;
            remove_marker(root)?;
        }
        return Err(error);
    }
    Ok(())
}

/// Name of the directory under a managed core tree that holds the
/// pin-verified pristine geo data pair.
///
/// Verification never lists the tree exhaustively — it names the metadata
/// and payload paths — and the elevated helper stage copies only named root
/// payloads, so `pristine/` is invisible to both and never reaches the
/// helper's runtime directory. It lives inside the core directory, so
/// reset-to-default keeps it exactly where the managed core survives.
const PRISTINE_DIR: &str = "pristine";

/// The geo data payloads retained as the pin-verified pristine pair, in
/// verification order (`geoip.dat` first, so a corrupt pair is reported on
/// geoip). Mirrors the DAT entries of [`RUNTIME_PAYLOAD_PINS`].
const GEO_DATA_PAIR: [(&str, &str); 2] =
    [("geoip.dat", GEOIP_SHA256), ("geosite.dat", GEOSITE_SHA256)];

/// True when `path` exists as an ordinary file: a real file, not a
/// directory and not a reparse point (which on Windows covers symlinks and
/// junctions). Pristine data gets the same shape check the strict verify
/// applies to managed payloads, so a planted reparse point can never steer
/// a restore read or a seeding decision elsewhere.
fn is_ordinary_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 && metadata.is_file()
        })
        .unwrap_or(false)
}

/// Copy the verified release geo data of `tree` into `tree/pristine` and
/// prove each copy byte-identical to the compiled release pins.
///
/// Called on the staging tree right after its four payload hashes pass and
/// before commit, so every committed core carries a pristine pair matching
/// its own release by construction: an upgrade replaces it (each new tree
/// seeds itself) and a rollback restores the old tree together with its
/// matching pair. On any failure the partially created `pristine/`
/// directory is removed before the error returns, so a broken seed can
/// never masquerade as a valid pair.
fn seed_pristine_from_tree(tree: &Path) -> Result<(), DiagError> {
    let pristine_dir = tree.join(PRISTINE_DIR);
    let result = (|| -> Result<(), DiagError> {
        fs::create_dir_all(&pristine_dir)
            .diag_with(Diag::new(Key::CoreDlDirectoryCreateFailed).arg(pristine_dir.display()))?;
        for (payload, expected) in GEO_DATA_PAIR {
            let source = tree.join(payload);
            let target = pristine_dir.join(payload);
            let mut input = File::open(&source)
                .diag_with(Diag::new(Key::CoreDlFileOpenFailed).arg(source.display()))?;
            let mut output = File::create(&target)
                .diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(target.display()))?;
            std::io::copy(&mut input, &mut output).diag_with(
                Diag::new(Key::CoreDlPristineCopyFailed)
                    .arg(source.display())
                    .arg(target.display()),
            )?;
            output
                .sync_all()
                .diag_with(Diag::new(Key::CoreDlFileFlushFailed).arg(target.display()))?;
            drop(output);
            let actual = sha256_hex(&target)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlPristineMismatch)
                        .arg(payload)
                        .arg(expected)
                        .arg(&actual),
                ));
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&pristine_dir);
    }
    result
}

/// True when every managed geo data payload of `core` hashes to its
/// compiled release pin. A payload that is missing, locked, or unreadable
/// does not match — it is never captured as pristine.
fn managed_geo_data_matches_pins(core: &Path) -> bool {
    GEO_DATA_PAIR.iter().all(|(payload, expected)| {
        sha256_hex(&core.join(payload)).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

/// Replace the managed geo data of the core at `core` with its retained
/// pristine pair, after proving every pristine file against the compiled
/// release pins.
///
/// Safe to call at any time and idempotent:
/// - a missing pair — or a pair member that is not an ordinary file — bails
///   with an error naming the file and saying restore is unavailable (a
///   future change turns this into a terminal-with-reason path);
/// - a pair member whose bytes do not match its compiled pin bails naming
///   the file and both hashes, before any managed file is touched;
/// - managed DATs that already match the pins are a no-op;
/// - otherwise each managed file is replaced atomically: bytes are
///   streamed into a uniquely named sibling temp file, flushed, then
///   renamed over the managed name (Windows `MOVEFILE_REPLACE_EXISTING`,
///   the repo's rename semantics), so there is never a window where the
///   managed file is missing. The temp file is removed on failure. When a
///   running core holds deny-write handles, the rename fails with a
///   sharing violation, which propagates for the UI to surface.
///
/// A transaction invalidates the presence cache on every return path — the
/// already-pinned no-op, a failed restore that may have replaced one file
/// before the other failed, and full success — so the next UI query
/// verifies the final tree once.
pub fn restore_pristine_geo_data(core: &Path) -> Result<(), DiagError> {
    let _presence = PresenceInvalidation;
    let pristine_dir = core.join(PRISTINE_DIR);
    for (payload, expected) in GEO_DATA_PAIR {
        let source = pristine_dir.join(payload);
        if !is_ordinary_file(&source) {
            return Err(DiagError::new(
                Diag::new(Key::CoreDlRestoreUnavailable).arg(source.display()),
            ));
        }
        let actual = sha256_hex(&source)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(DiagError::new(
                Diag::new(Key::CoreDlPristineMismatch)
                    .arg(payload)
                    .arg(expected)
                    .arg(&actual),
            ));
        }
    }
    if managed_geo_data_matches_pins(core) {
        return Ok(());
    }
    for (payload, _) in GEO_DATA_PAIR {
        let source = pristine_dir.join(payload);
        let managed = core.join(payload);
        let temp = core.join(format!(
            "{payload}.restore-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result = (|| -> Result<(), DiagError> {
            let mut input = File::open(&source)
                .diag_with(Diag::new(Key::CoreDlFileOpenFailed).arg(source.display()))?;
            let mut output = File::create(&temp)
                .diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(temp.display()))?;
            std::io::copy(&mut input, &mut output)
                .diag_with(Diag::new(Key::CoreDlFileCopyFailed).arg(temp.display()))?;
            output
                .sync_all()
                .diag_with(Diag::new(Key::CoreDlFileFlushFailed).arg(temp.display()))?;
            fs::rename(&temp, &managed).diag_with(
                Diag::new(Key::CoreDlFileReplaceFailed)
                    .arg(managed.display())
                    .arg(source.display()),
            )
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
            return result;
        }
    }
    Ok(())
}

/// Whether the managed geo data of a core matches the compiled release pins:
/// the provenance vocabulary, decided by hashing the on-disk
/// bytes (never by persisted state — there is none for provenance).
///
/// Pure query semantics: no writes, no presence-cache invalidation, no
/// locks retained past the call — safe to run off the UI thread at any
/// time, including while the core runs (the reads share the files the same
/// way verification's hash pass does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoDataProvenance {
    /// Both geo data files hash to the compiled release pins: the geo data
    /// is release-managed and release verification applies.
    ReleaseManaged,
    /// At least one file differs from its pin — replaced, missing, or
    /// unreadable. Hashing alone cannot tell drift apart from a missing or
    /// locked file (verification reports absent files separately), so any
    /// non-matching pair is user-managed state. Carries the newest of the
    /// two files' modification times as the visible update time; a file
    /// that is missing or unreadable contributes no stat, so `None` when
    /// neither file yields one.
    UserManaged { updated: Option<SystemTime> },
    /// The core directory itself is absent (or not a directory): there is
    /// no managed geo data to provenance or restore.
    NoCore,
}

/// Query the [`GeoDataProvenance`] of the managed core at `core`.
///
/// Each payload's bytes are compared against its compiled pin exactly like
/// the strict verification compares ([`managed_geo_data_matches_pins`]
/// shape), and the newest modification time of the two files is captured
/// for the user-managed update time regardless of hash outcome, so a
/// drifted file that is locked against reads still reports when it was
/// changed. A missing core directory answers [`GeoDataProvenance::NoCore`]
/// without touching the filesystem further.
pub fn geo_data_provenance(core: &Path) -> GeoDataProvenance {
    if !core.is_dir() {
        return GeoDataProvenance::NoCore;
    }
    let mut release_managed = true;
    let mut updated: Option<SystemTime> = None;
    for (payload, expected) in GEO_DATA_PAIR {
        let path = core.join(payload);
        release_managed = release_managed
            && sha256_hex(&path).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected));
        if let Ok(metadata) = fs::metadata(&path)
            && let Ok(modified) = metadata.modified()
        {
            updated = Some(updated.map_or(modified, |newest| newest.max(modified)));
        }
    }
    if release_managed {
        GeoDataProvenance::ReleaseManaged
    } else {
        GeoDataProvenance::UserManaged { updated }
    }
}

/// Run one blocking file operation off the async worker under the shared
/// download deadline. The file travels into the blocking task and back so
/// every chunk keeps the same handle; the deadline wraps the whole await, so
/// a stalled disk surfaces as the download timeout and task abort never
/// waits for the syscall to finish.
async fn deadline_disk_io(
    deadline: tokio::time::Instant,
    url: &str,
    dest: &Path,
    operation: Key,
    mut file: File,
    op: impl FnOnce(&mut File) -> std::io::Result<()> + Send + 'static,
) -> Result<File, DiagError> {
    let (result, file) = tokio::time::timeout_at(
        deadline,
        tokio::task::spawn_blocking(move || {
            let result = op(&mut file);
            (result, file)
        }),
    )
    .await
    .diag_with(
        Diag::new(Key::CoreDlDownloadTimeout)
            .arg(url)
            .arg(DOWNLOAD_TIMEOUT.as_secs()),
    )?
    .diag_with(Diag::new(operation).arg(dest.display()))?;
    result.diag_with(Diag::new(operation).arg(dest.display()))?;
    Ok(file)
}

/// Stream one pinned asset with hard request, size, and wall-clock limits.
/// A failed or oversized response never leaves a partial file behind.
///
/// Chunk writes and the final flush run on tokio's blocking pool, each
/// bounded by the same download deadline as the network reads: a stalled
/// disk surfaces as a download timeout instead of holding the async worker,
/// and aborting the download future never waits for an in-flight syscall.
async fn stream_download(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    stage: &Diag,
    max_bytes: u64,
    progress: &(impl Fn(u64, u64, &Diag) + Send),
) -> Result<(), DiagError> {
    let result = async {
        let mut response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, user_agent())
            .timeout(DOWNLOAD_TIMEOUT)
            .send()
            .await
            .diag_with(Diag::new(Key::CoreDlHttpRequestFailed).arg(url))?
            .error_for_status()
            .diag_with(Diag::new(Key::CoreDlHttpStatusRejected).arg(url))?;
        let total = response.content_length().unwrap_or(0);
        if total > max_bytes {
            return Err(DiagError::new(
                Diag::new(Key::CoreDlDownloadTooLarge)
                    .arg(url)
                    .arg(total)
                    .arg(max_bytes),
            ));
        }
        let mut file = fs::File::create(dest)
            .diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(dest.display()))?;
        progress(0, total, stage);
        let deadline = tokio::time::Instant::now() + DOWNLOAD_TIMEOUT;
        let mut done = 0_u64;
        loop {
            let chunk = tokio::time::timeout_at(deadline, response.chunk())
                .await
                .diag_with(
                    Diag::new(Key::CoreDlDownloadTimeout)
                        .arg(url)
                        .arg(DOWNLOAD_TIMEOUT.as_secs()),
                )?
                .diag(Key::CoreDlDownloadStreamFailed)?;
            let Some(chunk) = chunk else {
                break;
            };
            done = done
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| DiagError::new(Diag::new(Key::CoreDlDownloadSizeOverflow)))?;
            if done > max_bytes {
                return Err(DiagError::new(
                    Diag::new(Key::CoreDlDownloadLimitExceeded)
                        .arg(url)
                        .arg(max_bytes),
                ));
            }
            file = deadline_disk_io(
                deadline,
                url,
                dest,
                Key::CoreDlDownloadWriteFailed,
                file,
                move |writer| writer.write_all(&chunk),
            )
            .await?;
            progress(done, total, stage);
        }
        deadline_disk_io(
            deadline,
            url,
            dest,
            Key::CoreDlDownloadFlushFailed,
            file,
            |writer| writer.sync_all(),
        )
        .await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(dest);
    }
    result
}

fn sha256_reader(reader: &mut impl std::io::Read) -> Result<String, DiagError> {
    let mut hasher = Sha256::new();
    // digest 0.11 dropped the `io::Write` impl this used to hash through, so
    // the bytes are fed explicitly. The buffer is heap-allocated to keep the
    // 64 KiB off the stack, as in the helper's `sha256_handle`.
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).diag(Key::CoreDlHashingFailed)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}

/// sha256 of `file` as lowercase hex.
fn sha256_hex(file: &Path) -> Result<String, DiagError> {
    let mut file =
        File::open(file).diag_with(Diag::new(Key::CoreDlFileOpenFailed).arg(file.display()))?;
    sha256_reader(&mut file)
}

fn write_json_synced<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), DiagError> {
    let encoded = serde_json::to_vec_pretty(value).diag(Key::CoreDlMetadataSerializeFailed)?;
    let mut file =
        File::create(path).diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(path.display()))?;
    file.write_all(&encoded)
        .diag_with(Diag::new(Key::CoreDlFileWriteFailed).arg(path.display()))?;
    file.sync_all()
        .diag_with(Diag::new(Key::CoreDlFileFlushFailed).arg(path.display()))
}

/// Extract whitelisted files from the release zip into `dest` (flat).
/// `enclosed_name()` drops any entry with `..`/absolute components.
fn extract_release_zip(zip_path: &Path, dest: &Path) -> Result<(), DiagError> {
    let file = fs::File::open(zip_path)
        .diag_with(Diag::new(Key::CoreDlArchiveOpenFailed).arg(zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file).diag(Key::CoreDlArchiveInvalid)?;
    let mut found_exe = false;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .diag_with(Diag::new(Key::CoreDlArchiveEntryUnreadable).arg(i))?;
        if !entry.is_file() {
            continue;
        }
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !KEEP.contains(&name) {
            continue;
        }
        let out = dest.join(name);
        let mut w = fs::File::create(&out)
            .diag_with(Diag::new(Key::CoreDlFileCreateFailed).arg(out.display()))?;
        std::io::copy(&mut entry, &mut w)
            .diag_with(Diag::new(Key::CoreDlArchiveExtractFailed).arg(name))?;
        w.sync_all()
            .diag_with(Diag::new(Key::CoreDlFileFlushFailed).arg(out.display()))?;
        if name == "xray.exe" {
            found_exe = true;
        }
    }
    if !found_exe {
        return Err(DiagError::new(Diag::new(Key::CoreDlArchiveMissingXray)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{
        Diag, DiagError, GEOIP_SHA256, GEOSITE_SHA256, METADATA_SCHEMA, OfficialReleaseMetadata,
        VerifyScope, WINTUN_SHA256, XRAY_EXE_SHA256, XRAY_VERSION, ZIP_ASSET, ZIP_SHA256,
        acknowledge_core_health_at, commit_staging, deadline_disk_io, install_pinned_core_archive,
        marker_path, metadata_matches_compiled_pins, pinned_banner_version, pinned_release_archive,
        pinned_release_url, pinned_release_version, recover_interrupted_swap,
        rollback_pending_update_at, unique_staging, write_marker,
    };
    use crate::i18n::Key;
    use crate::model::settings::Language;
    use crate::sys::appdata::APPDATA_ENV_LOCK;

    fn tree(root: &Path, name: &str, sentinel: &[u8]) {
        let directory = root.join(name);
        fs::create_dir_all(&directory).expect("create transaction fixture");
        fs::write(directory.join("sentinel"), sentinel).expect("write transaction sentinel");
    }

    #[test]
    fn completed_swap_retains_last_good_until_health_ack() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        tree(root, "core", b"old");
        tree(root, ".core-test", b"new");
        let staging = root.join(".core-test");
        commit_staging(root, &staging, |_| Ok(())).expect("commit candidate");
        assert_eq!(fs::read(root.join("core/sentinel")).unwrap(), b"new");
        assert_eq!(fs::read(root.join("core.bak/sentinel")).unwrap(), b"old");
        assert!(marker_path(root).is_file());
        acknowledge_core_health_at(root).expect("acknowledge candidate");
        assert!(!root.join("core.bak").exists());
        assert!(!marker_path(root).exists());
    }

    #[test]
    fn interrupted_old_rename_restores_backup_on_recovery() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        tree(root, "core.bak", b"last-good");
        write_marker(root).expect("write transaction marker");
        recover_interrupted_swap(root).expect("recover interrupted rename");
        assert_eq!(fs::read(root.join("core/sentinel")).unwrap(), b"last-good");
        assert!(!root.join("core.bak").exists());
        assert!(!marker_path(root).exists());
    }

    #[test]
    fn failed_post_swap_validation_restores_old_tree() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        tree(root, "core", b"old");
        tree(root, ".core-invalid", b"bad");
        let staging = root.join(".core-invalid");
        let error = commit_staging(root, &staging, |_| {
            Err(DiagError::new(Diag::new(Key::CoreDlInstallFailed)))
        })
        .expect_err("validation must fail");
        assert_eq!(error.diag().key(), Key::CoreDlInstallFailed);
        assert_eq!(fs::read(root.join("core/sentinel")).unwrap(), b"old");
        assert!(!root.join("core.bak").exists());
        assert!(!marker_path(root).exists());
    }

    #[test]
    fn unhealthy_candidate_rolls_back_retained_tree_once() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        tree(root, "core", b"old");
        tree(root, ".core-candidate", b"new");
        let staging = root.join(".core-candidate");
        commit_staging(root, &staging, |_| Ok(())).expect("commit candidate");

        assert!(rollback_pending_update_at(root).expect("rollback candidate"));
        assert_eq!(fs::read(root.join("core/sentinel")).unwrap(), b"old");
        assert!(!rollback_pending_update_at(root).expect("second rollback"));
    }

    #[test]
    fn rollback_retries_candidate_quarantine_after_transient_access_denied() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        tree(root, "core", b"old");
        tree(root, ".core-candidate", b"new");
        let staging = root.join(".core-candidate");
        commit_staging(root, &staging, |_| Ok(())).expect("commit candidate");

        let attempts = std::cell::Cell::new(0);
        assert!(
            super::rollback_pending_update_with(root, |source, destination| {
                if source.file_name().and_then(|name| name.to_str()) == Some("core")
                    && attempts.replace(attempts.get() + 1) == 0
                {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                } else {
                    fs::rename(source, destination)
                }
            })
            .expect("transient candidate handle denial must roll back")
        );

        assert_eq!(attempts.get(), 2);
        assert_eq!(fs::read(root.join("core/sentinel")).unwrap(), b"old");
        assert!(!root.join("core.bak").exists());
        assert!(!marker_path(root).exists());
    }

    fn compiled_metadata() -> OfficialReleaseMetadata {
        OfficialReleaseMetadata {
            schema: METADATA_SCHEMA,
            archive_asset: ZIP_ASSET.to_string(),
            archive_sha256: ZIP_SHA256.to_string(),
            xray_sha256: XRAY_EXE_SHA256.to_string(),
            wintun_sha256: WINTUN_SHA256.to_string(),
            geoip_sha256: GEOIP_SHA256.to_string(),
            geosite_sha256: GEOSITE_SHA256.to_string(),
            version: pinned_banner_version().expect("compiled Xray version"),
        }
    }

    #[test]
    fn managed_metadata_requires_every_compiled_identity_pin() {
        let expected_version = pinned_banner_version().expect("compiled Xray version");
        assert!(metadata_matches_compiled_pins(
            &compiled_metadata(),
            &expected_version
        ));
        for field in [
            "schema",
            "archive",
            "archive_sha256",
            "xray_sha256",
            "wintun_sha256",
            "geoip_sha256",
            "geosite_sha256",
            "version",
        ] {
            let mut metadata = compiled_metadata();
            match field {
                "schema" => metadata.schema = METADATA_SCHEMA - 1,
                "archive" => metadata.archive_asset = "foreign.zip".to_owned(),
                "archive_sha256" => metadata.archive_sha256 = "0".repeat(64),
                "xray_sha256" => metadata.xray_sha256 = "0".repeat(64),
                "wintun_sha256" => metadata.wintun_sha256 = "0".repeat(64),
                "geoip_sha256" => metadata.geoip_sha256 = "0".repeat(64),
                "geosite_sha256" => metadata.geosite_sha256 = "0".repeat(64),
                "version" => metadata.version = "0.0.0".to_owned(),
                _ => unreachable!(),
            }
            assert!(
                !metadata_matches_compiled_pins(&metadata, &expected_version),
                "{field} mismatch must reject the managed core"
            );
        }
    }

    #[test]
    fn full_verify_scope_covers_every_runtime_payload() {
        let pins = VerifyScope::Full.payload_pins();
        assert_eq!(
            pins.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"]
        );
        assert_eq!(pins[0].1, XRAY_EXE_SHA256);
        assert_eq!(pins[1].1, WINTUN_SHA256);
        assert_eq!(pins[2].1, GEOIP_SHA256);
        assert_eq!(pins[3].1, GEOSITE_SHA256);
    }

    #[test]
    fn probe_verify_scope_hashes_only_the_executable() {
        // The latency-probe child executes only xray.exe, so its spawn verify
        // must hash exactly that one payload — never wintun.dll or the
        // geodata DATs.
        let pins = VerifyScope::XrayExeOnly.payload_pins();
        assert_eq!(pins.len(), 1, "probe verify must hash exactly one payload");
        assert_eq!(pins[0].0, "xray.exe");
        assert_eq!(pins[0].1, XRAY_EXE_SHA256);
    }

    #[test]
    fn core_release_url_and_archive_trust_are_compiled_pins() {
        assert_eq!(pinned_release_version(), XRAY_VERSION);
        assert_eq!(pinned_release_archive(), ZIP_ASSET);
        assert_eq!(
            pinned_release_url(),
            format!(
                "https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/{ZIP_ASSET}"
            )
        );
        let temporary = tempfile::tempdir().expect("temporary root");
        let archive = temporary.path().join("renamed-selection.zip");
        fs::write(&archive, b"not the pinned Xray release").expect("write wrong archive");
        // APPDATA is process-global: serialize against tests that redirect it
        // so `broccoli_root()` stays stable across the two existence checks.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let managed_root = super::broccoli_root();
        let root_existed = managed_root.exists();
        let error =
            install_pinned_core_archive(&archive).expect_err("wrong archive must not be trusted");
        assert_eq!(error.diag().key(), Key::CoreDlArchiveMismatch);
        assert!(
            error.text(Language::En).contains("SHA-256 pin"),
            "the rejection must name the failed pin: {}",
            error.text(Language::En)
        );
        assert_eq!(
            managed_root.exists(),
            root_existed,
            "archive rejection must precede managed-root creation"
        );
    }

    #[test]
    fn staging_names_are_unique_siblings() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let first = unique_staging(temporary.path(), "release");
        let second = unique_staging(temporary.path(), "release");
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(temporary.path()));
        assert_eq!(second.parent(), Some(temporary.path()));
    }

    /// Seed the process-global presence cache with a stale entry for `root`.
    fn seed_presence_cache(root: std::path::PathBuf) {
        let mut guard = super::PRESENCE_CACHE.lock().expect("presence cache lock");
        *guard = Some(super::PresenceCache {
            checked_at: std::time::SystemTime::now(),
            root,
            dat_pins_suspended: false,
            presence: super::CorePresence::Verified {
                version: "stale-version".into(),
            },
        });
    }

    fn presence_cache_is_forgotten() -> bool {
        super::PRESENCE_CACHE
            .lock()
            .expect("presence cache lock")
            .is_none()
    }

    #[test]
    fn presence_memo_answers_only_the_mode_that_filled_it() {
        // The strict entry heals a drifted geo data pair while the suspended
        // entry accepts the same pair as user-managed state, so a memo may be
        // reused only by a query in the mode that produced it; otherwise the
        // query re-verifies instead of serving the other mode's answer.
        let root = std::path::PathBuf::from(r"C:\broccoli-presence-fixture");
        let memo = |dat_pins_suspended: bool| super::PresenceCache {
            checked_at: std::time::SystemTime::now(),
            root: root.clone(),
            dat_pins_suspended,
            presence: super::CorePresence::Verified {
                version: "v0.0.0".into(),
            },
        };
        assert!(memo(false).answers(&root, false));
        assert!(memo(true).answers(&root, true));
        assert!(
            !memo(false).answers(&root, true),
            "a strict memo must not answer a suspended query"
        );
        assert!(
            !memo(true).answers(&root, false),
            "a suspended memo must not answer a strict query"
        );
        assert!(
            !memo(false).answers(&root.join("core"), false),
            "another root must re-verify"
        );
        let expired = super::PresenceCache {
            checked_at: std::time::SystemTime::now() - super::PRESENCE_CACHE_TTL * 2,
            ..memo(false)
        };
        assert!(
            !expired.answers(&root, false),
            "an expired memo must re-verify"
        );
    }

    #[test]
    fn presence_reports_an_absent_or_empty_tree_as_missing() {
        crate::sys::appdata::with_appdata(|| {
            assert!(
                matches!(
                    super::cached_core_presence(false),
                    super::CorePresence::Missing
                ),
                "an absent core directory must read as missing"
            );
            fs::create_dir_all(super::core_dir()).expect("create an empty core scaffold");
            assert!(
                matches!(
                    super::verify_core_presence(false),
                    super::CorePresence::Missing
                ),
                "an empty scaffold must read as missing, not as a tree that failed verification"
            );
        });
    }

    #[test]
    fn presence_reports_a_stale_tree_with_the_installed_version_and_reason() {
        // A tree written by another build must read as unverified with the
        // version its own metadata names: the core setup surface reports
        // "installed X, this build needs Y" from exactly these facts.
        crate::sys::appdata::with_appdata(|| {
            let core = super::core_dir();
            fs::create_dir_all(&core).expect("create the core directory");
            // The verification shape-checks every payload path before it
            // compares the release metadata: a tree with missing payload files
            // fails there instead of naming the pin mismatch this test is
            // about.
            for payload in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
                fs::write(core.join(payload), b"another build's payload")
                    .expect("write a stale payload");
            }
            let metadata = serde_json::json!({
                "schema": super::METADATA_SCHEMA,
                "archive_asset": super::ZIP_ASSET,
                "archive_sha256": super::ZIP_SHA256,
                "xray_sha256": super::XRAY_EXE_SHA256,
                "wintun_sha256": super::WINTUN_SHA256,
                "geoip_sha256": super::GEOIP_SHA256,
                "geosite_sha256": super::GEOSITE_SHA256,
                "version": "26.7.28",
            });
            fs::write(
                core.join(super::RELEASE_DIGEST_FILE),
                serde_json::to_vec(&metadata).expect("serialize the release metadata"),
            )
            .expect("write the release metadata");

            match super::verify_core_presence(false) {
                super::CorePresence::Unverified { installed, failure } => {
                    assert_eq!(
                        installed.as_deref(),
                        Some("26.7.28"),
                        "a stale tree must name the version its metadata carries"
                    );
                    assert_eq!(
                        failure.diag().key(),
                        Key::CoreDlMetadataMismatch,
                        "the reason must be the pin comparison's own error"
                    );
                }
                _ => panic!("a tree written by another build must read as unverified"),
            }
        });
    }

    #[test]
    fn managed_core_transactions_own_the_presence_cache_invalidation() {
        // No call site hand-invalidates: the transaction run against the tree
        // forgets the cache itself, so a memo captured before it can never
        // outlive it — on an early return, and on a failure that may have left
        // the tree partially modified, not just on the happy path.
        crate::sys::appdata::with_appdata(|| {
            // Early return: an empty root has nothing to recover.
            seed_presence_cache(super::broccoli_root());
            super::recover_installation().expect("an empty root has nothing to recover");
            assert!(
                presence_cache_is_forgotten(),
                "an early-returning recovery must forget the cached presence"
            );

            // Failure: `core` exists but is not a directory, so the
            // transaction refuses the tree after the cache was refreshed.
            let root = super::broccoli_root();
            fs::create_dir_all(&root).expect("create app-data root");
            fs::write(root.join("core"), b"not a directory").expect("write non-directory core");
            seed_presence_cache(root.clone());
            assert!(
                super::recover_installation().is_err(),
                "a non-directory core must fail recovery"
            );
            assert!(
                presence_cache_is_forgotten(),
                "a failed recovery must forget the cached presence"
            );

            // Failure inside a path-taking transaction: the pristine pair is
            // absent, so restore bails before touching anything.
            seed_presence_cache(root.clone());
            assert!(
                super::restore_pristine_geo_data(&root.join("core")).is_err(),
                "a missing pristine pair must refuse the restore"
            );
            assert!(
                presence_cache_is_forgotten(),
                "a refused restore must forget the cached presence"
            );
        });
    }

    #[tokio::test]
    async fn stalled_disk_operation_surfaces_as_the_download_deadline() {
        // The download deadline must bound the disk leg too: a write that
        // hangs on the blocking pool surfaces as the timeout instead of
        // holding the async worker, and the caller never waits for the
        // syscall to finish.
        let temporary = tempfile::tempdir().expect("temporary root");
        let dest = temporary.path().join("stalled-disk.bin");
        let file = fs::File::create(&dest).expect("create stalled file");
        let started = std::time::Instant::now();
        let error = deadline_disk_io(
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(50),
            "https://example.invalid/xray.zip",
            &dest,
            Key::CoreDlDownloadWriteFailed,
            file,
            |_writer| {
                std::thread::sleep(std::time::Duration::from_secs(2));
                Ok(())
            },
        )
        .await
        .expect_err("a stalled disk operation must fail the download deadline");
        assert_eq!(error.diag().key(), Key::CoreDlDownloadTimeout);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the caller must not wait for the stalled syscall"
        );
    }

    #[test]
    fn staging_guard_removes_tree_on_drop() {
        // A completed or failed download both end the guarded scope; the tree,
        // partial zip included, must be gone either way.
        let temporary = tempfile::tempdir().expect("temporary root");
        let dir = temporary.path().join("broccoli-core-dl-dropped");
        fs::create_dir_all(&dir).expect("create staged directory");
        fs::write(dir.join(ZIP_ASSET), b"partial download").expect("write partial zip");
        {
            let _guard = super::StagingGuard::new(dir.clone());
            assert!(
                dir.exists(),
                "staging tree must exist while the guard is alive"
            );
        }
        assert!(
            !dir.exists(),
            "dropping the guard must remove the staging tree"
        );
    }

    #[test]
    fn staging_guard_drop_tolerates_missing_directory() {
        // A dir that was never created, and a second drop over an already
        // removed path, are both no-ops: cleanup never panics.
        let temporary = tempfile::tempdir().expect("temporary root");
        let dir = temporary.path().join("broccoli-core-dl-never-created");
        drop(super::StagingGuard::new(dir.clone()));
        assert!(!dir.exists());
        drop(super::StagingGuard::new(dir));
    }

    #[tokio::test]
    async fn aborted_download_future_removes_staging_dir() {
        // Abort mid-flight (the CoreCmd::Stop / shutdown path): the staging
        // dir plus partial zip must not survive the dropped future.
        let temporary = tempfile::tempdir().expect("temporary root");
        let dir = temporary.path().join("broccoli-core-dl-aborted");
        fs::create_dir_all(&dir).expect("create staged directory");
        fs::write(dir.join(ZIP_ASSET), b"partial download").expect("write partial zip");
        let staged = dir.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _guard = super::StagingGuard::new(staged);
            started_tx
                .send(())
                .expect("staging task receiver must be alive");
            // Stand-in for the in-flight download: never completes on its own.
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });
        started_rx.await.expect("staging task must start");
        handle.abort();
        handle
            .await
            .expect_err("aborted task must not complete normally");
        assert!(
            !dir.exists(),
            "aborting the download task must remove its staging dir"
        );
    }

    #[tokio::test]
    async fn aborted_download_with_open_partial_file_removes_staging_dir() {
        // The worst Windows case: the abort lands while stream_download still
        // holds the partial zip open. The handle drops with the future, and
        // the guard's removal must then succeed.
        let temporary = tempfile::tempdir().expect("temporary root");
        let dir = temporary.path().join("broccoli-core-dl-aborted-open");
        fs::create_dir_all(&dir).expect("create staged directory");
        let staged = dir.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let partial = staged.join(ZIP_ASSET);
            let _guard = super::StagingGuard::new(staged);
            let _file = fs::File::create(&partial).expect("create partial zip");
            started_tx
                .send(())
                .expect("staging task receiver must be alive");
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });
        started_rx.await.expect("staging task must start");
        handle.abort();
        handle
            .await
            .expect_err("aborted task must not complete normally");
        assert!(
            !dir.exists(),
            "aborting the download task must remove its staging dir even with an open partial file"
        );
    }
}

#[cfg(test)]
mod pristine_tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        GEOIP_SHA256, GEOSITE_SHA256, PRISTINE_DIR, open_verified_core, restore_pristine_geo_data,
        seed_pristine_from_tree, sha256_hex,
    };
    use crate::i18n::{Key, t_fmt};
    use crate::model::settings::Language;
    use crate::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect};

    const DRIFTED_GEOIP: &[u8] = b"drifted geoip bytes";
    const DRIFTED_GEOSITE: &[u8] = b"drifted geosite bytes";

    /// A managed core fixture whose DATs are drifted bytes that cannot match
    /// any compiled pin.
    fn drifted_core(root: &Path) -> PathBuf {
        let core = root.join("core");
        fs::create_dir_all(&core).expect("create fixture core dir");
        fs::write(core.join("geoip.dat"), DRIFTED_GEOIP).expect("write drifted geoip");
        fs::write(core.join("geosite.dat"), DRIFTED_GEOSITE).expect("write drifted geosite");
        core
    }

    /// Create the pristine pair directory and return its two file paths.
    fn pristine_pair(core: &Path) -> (PathBuf, PathBuf) {
        let dir = core.join(PRISTINE_DIR);
        fs::create_dir_all(&dir).expect("create fixture pristine dir");
        (dir.join("geoip.dat"), dir.join("geosite.dat"))
    }

    /// Build the pristine pair from the copied core's own managed bytes —
    /// pin-matching because the clone is the real installed core. Retention
    /// happens only inside the install funnel for release trees, so tests
    /// that need a pair on a clone construct it directly.
    fn pristine_from_managed(core: &Path) {
        let (geoip, geosite) = pristine_pair(core);
        fs::copy(core.join("geoip.dat"), geoip).expect("seed pristine geoip from managed bytes");
        fs::copy(core.join("geosite.dat"), geosite)
            .expect("seed pristine geosite from managed bytes");
    }

    #[test]
    fn restore_without_pristine_pair_bails_naming_the_missing_file() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = drifted_core(temporary.path());
        let error = restore_pristine_geo_data(&core).expect_err("missing pair must refuse");
        assert_eq!(error.diag().key(), Key::CoreDlRestoreUnavailable);
        let missing = core.join(PRISTINE_DIR).join("geoip.dat");
        let missing = missing.display().to_string();
        let message = error.text(Language::En);
        assert!(
            message.contains("geoip.dat"),
            "the error must name the missing pristine file: {message}"
        );
        assert_eq!(
            message,
            t_fmt(Language::En, Key::CoreDlRestoreUnavailable, &[&missing]),
            "the refusal must render the keyed sentence with the missing path"
        );
        assert_eq!(
            fs::read(core.join("geoip.dat")).unwrap(),
            DRIFTED_GEOIP,
            "managed geo data must be untouched by a refused restore"
        );
        assert_eq!(
            fs::read(core.join("geosite.dat")).unwrap(),
            DRIFTED_GEOSITE,
            "managed geo data must be untouched by a refused restore"
        );
    }

    #[test]
    fn restore_refuses_tampered_pristine_before_touching_managed_files() {
        // Tampered pristine must be reported (naming the file and both
        // hashes) even though the managed DATs are drifted too: pristine
        // validation precedes any managed write, so a corrupt pair can never
        // be copied over the managed files.
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = drifted_core(temporary.path());
        let (pristine_geoip, pristine_geosite) = pristine_pair(&core);
        fs::write(&pristine_geoip, b"tampered pristine geoip").expect("tamper geoip pair member");
        fs::write(&pristine_geosite, b"tampered pristine geosite")
            .expect("tamper geosite pair member");
        let message = restore_pristine_geo_data(&core)
            .expect_err("tampered pair must refuse")
            .to_string();
        let tampered_hash = sha256_hex(&pristine_geoip).expect("hash tampered pair member");
        assert!(message.contains("geoip.dat"), "{message}");
        assert!(message.contains(GEOIP_SHA256), "{message}");
        assert!(message.contains(tampered_hash.as_str()), "{message}");
        assert_eq!(
            fs::read(core.join("geoip.dat")).unwrap(),
            DRIFTED_GEOIP,
            "managed geoip must be untouched by a refused restore"
        );
        assert_eq!(
            fs::read(core.join("geosite.dat")).unwrap(),
            DRIFTED_GEOSITE,
            "managed geosite must be untouched by a refused restore"
        );
        assert!(
            fs::read_dir(&core).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".restore-")
            }),
            "a refused restore must not leave temp files behind"
        );
    }

    #[test]
    fn seed_pristine_failure_removes_the_partial_pristine_dir() {
        // A drifted tree must fail seeding with the mismatch reported loudly
        // and the partially built pristine dir removed.
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = drifted_core(temporary.path());
        let error = seed_pristine_from_tree(&core).expect_err("drifted tree must not seed");
        assert_eq!(error.diag().key(), Key::CoreDlPristineMismatch);
        let message = error.text(Language::En);
        assert!(message.contains("geoip.dat"), "{message}");
        assert!(
            message.contains("does not match the compiled release pin"),
            "{message}"
        );
        assert!(
            !core.join(PRISTINE_DIR).exists(),
            "the partial pristine dir must be removed after a failed seed"
        );
        assert_eq!(
            fs::read(core.join("geoip.dat")).unwrap(),
            DRIFTED_GEOIP,
            "managed geoip must be untouched by a failed seed"
        );
    }

    /// Copy the real installed managed core (`%APPDATA%\broccoli\core`)
    /// into `root/core`, asserting its presence the way the e2e suite does.
    /// Only ignored tests call this: the always-run suite must pass with no
    /// core installed and no network.
    fn copy_installed_core(root: &Path) -> PathBuf {
        // APPDATA readers serialize against the redirecting tests (suite
        // convention), so the copied core is the real installed one.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let installed = std::env::var_os("APPDATA").expect("real APPDATA must be available");
        let installed_core = PathBuf::from(installed).join("broccoli/core");
        assert!(
            installed_core.join("xray.exe").is_file(),
            "the managed core must be installed before exercising restore (missing {})",
            installed_core.display()
        );
        let core = root.join("core");
        fs::create_dir_all(&core).expect("create copied core dir");
        for name in [
            ".broccoli-official-release.json",
            "xray.exe",
            "wintun.dll",
            "geoip.dat",
            "geosite.dat",
        ] {
            fs::copy(installed_core.join(name), core.join(name)).expect("copy installed payload");
        }
        core
    }

    #[test]
    #[ignore = "requires the installed managed core"]
    fn restore_replaces_drifted_managed_geo_data_and_passes_strict_verify() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = copy_installed_core(temporary.path());
        pristine_from_managed(&core);

        // Drift the managed DATs, then restore them.
        fs::write(core.join("geoip.dat"), b"drifted").expect("drift managed geoip");
        fs::write(core.join("geosite.dat"), b"drifted").expect("drift managed geosite");
        restore_pristine_geo_data(&core).expect("restore must replace drifted managed geo data");

        let restored_geoip = sha256_hex(&core.join("geoip.dat")).expect("hash restored geoip");
        let restored_geosite =
            sha256_hex(&core.join("geosite.dat")).expect("hash restored geosite");
        assert!(
            restored_geoip.eq_ignore_ascii_case(GEOIP_SHA256),
            "restored geoip.dat must equal the compiled release pin: {restored_geoip}"
        );
        assert!(
            restored_geosite.eq_ignore_ascii_case(GEOSITE_SHA256),
            "restored geosite.dat must equal the compiled release pin: {restored_geosite}"
        );

        // Idempotence: a second restore while the managed files already
        // match the pins is a safe no-op that leaves the tree byte-identical.
        restore_pristine_geo_data(&core).expect("restore must be idempotent");
        assert_eq!(
            sha256_hex(&core.join("geoip.dat")).expect("re-hash restored geoip"),
            restored_geoip,
            "the no-op restore must not rewrite the managed files"
        );
        assert!(
            fs::read_dir(&core).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".restore-")
            }),
            "restore must not leave temp files behind"
        );

        // The whole tree still passes the strict full verification every
        // traffic-carrying spawn runs.
        drop(open_verified_core(&core).expect("restored core must pass full verification"));
    }

    #[test]
    #[ignore = "requires the installed managed core"]
    fn suspended_verify_keeps_drifted_dats_and_strict_verify_heals_them() {
        // The two entries answer the same drifted tree differently: with the
        // pins suspended (a config that carries geodata URLs, so the core's
        // own updater owns the pair) the refreshed bytes are the expected
        // user-managed state and must survive the verification untouched;
        // the strict entry heals the same drift from the retained pristine
        // pair.
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = copy_installed_core(temporary.path());
        pristine_from_managed(&core);
        fs::write(core.join("geoip.dat"), DRIFTED_GEOIP).expect("drift managed geoip");
        fs::write(core.join("geosite.dat"), DRIFTED_GEOSITE).expect("drift managed geosite");

        drop(
            super::open_verified_core_user_managed_dats(&core)
                .expect("a user-managed DAT pair must verify with the pins suspended"),
        );
        assert_eq!(
            fs::read(core.join("geoip.dat")).unwrap(),
            DRIFTED_GEOIP,
            "suspended verification must leave the user-managed geoip.dat untouched"
        );
        assert_eq!(
            fs::read(core.join("geosite.dat")).unwrap(),
            DRIFTED_GEOSITE,
            "suspended verification must leave the user-managed geosite.dat untouched"
        );

        drop(open_verified_core(&core).expect("the strict entry must heal the drifted pair"));
        let healed_geoip = sha256_hex(&core.join("geoip.dat")).expect("hash healed geoip");
        let healed_geosite = sha256_hex(&core.join("geosite.dat")).expect("hash healed geosite");
        assert!(
            healed_geoip.eq_ignore_ascii_case(GEOIP_SHA256),
            "the strict verification must restore the pinned geoip.dat: {healed_geoip}"
        );
        assert!(
            healed_geosite.eq_ignore_ascii_case(GEOSITE_SHA256),
            "the strict verification must restore the pinned geosite.dat: {healed_geosite}"
        );
    }

    #[test]
    #[ignore = "requires the pinned official Xray archive (BROCCOLI_TEST_XRAY_ARCHIVE)"]
    fn installing_the_pinned_archive_retains_a_pin_matching_pristine_pair() {
        // Drives the single install funnel (first install and in-app core
        // updates alike) against an isolated APPDATA root and asserts the
        // committed core carries a pin-matching pristine pair plus a tree
        // that passes the strict full verification.
        let archive = PathBuf::from(
            std::env::var_os("BROCCOLI_TEST_XRAY_ARCHIVE")
                .expect("BROCCOLI_TEST_XRAY_ARCHIVE must point to the official pinned ZIP"),
        );
        assert!(
            archive.is_file(),
            "BROCCOLI_TEST_XRAY_ARCHIVE must point to a readable ZIP: {}",
            archive.display()
        );
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let _appdata = AppDataRedirect::to(temporary.path());

        let installed = super::install_pinned_core_archive(&archive)
            .expect("installing the pinned archive must succeed");
        let expected_version = super::pinned_release_version()
            .strip_prefix('v')
            .expect("compiled pinned version must have a v prefix");
        assert_eq!(installed, expected_version);

        let core = temporary.path().join("broccoli/core");
        let pristine_dir = core.join(PRISTINE_DIR);
        for (payload, expected) in super::GEO_DATA_PAIR {
            let actual =
                sha256_hex(&pristine_dir.join(payload)).expect("hash installed pristine file");
            assert!(
                actual.eq_ignore_ascii_case(expected),
                "installed pristine {payload} must match its compiled pin: {actual}"
            );
        }
        // The committed tree passes the strict full verification that every
        // traffic-carrying spawn runs (metadata plus all four payloads).
        drop(open_verified_core(&core).expect("installed core must pass full verification"));
    }
}

#[cfg(test)]
mod provenance_tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    use super::{GeoDataProvenance, geo_data_provenance, restore_pristine_geo_data};
    use crate::sys::appdata::APPDATA_ENV_LOCK;

    const DRIFTED_GEOIP: &[u8] = b"drifted geoip bytes";
    const DRIFTED_GEOSITE: &[u8] = b"drifted geosite bytes";

    /// A managed core fixture whose DATs are drifted bytes that cannot match
    /// any compiled pin. Release-managed state needs pin-matching bytes,
    /// which only exist in the real installed core, so the always-run tests
    /// below can only exercise user-managed and no-core answers.
    fn drifted_core(root: &Path) -> PathBuf {
        let core = root.join("core");
        fs::create_dir_all(&core).expect("create fixture core dir");
        fs::write(core.join("geoip.dat"), DRIFTED_GEOIP).expect("write drifted geoip");
        fs::write(core.join("geosite.dat"), DRIFTED_GEOSITE).expect("write drifted geosite");
        core
    }

    /// Rewrite `path`'s mtime so update-time assertions are deterministic
    /// (same helper shape as the panic-report cleanup tests in main.rs).
    fn set_mtime(path: &Path, time: SystemTime) {
        fs::File::options()
            .write(true)
            .open(path)
            .expect("open file to set mtime")
            .set_modified(time)
            .expect("set file mtime");
    }

    #[test]
    fn drifted_pair_reports_user_managed_with_the_newest_mtime() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = drifted_core(temporary.path());
        let geoip = core.join("geoip.dat");
        let geosite = core.join("geosite.dat");
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let new = old + std::time::Duration::from_secs(3600);
        set_mtime(&geoip, old);
        set_mtime(&geosite, new);

        let provenance = geo_data_provenance(&core);
        assert_eq!(
            provenance,
            GeoDataProvenance::UserManaged { updated: Some(new) },
            "a drifted pair must report user-managed with the newest of the \
             two files' modification times"
        );
        // The update time is the file attribute, never a call-time clock
        // reading: the query must be a pure function of the two files.
        assert_eq!(
            geo_data_provenance(&core),
            provenance,
            "a repeat query with unchanged files must return the same answer"
        );
    }

    #[test]
    fn missing_payload_is_user_managed_with_the_existing_files_mtime() {
        // A missing DAT cannot match its pin; hashing cannot distinguish the
        // absence from a drift, so the pair is user-managed and the surviving
        // file's mtime is the visible update time.
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = temporary.path().join("core");
        fs::create_dir_all(&core).expect("create fixture core dir");
        let geoip = core.join("geoip.dat");
        fs::write(&geoip, DRIFTED_GEOIP).expect("write drifted geoip");
        let marked = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        set_mtime(&geoip, marked);

        assert_eq!(
            geo_data_provenance(&core),
            GeoDataProvenance::UserManaged {
                updated: Some(marked),
            },
            "a missing payload must still report user-managed with the \
             surviving file's mtime"
        );
    }

    #[test]
    fn user_managed_with_no_stattable_payload_carries_no_update_time() {
        // An empty managed core dir (both payloads missing) is user-managed
        // with no stat to date it — not release-managed and not NoCore, the
        // latter being reserved for a missing core directory itself.
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = temporary.path().join("core");
        fs::create_dir_all(&core).expect("create fixture core dir");
        assert_eq!(
            geo_data_provenance(&core),
            GeoDataProvenance::UserManaged { updated: None }
        );
    }

    #[test]
    fn absent_core_directory_reports_no_core() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let missing = temporary.path().join("core");
        assert_eq!(
            geo_data_provenance(&missing),
            GeoDataProvenance::NoCore,
            "a missing core directory must answer NoCore"
        );
        // A regular file where the core directory belongs is not a managed
        // core tree either.
        let not_a_dir = temporary.path().join("core");
        fs::write(&not_a_dir, b"not a core directory").expect("write fixture file");
        assert_eq!(
            geo_data_provenance(&not_a_dir),
            GeoDataProvenance::NoCore,
            "a non-directory core path must answer NoCore"
        );
    }

    /// Copy the real installed core's geo data (`%APPDATA%\broccoli\core`)
    /// into `root/core`, asserting its presence the way the e2e suite does.
    /// Only ignored tests call this: the always-run suite must pass with no
    /// core installed and no network.
    fn copy_installed_geo_data(root: &Path) -> PathBuf {
        // APPDATA readers serialize against the redirecting tests (suite
        // convention), so the copied files are the real installed ones.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let installed = std::env::var_os("APPDATA").expect("real APPDATA must be available");
        let installed_core = PathBuf::from(installed).join("broccoli/core");
        let core = root.join("core");
        fs::create_dir_all(&core).expect("create copied core dir");
        for payload in ["geoip.dat", "geosite.dat"] {
            let source = installed_core.join(payload);
            assert!(
                source.is_file(),
                "the managed core must be installed before exercising \
                 provenance (missing {})",
                source.display()
            );
            fs::copy(source, core.join(payload)).expect("copy installed geo data payload");
        }
        core
    }

    /// Build the pristine pair from the copied core's own managed bytes —
    /// pin-matching because the clone is the real installed core (same
    /// construction as pristine_tests).
    fn pristine_from_managed(core: &Path) {
        let dir = core.join(super::PRISTINE_DIR);
        fs::create_dir_all(&dir).expect("create fixture pristine dir");
        for payload in ["geoip.dat", "geosite.dat"] {
            fs::copy(core.join(payload), dir.join(payload))
                .expect("seed pristine payload from managed bytes");
        }
    }

    #[test]
    #[ignore = "requires the installed managed core"]
    fn provenance_follows_drift_and_restore_round_trip() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let core = copy_installed_geo_data(temporary.path());
        pristine_from_managed(&core);

        // The untouched clone matches the compiled pins: release-managed.
        assert_eq!(
            geo_data_provenance(&core),
            GeoDataProvenance::ReleaseManaged,
            "an untouched installed core must report release-managed"
        );

        // Drift one DAT: user-managed, dated by the drifted file's own mtime
        // (the write made it the newest of the pair).
        fs::write(core.join("geoip.dat"), b"drifted").expect("drift managed geoip");
        let drifted_mtime = fs::metadata(core.join("geoip.dat"))
            .expect("stat drifted geoip")
            .modified()
            .expect("drifted geoip mtime");
        assert_eq!(
            geo_data_provenance(&core),
            GeoDataProvenance::UserManaged {
                updated: Some(drifted_mtime),
            }
        );

        // Restore via the pub primitive: the status the UI would show flips
        // back to release-managed.
        restore_pristine_geo_data(&core).expect("restore must replace drifted geo data");
        assert_eq!(
            geo_data_provenance(&core),
            GeoDataProvenance::ReleaseManaged,
            "a restored pair must report release-managed again"
        );
    }
}

//! DAT pin suspension and self-healing drift restore on a copy of the real
//! installed managed core.
//!
//! A user-configured `geodata` block suspends only the geo data files'
//! SHA-256 compare: drifted geoip.dat/geosite.dat must verify under the
//! config-driven open decision (`open_verified_for_config`, a config whose
//! `geodata` block carries an asset URL) and are never healed, while a config
//! without that block restores them from the retained pin-verified pristine
//! pair and re-verifies — failing terminally only
//! when the pair is missing or corrupt. A tampered xray.exe or wintun.dll
//! must refuse to open in both modes. These tests are ignored by default:
//! they require the real pinned managed core under `%APPDATA%\broccoli\core`
//! (the only source of bytes that match the compiled pins) and copy tens of
//! MB per clone.

use std::fs;
use std::path::{Path, PathBuf};

use broccoli::diag::DiagError;
use broccoli::sys::core_dl::{
    VerifiedCore, VerifyScope, open_verified_for_config, open_verified_for_config_at,
    pinned_release_version,
};

/// The config a spawn would run when the user configured the core's own geo
/// data updater: its `geodata` block is what suspends the DAT compares.
const USER_MANAGED_CONFIG: &[u8] =
    br#"{"geodata":{"assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}}"#;

/// The config a spawn would run with the release-managed geo data: no
/// `geodata` block, so the DAT compares stay hard.
const RELEASE_MANAGED_CONFIG: &[u8] = br#"{"outbounds":[]}"#;

/// Open `core` the way a spawn running `config` opens it.
fn open_for_config(core: &Path, config: &[u8]) -> Result<VerifiedCore, DiagError> {
    let config: serde_json::Value =
        serde_json::from_slice(config).expect("fixture config must parse");
    open_verified_for_config(core, &config, VerifyScope::Full)
}

/// The managed-core members a verify covers; copied in pin order so a clone
/// is a faithful stand-in for the real tree.
const CORE_FILES: &[&str] = &[
    ".broccoli-official-release.json",
    "xray.exe",
    "wintun.dll",
    "geoip.dat",
    "geosite.dat",
];

/// Bytes no compiled release pin can match; `drift` writes these, so the
/// "managed file stayed drifted" assertions compare against the same
/// constant.
const DRIFTED_BYTES: &[u8] = b"user-managed replacement bytes, not the release pin";

/// The payloads `copy_runtime_payloads` stages — the metadata file is
/// verified but never staged, so fidelity checks must not expect it.
const PAYLOAD_FILES: &[&str] = &["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"];

fn installed_core() -> PathBuf {
    let appdata = std::env::var_os("APPDATA").expect("APPDATA must be set for the real core");
    PathBuf::from(appdata).join("broccoli").join("core")
}

/// Clone the real installed core into a fresh directory inside `sink`.
fn clone_installed_core(sink: &Path) -> PathBuf {
    let source = installed_core();
    let destination = sink.join("core");
    fs::create_dir_all(&destination).expect("create cloned core directory");
    for name in CORE_FILES {
        fs::copy(source.join(name), destination.join(name)).unwrap_or_else(|error| {
            panic!(
                "copy {} from the real managed core {}: {error}",
                name,
                source.display()
            )
        });
    }
    destination
}

/// `VerifiedCore::version` is the banner version without the leading `v`.
fn assert_pinned_version(version: &str) {
    let pinned = pinned_release_version();
    assert_eq!(
        pinned.strip_prefix('v'),
        Some(version),
        "verified core version must equal the compiled release version"
    );
}

fn drift(path: &Path) {
    fs::write(path, DRIFTED_BYTES).expect("drift geo data file");
}

/// Create the pristine pair directory and return its two file paths.
fn pristine_pair(core: &Path) -> (PathBuf, PathBuf) {
    let dir = core.join("pristine");
    fs::create_dir_all(&dir).expect("create fixture pristine dir");
    (dir.join("geoip.dat"), dir.join("geosite.dat"))
}

/// Build the pristine pair from the clone's own managed bytes — pin-matching
/// because the clone is the real installed core. Retention happens only
/// inside the install funnel for release trees, so tests that need a pair on
/// a clone construct it directly (same shape as `pristine_from_managed` in
/// `core_dl.rs`'s pristine_tests).
fn pristine_from_managed(core: &Path) {
    let (geoip, geosite) = pristine_pair(core);
    fs::copy(core.join("geoip.dat"), geoip).expect("seed pristine geoip from managed bytes");
    fs::copy(core.join("geosite.dat"), geosite).expect("seed pristine geosite from managed bytes");
}

/// Assert no `.restore-*` temp file survives anywhere in `core`.
fn assert_no_restore_temps(core: &Path) {
    assert!(
        fs::read_dir(core).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".restore-")
        }),
        "a heal must not leave temp files behind"
    );
}

/// `VerifiedCore` does not implement `Debug`, so `Result::expect_err` is
/// unavailable; extract the error explicitly instead.
fn expect_verify_error(result: Result<VerifiedCore, DiagError>, message: &str) -> DiagError {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Baseline: an unmodified clone of the release tree must verify under the
/// config-driven open — this validates the harness itself before the drift
/// assertions. The two adapters are the two shapes a spawn holds: a parsed
/// config value, and the config file on disk the spawn is about to run.
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn unmodified_clone_passes_release_managed_verification() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    let verified = open_for_config(&clone, RELEASE_MANAGED_CONFIG)
        .expect("pristine clone must verify under a release-managed config");
    assert_pinned_version(verified.version());

    let config = sink.path().join("config.json");
    fs::write(&config, RELEASE_MANAGED_CONFIG).expect("write release-managed config file");
    let from_path = open_verified_for_config_at(&clone, &config, VerifyScope::Full)
        .expect("the on-disk form of the same config must verify identically");
    assert_pinned_version(from_path.version());
}

/// Drifted geo data: a release-managed open on a clone WITHOUT a pristine pair
/// is terminal with the restore reason named (the unrestorable-heal path),
/// a user-managed open accepts the drift, and its stage-copy
/// proof still holds (byte fidelity against the observed hash, not the pin).
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn user_managed_dats_accept_drift_that_strict_verification_rejects() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    drift(&clone.join("geoip.dat"));
    drift(&clone.join("geosite.dat"));

    let strict = expect_verify_error(
        open_for_config(&clone, RELEASE_MANAGED_CONFIG),
        "drifted geo data must fail the strict release verify without a pristine pair",
    );
    let message = strict.to_string();
    assert!(
        message.contains("failed release verification"),
        "strict failure must name the failed release verification, got: {message}"
    );
    assert!(
        message.contains("restore unavailable"),
        "the unrestorable heal must name the restore reason, got: {message}"
    );
    assert!(
        message.contains("auto-restore failed"),
        "the unrestorable heal must be reported as a failed auto-restore, got: {message}"
    );

    let mut verified = open_for_config(&clone, USER_MANAGED_CONFIG)
        .expect("drifted geo data must verify under a user-managed config");
    assert_pinned_version(verified.version());

    // The helper-stage copy hashes each copied payload against the recorded
    // expectation. Under suspension the DAT expectation is the observed
    // hash, so staging drifted (user-managed) bytes still proves byte
    // fidelity and the staged copies equal the drifted sources exactly.
    let stage = sink.path().join("stage");
    fs::create_dir(&stage).expect("create stage directory");
    verified
        .copy_runtime_payloads(&stage)
        .expect("staging must succeed with user-managed geo data");
    for name in PAYLOAD_FILES {
        let copied = fs::read(stage.join(name)).expect("staged payload present");
        let source = fs::read(clone.join(name)).expect("clone payload readable");
        assert_eq!(
            copied, source,
            "staged {name} must be byte-identical to its locked source"
        );
    }
}

/// Executable/driver tampering stays terminal in both modes — the
/// suspension never widens past the two geo data files.
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn tampered_executable_or_driver_fails_in_strict_and_user_managed_modes() {
    for tampered in ["xray.exe", "wintun.dll"] {
        let sink = tempfile::tempdir().expect("temporary clone sink");
        let clone = clone_installed_core(sink.path());
        drift(&clone.join(tampered));

        let strict = expect_verify_error(
            open_for_config(&clone, RELEASE_MANAGED_CONFIG),
            "tampered payload must fail the strict release verify",
        );
        assert!(
            strict.to_string().contains("failed release verification"),
            "strict failure must be a payload verification error, got: {strict}"
        );
        let user_managed = expect_verify_error(
            open_for_config(&clone, USER_MANAGED_CONFIG),
            "tampered payload must fail the user-managed release verify too",
        );
        assert!(
            user_managed
                .to_string()
                .contains(&format!("{tampered} failed release verification")),
            "user-managed failure must name the tampered payload, got: {user_managed}"
        );
    }
}

/// Strict entry: drift with no geodata block self-heals. With a
/// valid retained pristine pair, a release-managed open restores the drifted
/// managed geo data from it, re-verifies, and proceeds — the managed files
/// end up byte-identical to the pristine pair (which is the release pin
/// bytes by construction of the clone).
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn strict_verify_heals_drifted_geo_data_from_the_pristine_pair() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    pristine_from_managed(&clone);
    drift(&clone.join("geoip.dat"));
    drift(&clone.join("geosite.dat"));

    let verified = open_for_config(&clone, RELEASE_MANAGED_CONFIG)
        .expect("drifted geo data with a pristine pair must heal and verify strictly");
    assert_pinned_version(verified.version());
    drop(verified);

    for payload in ["geoip.dat", "geosite.dat"] {
        assert_eq!(
            fs::read(clone.join(payload)).unwrap(),
            fs::read(clone.join("pristine").join(payload)).unwrap(),
            "healed {payload} must equal the retained pristine pair"
        );
    }
    assert_no_restore_temps(&clone);
    // The pristine pair itself survives the heal untouched.
    assert!(
        clone.join("pristine/geoip.dat").is_file() && clone.join("pristine/geosite.dat").is_file(),
        "the pristine pair must survive an auto-restore"
    );
}

/// A drifted strict open on a core with NO pristine pair fails
/// terminally naming both the release-verification failure and the restore
/// reason — no silent continue, no partial write.
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn strict_verify_without_pristine_pair_fails_naming_the_restore_reason() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    drift(&clone.join("geoip.dat"));
    drift(&clone.join("geosite.dat"));

    let error = expect_verify_error(
        open_for_config(&clone, RELEASE_MANAGED_CONFIG),
        "drifted geo data without a pristine pair must fail terminally",
    );
    let message = error.to_string();
    assert!(
        message.contains("failed release verification"),
        "the terminal error must keep the release-verification failure, got: {message}"
    );
    assert!(
        message.contains("restore unavailable"),
        "the terminal error must name why the heal was impossible, got: {message}"
    );
    assert_eq!(
        fs::read(clone.join("geoip.dat")).unwrap(),
        DRIFTED_BYTES,
        "managed geoip must be untouched by the refused heal"
    );
    assert_eq!(
        fs::read(clone.join("geosite.dat")).unwrap(),
        DRIFTED_BYTES,
        "managed geosite must be untouched by the refused heal"
    );
    assert_no_restore_temps(&clone);
}

/// A corrupt pristine pair makes the heal terminal before any
/// managed write — the strict open names the pristine pin mismatch (and the
/// release-verification failure) and leaves the drifted managed files
/// byte-identical.
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn strict_verify_fails_on_tampered_pristine_without_healing_managed_files() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    pristine_from_managed(&clone);
    drift(&clone.join("geoip.dat"));
    drift(&clone.join("geosite.dat"));
    fs::write(
        clone.join("pristine/geoip.dat"),
        b"tampered pristine geoip, not the release pin",
    )
    .expect("tamper the pristine pair member");

    let error = expect_verify_error(
        open_for_config(&clone, RELEASE_MANAGED_CONFIG),
        "a corrupt pristine pair must fail the strict open terminally",
    );
    let message = error.to_string();
    assert!(
        message.contains("failed release verification"),
        "the terminal error must keep the release-verification failure, got: {message}"
    );
    assert!(
        message.contains("pristine geoip.dat") && message.contains("does not match"),
        "the terminal error must name the corrupt pristine pair member, got: {message}"
    );
    assert_eq!(
        fs::read(clone.join("geoip.dat")).unwrap(),
        DRIFTED_BYTES,
        "managed geoip must be untouched by a heal refused on corrupt pristine"
    );
    assert_eq!(
        fs::read(clone.join("geosite.dat")).unwrap(),
        DRIFTED_BYTES,
        "managed geosite must be untouched by a heal refused on corrupt pristine"
    );
    assert_no_restore_temps(&clone);
}

/// A heal on `geosite.dat` after `geoip.dat` already verified
/// and locked must still succeed — the restore replaces both geo data
/// files, so the lock on the already-verified geoip is released and
/// re-established (regression for the Windows sharing-violation trap).
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn strict_verify_heals_geosite_only_drift_after_geoip_is_locked() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    pristine_from_managed(&clone);
    drift(&clone.join("geosite.dat"));

    let verified = open_for_config(&clone, RELEASE_MANAGED_CONFIG)
        .expect("a lone geosite drift must heal and verify strictly");
    assert_pinned_version(verified.version());
    drop(verified);

    assert_eq!(
        fs::read(clone.join("geosite.dat")).unwrap(),
        fs::read(clone.join("pristine/geosite.dat")).unwrap(),
        "healed geosite must equal the retained pristine pair"
    );
    assert_no_restore_temps(&clone);
}

/// A user-managed config never heals — drift is the expected
/// user-managed state even when a valid pristine pair sits right there —
/// so the managed files stay drifted after a successful open.
#[test]
#[ignore = "requires the real installed managed core under %APPDATA%\\broccoli\\core"]
fn user_managed_entry_never_heals_drifted_geo_data_even_with_a_valid_pristine_pair() {
    let sink = tempfile::tempdir().expect("temporary clone sink");
    let clone = clone_installed_core(sink.path());
    pristine_from_managed(&clone);
    drift(&clone.join("geoip.dat"));
    drift(&clone.join("geosite.dat"));

    let verified = open_for_config(&clone, USER_MANAGED_CONFIG)
        .expect("drifted geo data must verify under a user-managed config");
    assert_pinned_version(verified.version());
    drop(verified);

    assert_eq!(
        fs::read(clone.join("geoip.dat")).unwrap(),
        DRIFTED_BYTES,
        "user-managed geoip must stay drifted (no heal under suspension)"
    );
    assert_eq!(
        fs::read(clone.join("geosite.dat")).unwrap(),
        DRIFTED_BYTES,
        "user-managed geosite must stay drifted (no heal under suspension)"
    );
    assert!(
        clone.join("pristine/geoip.dat").is_file() && clone.join("pristine/geosite.dat").is_file(),
        "the pristine pair must be left in place by a user-managed open"
    );
}

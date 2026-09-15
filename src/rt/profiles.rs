//! The profile-validation verb: one accepted `CoreCmd::ValidateProfiles`
//! request, the per-profile worker that runs it, and the scratch-config
//! contract that worker owns.
//!
//! A request carries the screen's model snapshot — the servers file, the
//! scratch settings the staged profile is generated with — plus the profiles
//! to validate and where an accepted draft commits. The worker walks the
//! profiles in order: it stages each profile into the working servers file in
//! place (restoring the file when the candidate is rejected), generates a
//! config, writes that config to a scratch file in the config
//! directory and runs the file through `xray run -test`
//! ([`super::apply::validate`]). The accepted/rejected verdict travels back on
//! the request's own reply channel; nothing is ever persisted, and a rejected
//! profile never reaches the caller's model.
//!
//! The scratch config holds the full generated profile — UUIDs, passwords,
//! private keys — so the worker owns its lifetime through
//! [`ScratchConfigGuard`]: the file is removed on drop, during panic
//! unwinding, and on the worker's own cancellation. Cancellation is
//! cooperative by construction: the worker observes its cancel flag between
//! profiles, so an in-flight `xray -test` child is never hard-aborted while it
//! holds the file open (Windows cannot delete a file a live child keeps open,
//! so an abort would strand plaintext secrets and orphan the child). A crash
//! or kill still strands the file; the next launch's sweep
//! ([`sweep_stale_scratch_configs`], the shell's single entry point) removes
//! stale ones by age under the exact same naming contract.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, t, t_fmt};
use crate::links;
use crate::model::settings::Language;
use crate::model::{ServerProfile, ServersFile, Settings};

use super::apply;

/// Where an accepted draft validation commits: which editor draft the request
/// was staged from, echoed back on the verdict so the screen applies the
/// profile to the same draft and discards a verdict whose draft has moved on
/// (the generation is bumped by every content edit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolTarget {
    ExistingDraft { profile_id: String, generation: u64 },
    AddDraft { profile_id: String, generation: u64 },
}

/// What a validation is for: a draft profile on its way into the model, or a
/// batch of imported profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileValidationOrigin {
    Draft,
    Import,
}

/// One accepted `CoreCmd::ValidateProfiles` request: every input the worker
/// needs, so the runtime owns the scratch write, the child and the
/// cancellation.
#[derive(Debug)]
pub struct ProfileValidationRequest {
    /// Which flow staged the profiles (draft commit vs import batch).
    pub origin: ProfileValidationOrigin,
    /// Locale for the worker's own messages (scratch write failures, the
    /// silent-`xray` fallback, duplicate accepted ids).
    pub lang: Language,
    /// Profiles to validate, in order.
    pub profiles: Vec<ServerProfile>,
    /// The draft an accepted profile commits to; required for the draft flow.
    pub draft_target: Option<ToolTarget>,
    /// The import paste the request was staged from, echoed back so the screen
    /// can discard a verdict whose paste has changed.
    pub import_source: Option<String>,
    /// Servers-file snapshot the staged profile is generated into.
    pub servers: ServersFile,
    /// Scratch settings for the generated config: the caller's settings with
    /// `raw_override` cleared, so the staged profile is exercised instead of
    /// the raw passthrough.
    pub settings: Settings,
}

/// The accepted/rejected verdict of one run, as the screen renders it.
#[derive(Debug)]
pub struct ProfileValidationResult {
    pub origin: ProfileValidationOrigin,
    pub accepted: Vec<ServerProfile>,
    pub rejected: Vec<(String, String)>,
    pub import_source: Option<String>,
    pub draft_target: Option<ToolTarget>,
}

/// Terminal verdict of one accepted `CoreCmd::ValidateProfiles`: `Ok(result)`
/// when the worker walked the profile list, `Err` when it never did
/// (rejection, cancellation, join failure). The error stays a keyed chain
/// until the screen renders it in the active language. Travels the request's
/// own reply channel.
pub type ProfileValidationReply = Result<ProfileValidationResult, DiagError>;

/// Terminal a cancelled validation delivers when the worker itself observes
/// the cancel flag between profiles. The runtime-owned cancel paths (a
/// record cancelled before its worker ran, a join failure) deliver their own
/// per-kind wording.
pub(crate) fn validation_cancelled() -> DiagError {
    DiagError::from(Diag::new(Key::SeatValidationCancelled))
}

/// Run one accepted request to its terminal: per profile, stage it, generate
/// a config, validate the generated config with `xray run -test`, and
/// accumulate the verdict. `cancel` is observed before the first profile and
/// between profiles — never inside a validation child, whose open file the
/// guard must be allowed to remove.
pub(crate) async fn validate(
    request: ProfileValidationRequest,
    cancel: &AtomicBool,
) -> ProfileValidationReply {
    let ProfileValidationRequest {
        origin,
        lang,
        profiles,
        draft_target,
        import_source,
        servers,
        settings,
    } = request;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut staged_servers = servers;
    for profile in profiles {
        // Cooperative cancel boundary: the previous iteration's staging was
        // either committed or already reverted, so nothing is left behind
        // and no partial verdict is reported — a cancelled run commits
        // nothing.
        if cancel.load(Ordering::Relaxed) {
            return Err(validation_cancelled());
        }
        let label = if profile.name.is_empty() {
            profile.tag()
        } else {
            profile.name.clone()
        };
        if origin == ProfileValidationOrigin::Import
            && let Err(error) = links::validate_profile(&profile)
        {
            rejected.push((label, error.text(lang)));
            continue;
        }
        if origin == ProfileValidationOrigin::Import
            && accepted
                .iter()
                .any(|accepted_profile: &ServerProfile| accepted_profile.id == profile.id)
        {
            rejected.push((
                label,
                t_fmt(
                    lang,
                    Key::SrvDuplicateAcceptedId,
                    &[&format!("{:?}", profile.id)],
                ),
            ));
            continue;
        }

        match stage_and_validate(&mut staged_servers, &profile, &settings, lang).await {
            Ok(()) => accepted.push(profile),
            Err(message) => rejected.push((label, message)),
        }
    }
    Ok(ProfileValidationResult {
        origin,
        accepted,
        rejected,
        import_source,
        draft_target,
    })
}

/// Stage `profile` into the working servers file in place, generate the
/// config for the staged file and validate it with `xray run -test`. `Err`
/// is the rejection text as the screen renders it, and the staging has
/// already been reverted: a rejected profile leaves the file that later
/// profiles are generated against holding only accepted candidates. (The
/// per-profile whole-file copy this replaced deep-copied every other profile
/// once per candidate, so an import batch of N profiles cost O(N²) copies.)
async fn stage_and_validate(
    staged: &mut ServersFile,
    profile: &ServerProfile,
    settings: &Settings,
    lang: Language,
) -> Result<(), String> {
    let staging = stage_profile(staged, profile);
    match generate_and_validate(staged, settings, lang).await {
        Ok(()) => Ok(()),
        Err(message) => {
            staging.revert(staged);
            Err(message)
        }
    }
}

/// Undo record of one in-place staging ([`stage_profile`]): the element a
/// candidate displaced, or the push to truncate, plus the `active` backfill
/// to withdraw. Reverting restores the working file exactly as it was
/// before the candidate was staged.
struct StagingUndo {
    displaced: Option<(usize, ServerProfile)>,
    filled_active: bool,
}

impl StagingUndo {
    /// Roll the working file back to exactly the accepted-candidate state
    /// the rejected candidate was staged onto.
    fn revert(self, staged: &mut ServersFile) {
        match self.displaced {
            Some((index, displaced)) => staged.profiles[index] = displaced,
            None => {
                staged.profiles.pop();
            }
        }
        if self.filled_active {
            staged.active = None;
        }
    }
}

/// Stage `profile` into `staged` in place — replace the entry with the same
/// id, else append — and backfill `active` when the file has none, because
/// the generated config needs an active outbound. Returns the undo record a
/// rejection applies; an accepted candidate keeps both the entry and the
/// backfill. Only the candidate itself is cloned.
fn stage_profile(staged: &mut ServersFile, profile: &ServerProfile) -> StagingUndo {
    let mut displaced = None;
    match staged
        .profiles
        .iter()
        .position(|existing| existing.id == profile.id)
    {
        Some(index) => {
            let previous = std::mem::replace(&mut staged.profiles[index], profile.clone());
            displaced = Some((index, previous));
        }
        None => staged.profiles.push(profile.clone()),
    }
    let filled_active = staged.active.is_none();
    if filled_active {
        staged.active = Some(profile.id.clone());
    }
    StagingUndo {
        displaced,
        filled_active,
    }
}

/// Generate the staged file's config, write it to a scratch file in the
/// config directory and run it through `xray run -test`
/// ([`apply::validate`]). `Err` is the rejection text for the profile.
async fn generate_and_validate(
    staged: &ServersFile,
    settings: &Settings,
    lang: Language,
) -> Result<(), String> {
    let config = crate::r#gen::generate(staged, settings).map_err(|error| error.text(lang))?;
    let directory = crate::sys::paths::config_dir();
    std::fs::create_dir_all(&directory)
        .map_err(|error| t_fmt(lang, Key::SrvScratchConfigDirFailed, &[&error]))?;
    let path = directory.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|error| t_fmt(lang, Key::SrvScratchConfigSerializeFailed, &[&error]))?;
    std::fs::write(&path, bytes)
        .map_err(|error| t_fmt(lang, Key::SrvScratchConfigWriteFailed, &[&error]))?;
    // The guard removes the scratch config on drop — normal completion
    // and panic unwinding alike — so a mid-flight abort cannot leave
    // plaintext profile secrets on disk.
    let (ok, output) = {
        let _scratch = ScratchConfigGuard::new(path.clone());
        apply::validate(&path).await
    };
    if ok {
        return Ok(());
    }
    let output = output.text(lang);
    if output.trim().is_empty() {
        Err(t(lang, Key::SrvXrayTestSilent).to_string())
    } else {
        Err(output)
    }
}

/// RAII owner of a scratch `profile-test-*.json` written for `xray run -test`
/// validation. The config holds the full generated profile — UUIDs,
/// passwords, private keys — so it must not linger if the worker panics or
/// aborts mid-flight; `drop` removes the file even while unwinding. A failed
/// removal is logged, never silently swallowed and never panicking; a path
/// that is already gone is not an error.
pub(crate) struct ScratchConfigGuard {
    path: PathBuf,
}

impl ScratchConfigGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for ScratchConfigGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "broccoli: failed to remove scratch validation config {}: {error}",
                self.path.display()
            );
        }
    }
}

// ---------- scratch-config naming contract ----------

/// Prefix of every scratch validation-config file name — the exact bytes
/// [`scratch_config_file_name`] emits, never matched loosely.
const SCRATCH_CONFIG_PREFIX: &str = "profile-test-";
/// Suffix of every scratch validation-config file name.
const SCRATCH_CONFIG_SUFFIX: &str = ".json";

/// Build the file name for a scratch validation config of `uuid` — the
/// single naming contract both the worker and the startup sweep
/// ([`cleanup_old_scratch_configs`]) share, so the sweep can never grow a
/// second, looser idea of what it may delete.
fn scratch_config_file_name(uuid: &uuid::Uuid) -> String {
    format!(
        "{SCRATCH_CONFIG_PREFIX}{}{SCRATCH_CONFIG_SUFFIX}",
        uuid.simple()
    )
}

/// True when `name` matches the scratch naming contract exactly: the
/// `profile-test-` prefix, a 32-hex-char uuid stem in the lowercase simple
/// form the worker emits, and the `.json` suffix. Uppercase stems,
/// hyphenated uuids, other extensions, and any user config name fail the
/// check — the sweep deletes only what this predicate accepts.
fn is_scratch_config_file_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix(SCRATCH_CONFIG_PREFIX)
        .and_then(|rest| rest.strip_suffix(SCRATCH_CONFIG_SUFFIX))
    else {
        return false;
    };
    stem.len() == 32
        && stem
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Age bound of the startup scratch-config sweep: a scratch file is live
/// only while one `xray run -test` validation runs (bounded to
/// [`apply::VALIDATE_TIMEOUT`], plus the current profile's generate/write),
/// so anything a full day old is necessarily a crash or kill leftover. The
/// day-scale mirrors the crash-report startup sweep (`REPORT_MAX_AGE` in
/// main.rs) and the app-log startup rotation bound (`APP_LOG_MAX_AGE` in
/// app.rs); it stays far above the lifetime of any legitimately live file, so
/// a second instance validating while this sweep runs can never lose a
/// mid-flight scratch config.
const SCRATCH_CONFIG_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Remove scratch validation configs (`profile-test-*.json` — full
/// generated profiles with UUIDs, passwords, private keys) in `dir` whose
/// mtime is at least `max_age` old. A crash or kill mid-validation strands
/// such a file because the worker task — and its [`ScratchConfigGuard`] —
/// dies with the process; this sweep is the next-launch backstop. Mirrors the
/// crash-report cleanup discipline (`cleanup_old_reports` in main.rs):
/// best-effort, mtime-bounded, a future-stamped file counts as recent and is
/// kept, and only regular files whose names match the exact scratch naming
/// contract ([`is_scratch_config_file_name`]) are ever considered — user
/// configs, lookalikes, and subdirectories survive no matter how old. Young
/// files from a concurrent second instance survive via `max_age`. Returns the
/// number of files removed; a missing `dir` is a no-op.
fn cleanup_old_scratch_configs(
    dir: &Path,
    now: std::time::SystemTime,
    max_age: std::time::Duration,
) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for entry in entries {
        // Best-effort housekeeping: an entry that races away or cannot be
        // inspected must not abort the sweep of the remaining entries.
        let Ok(entry) = entry else { continue };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_scratch_config_file_name(name) {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        // A file stamped in the future (clock skew) counts as recent and is
        // kept — the sweep must never delete a file that may be new.
        let age = now
            .duration_since(modified)
            .unwrap_or(std::time::Duration::ZERO);
        if age >= max_age && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Remove scratch validation configs stranded by a crash or kill — the
/// runtime's single entry point for the shell's boot sweep. Age-bounded
/// ([`SCRATCH_CONFIG_MAX_AGE`]) and name-checked against the worker's exact
/// contract, so a live validation of this or a concurrent instance can never
/// lose its scratch config and nothing outside the contract is ever deleted.
/// Returns the number of files removed; a missing config dir is not an error.
pub fn sweep_stale_scratch_configs() -> std::io::Result<usize> {
    cleanup_old_scratch_configs(
        &crate::sys::paths::config_dir(),
        std::time::SystemTime::now(),
        SCRATCH_CONFIG_MAX_AGE,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::{
        ProfileValidationOrigin, ProfileValidationRequest, SCRATCH_CONFIG_MAX_AGE,
        ScratchConfigGuard, cleanup_old_scratch_configs, is_scratch_config_file_name,
        scratch_config_file_name, stage_and_validate, stage_profile, validate,
    };
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ServerProfile, ServersFile, Settings};

    fn request(profiles: Vec<ServerProfile>) -> ProfileValidationRequest {
        ProfileValidationRequest {
            origin: ProfileValidationOrigin::Import,
            lang: Language::En,
            profiles,
            draft_target: None,
            import_source: None,
            servers: crate::model::ServersFile::default(),
            settings: crate::model::Settings::default(),
        }
    }

    #[test]
    fn scratch_config_guard_removes_the_file_on_normal_drop() {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-guard-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile-test-deadbeef.json");
        std::fs::write(&path, b"{}").unwrap();
        {
            let _guard = ScratchConfigGuard::new(path.clone());
            assert!(path.exists(), "the scratch file must exist while owned");
        }
        assert!(
            !path.exists(),
            "dropping the guard must remove the scratch file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scratch_config_guard_removes_the_file_on_panic_abort() {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-guard-abort-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile-test-cafebabe.json");
        std::fs::write(&path, b"{}").unwrap();
        let outcome = std::panic::catch_unwind(|| {
            let _guard = ScratchConfigGuard::new(path.clone());
            panic!("simulated mid-validation abort");
        });
        assert!(outcome.is_err(), "the simulated abort must unwind");
        assert!(
            !path.exists(),
            "aborting mid-validation must still remove the scratch file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scratch_config_guard_survives_a_failed_removal_without_panicking() {
        // `remove_file` on a directory fails on every platform; the guard must
        // log that failure and drop cleanly instead of panicking.
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-guard-fail-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile-test-not-a-file.json");
        std::fs::create_dir_all(&path).unwrap();
        {
            let _guard = ScratchConfigGuard::new(path.clone());
        }
        assert!(
            path.exists(),
            "a failed removal must leave the path untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- scratch-config naming contract ----------

    /// A scratch config whose mtime reads `now - max_age ± margin` needs a
    /// helper: `File::set_modified` is the std-only way to backdate a file
    /// on every platform (mirrors the main.rs crash-report tests).
    fn set_mtime(path: &std::path::Path, time: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open scratch config to set mtime")
            .set_modified(time)
            .expect("set scratch config mtime");
    }

    #[test]
    fn scratch_config_file_name_round_trips_the_writer_contract() {
        let uuid = uuid::Uuid::new_v4();
        let name = scratch_config_file_name(&uuid);
        assert_eq!(
            name,
            format!("profile-test-{}.json", uuid.simple()),
            "the builder must emit the documented profile-test-<uuid>.json shape"
        );
        assert!(
            is_scratch_config_file_name(&name),
            "a name the writer built must satisfy the sweep predicate"
        );
        // Anything outside the exact writer output must fail the predicate:
        // the sweep deletes only what this accepts.
        for lookalike in [
            "profile-test-NotAHexStemThatLongEnough.json", // uppercase + wrong stem
            "profile-test-11111111-2222-3333-4444-555555555555.json", // hyphenated uuid
            "profile-test-deadbeef.json",                  // short stem
            "profile-test-deadbeefdeadbeefdeadbeefdeadbeef.bak", // other extension
            "profile-test-deadbeefdeadbeefdeadbeefdeadbee.json", // 31-hex stem
            "profile-test-deadbeefdeadbeefdeadbeefdeadbeefx.json", // non-hex stem
            "profile-test-.json",                          // empty stem
            "config.json",
            "config.candidate.json",
            "servers.json.broken-123",
        ] {
            assert!(
                !is_scratch_config_file_name(lookalike),
                "{lookalike:?} must not match the scratch naming contract"
            );
        }
    }

    #[test]
    fn startup_sweep_removes_a_scratch_config_stranded_by_kill_mid_validation() {
        // A hard kill mid-validation never runs the worker's guard; the file
        // it wrote stays behind until the next launch's sweep. Backdating is
        // the in-process stand-in for that kill: the file is exactly what
        // the worker writes (contract name, secrets inside).
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-sweep-kill-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now();
        let stranded = dir.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
        std::fs::write(&stranded, b"{\"privateKey\":\"secret\"}").unwrap();
        set_mtime(
            &stranded,
            now - SCRATCH_CONFIG_MAX_AGE - std::time::Duration::from_secs(1),
        );
        let removed = cleanup_old_scratch_configs(&dir, now, SCRATCH_CONFIG_MAX_AGE)
            .expect("cleanup succeeds");
        assert_eq!(removed, 1, "the stranded config must be removed");
        assert!(
            !stranded.exists(),
            "the kill-stranded scratch config must be gone after the sweep"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_sweep_keeps_young_live_files_and_never_touches_user_configs() {
        // A second instance may be validating right now (single-instance
        // guard notwithstanding, a second launch can start while the first's
        // worker is mid-flight): its young scratch config must survive.
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-sweep-live-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now();
        let live = dir.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
        std::fs::write(&live, b"{}").unwrap();
        // A future-stamped file (clock skew) counts as recent too.
        let skewed = dir.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
        std::fs::write(&skewed, b"{}").unwrap();
        set_mtime(&skewed, now + SCRATCH_CONFIG_MAX_AGE);
        // User configs live beside the scratch files and must survive no
        // matter how old they are.
        let user_configs = [
            "config.json",
            "config.candidate.json",
            "config.lastgood.json",
            "config.rollback.json",
        ];
        for name in user_configs {
            let path = dir.join(name);
            std::fs::write(&path, b"{}").unwrap();
            set_mtime(
                &path,
                now - SCRATCH_CONFIG_MAX_AGE - std::time::Duration::from_secs(1),
            );
        }
        let removed = cleanup_old_scratch_configs(&dir, now, SCRATCH_CONFIG_MAX_AGE)
            .expect("cleanup succeeds");
        assert_eq!(removed, 0, "nothing old enough to sweep may exist");
        assert!(live.exists(), "a young live scratch config must survive");
        assert!(skewed.exists(), "a future-stamped config must survive");
        for name in user_configs {
            assert!(
                dir.join(name).exists(),
                "{name} must never be deleted by the scratch sweep"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_sweep_keeps_files_just_under_the_age_limit() {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-sweep-bound-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now();
        let borderline = dir.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
        std::fs::write(&borderline, b"{}").unwrap();
        set_mtime(
            &borderline,
            now - SCRATCH_CONFIG_MAX_AGE + std::time::Duration::from_secs(60),
        );
        let removed = cleanup_old_scratch_configs(&dir, now, SCRATCH_CONFIG_MAX_AGE)
            .expect("cleanup succeeds");
        assert_eq!(removed, 0, "a config under the age bound must be kept");
        assert!(
            borderline.exists(),
            "the bound is pinned: only files at least SCRATCH_CONFIG_MAX_AGE old are removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_sweep_never_removes_lookalikes_or_directories() {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-sweep-contract-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now();
        let ancient = now - SCRATCH_CONFIG_MAX_AGE - std::time::Duration::from_secs(1);
        // Every entry below mimics the scratch shape but is not deletable:
        // the sweep must never remove anything outside the exact naming
        // contract the writer emits.
        let lookalikes = [
            "profile-test-UPPERCASEdeadbeefdeadbeefdeadbeef0.json",
            "profile-test-11111111-2222-3333-4444-555555555555.json",
            "profile-test-nothexnothexnothexnothexnothexno0.json",
            "profile-test.json",
            "profile-test-00000000000000000000000000000000.bak",
        ];
        for name in lookalikes {
            let path = dir.join(name);
            std::fs::write(&path, b"{}").unwrap();
            set_mtime(&path, ancient);
        }
        // A directory whose name matches the scratch pattern exactly must
        // survive (metadata filters regular files before age is consulted).
        let directory = dir.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let removed = cleanup_old_scratch_configs(&dir, now, SCRATCH_CONFIG_MAX_AGE)
            .expect("cleanup succeeds");
        assert_eq!(removed, 0);
        for name in lookalikes {
            assert!(
                dir.join(name).exists(),
                "{name} must never be removed by the scratch sweep"
            );
        }
        assert!(
            directory.is_dir(),
            "directories must never be removed by the scratch sweep"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_sweep_missing_dir_is_a_noop() {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-scratch-sweep-missing-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let removed =
            cleanup_old_scratch_configs(&dir, std::time::SystemTime::now(), SCRATCH_CONFIG_MAX_AGE)
                .expect("a missing scratch dir must not be an error");
        assert_eq!(removed, 0);
    }

    // ---------- in-place staging ----------

    fn import_profile(name: &str, id: &str) -> ServerProfile {
        ServerProfile {
            id: id.to_string(),
            ..ServerProfile::new(name, OutboundModel::new(Protocol::Freedom))
        }
    }

    #[test]
    fn rejected_candidates_roll_back_and_accepted_ones_commit() {
        // The working file is what later candidates are generated against,
        // so a rejection must leave it exactly as it was and an acceptance
        // must stay in it.
        let existing = import_profile("existing", "0123456789abcdef");
        let mut staged = ServersFile {
            profiles: vec![existing.clone()],
            active: Some(existing.id.clone()),
            ..ServersFile::default()
        };

        // A rejected fresh entry: the push is truncated and the `active`
        // backfill an empty file needed for generation is withdrawn.
        let mut empty = ServersFile::default();
        let undo = stage_profile(&mut empty, &import_profile("rejected", "fedcba9876543210"));
        assert!(
            empty.active.is_some(),
            "staging must backfill an active outbound for generation"
        );
        undo.revert(&mut empty);
        assert!(empty.profiles.is_empty(), "the pushed entry must be gone");
        assert!(empty.active.is_none(), "the backfill must be withdrawn");

        // A rejected replacement: the displaced entry returns to its exact
        // position.
        let updated = import_profile("existing-updated", "0123456789abcdef");
        let undo = stage_profile(&mut staged, &updated);
        assert_eq!(staged.profiles[0].name, "existing-updated");
        undo.revert(&mut staged);
        assert_eq!(staged.profiles.len(), 1);
        assert_eq!(staged.profiles[0].name, "existing");

        // An accepted candidate keeps its staging (the caller never applies
        // the undo), so the later ones are generated against it.
        stage_profile(&mut staged, &import_profile("accepted", "0011223344556677"));
        assert_eq!(staged.profiles.len(), 2, "the accepted entry stays staged");
        assert_eq!(staged.profiles[1].id, "0011223344556677");
        assert_eq!(
            staged.active.as_deref(),
            Some("0123456789abcdef"),
            "an existing active choice must not be overwritten"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_generate_rejection_rolls_the_staging_back() {
        // The wiring, not just the undo record: a candidate whose config is
        // rejected before any child runs must leave the working file exactly
        // as it was, so later candidates are staged against accepted state
        // only. An unparsable raw override fails generation up front.
        let existing = import_profile("existing", "0123456789abcdef");
        let mut staged = ServersFile {
            profiles: vec![existing.clone()],
            active: Some(existing.id.clone()),
            ..ServersFile::default()
        };
        let settings = Settings {
            raw_override: Some("not json".to_string()),
            ..Settings::default()
        };
        let candidate = import_profile("candidate", "fedcba9876543210");
        let error = stage_and_validate(&mut staged, &candidate, &settings, Language::En)
            .await
            .expect_err("an unparsable raw override must reject the candidate");
        let prefix = t(Language::En, Key::GenRawOverride)
            .split_once("{}")
            .expect("the raw-override sentence carries one placeholder")
            .0;
        assert!(error.starts_with(prefix), "{error}");
        assert_eq!(
            staged.profiles.len(),
            1,
            "the rejected candidate must be gone"
        );
        assert_eq!(staged.profiles[0].id, "0123456789abcdef");
        assert_eq!(staged.active.as_deref(), Some("0123456789abcdef"));
    }

    // ---------- cooperative cancellation ----------

    #[tokio::test(flavor = "current_thread")]
    async fn an_already_cancelled_request_returns_the_cancel_terminal() {
        // The worker's first cancel boundary runs before any filesystem work,
        // so a request cancelled that early writes no scratch config and
        // reports no partial verdict.
        let profile = ServerProfile::new("cancelled", OutboundModel::new(Protocol::Freedom));
        match validate(request(vec![profile]), &AtomicBool::new(true)).await {
            Ok(_) => panic!("a cancelled request must not report a verdict"),
            Err(error) => assert_eq!(error.diag().key(), Key::SeatValidationCancelled),
        }
    }
}

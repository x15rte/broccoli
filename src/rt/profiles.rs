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
//! ([`super::apply::validate`]). Siblings the model's profile-set pass blocks
//! on are stood in for while a candidate is tested ([`PreparedSet`]), so an
//! unresolved row cannot veto another row's save. The accepted/rejected
//! verdict travels back on the request's own reply channel; nothing is ever
//! persisted, and a rejected profile never reaches the caller's model.
//!
//! The scratch config holds the full generated profile — UUIDs, passwords,
//! private keys — so the worker owns its lifetime through
//! [`ScratchConfigGuard`]: the file is removed on drop, during panic
//! unwinding, and on the worker's own cancellation. Cancellation is
//! cooperative by construction: the worker observes its cancel signal between
//! profiles, so an in-flight `xray -test` child is never hard-aborted while it
//! holds the file open (Windows cannot delete a file a live child keeps open,
//! so an abort would strand plaintext secrets and orphan the child). A crash
//! or kill still strands the file; the next launch's sweep
//! ([`sweep_stale_scratch_configs`], the shell's single entry point) removes
//! stale ones by age under the exact same naming contract.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, t, t_fmt, validation_issue_message};
use crate::links;
use crate::model::settings::Language;
use crate::model::validation::blocking_profile_numbers;
use crate::model::{OutboundModel, Protocol, ServerProfile, ServersFile, Settings};

use super::apply;
use super::cancel::Cancel;
use super::events::AppLogSink;

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
    /// Servers-file snapshot the staged profile is generated into. The
    /// worker moves it into a [`PreparedSet`], which stands in for the rows
    /// the model blocks on; the caller never sees a mutation.
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
/// the cancel signal between profiles. The runtime-owned cancel paths (a
/// record cancelled before its worker ran, a join failure) deliver their own
/// per-kind wording.
pub(crate) fn validation_cancelled() -> DiagError {
    DiagError::from(Diag::new(Key::SeatValidationCancelled))
}

/// The working file one request validates against: the caller's
/// [`ServersFile`] moved in, every row the model's profile-set pass blocks on
/// replaced by a stand-in, then candidates staged one at a time.
///
/// [`Self::build`] reads the stand-in set from the model's own verdict
/// ([`blocking_profile_numbers`]) rather than a second predicate over the
/// profiles, so every rule the generator refuses on is covered: an outbound
/// mark, an empty name, a duplicate id or tag, and the dial graph's dangling
/// hop. A row that is still gated would veto every unrelated candidate before
/// that candidate's own test ran, leaving the user unable to save the row
/// they just fixed.
///
/// A stand-in keeps the row's identity so chain, routing, and balancer
/// references still resolve: same `id`, same `name`, same group, same
/// position, the file's `active` choice untouched, and a default `freedom`
/// outbound. Two rows can name the same generated tag or id, and no stand-in
/// can fix such a duplicate by changing only its outbound, so a stand-in gives
/// up what it cannot hold exclusively: an unnamed row's name, a tag another
/// row already claims — it takes a name no other row claims instead — and an
/// empty or already-claimed id. The tag a chain aims at survives on the row
/// that keeps it (a real row first, else the first stand-in in list order).
///
/// Candidates are staged from the request's own `profiles`, never stood in
/// for, so a candidate carrying its own gate is still real and is rejected
/// with its own message. The first [`Self::stage`] has the sole owner, so no
/// candidate pays a whole-file copy.
pub(crate) struct PreparedSet {
    /// The one working copy. The `Arc` exists only so a candidate's blocking
    /// leg can keep the file alive while it generates, without copying it;
    /// staging replaces or mutates elements of the sole owner in place.
    servers: Arc<ServersFile>,
}

impl PreparedSet {
    /// Build the request's working file: move the caller's file in and stand
    /// in for every row the model's profile-set pass blocks on that is not one
    /// of `candidates`. One model pass decides the stand-in set for the whole
    /// request; [`Self::stage`] checks the contract against the file each
    /// candidate is generated from.
    fn build(mut servers: ServersFile, candidates: &[ServerProfile]) -> Self {
        let blocked = blocking_profile_numbers(&servers.profiles, servers.active.as_deref());
        let candidate_numbers: BTreeSet<usize> = servers
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| {
                candidates
                    .iter()
                    .any(|candidate| candidate.id == profile.id)
            })
            .map(|(index, _)| index + 1)
            .collect();
        let neutralized: BTreeSet<usize> =
            blocked.difference(&candidate_numbers).copied().collect();
        // Rows that stay real keep their generated tags and ids first, so a
        // stand-in never takes a tag or id a live row still answers to. A
        // candidate's row is replaced by the incoming profile when it is
        // staged, so the tag it will hold — not the stored one — is what a
        // stand-in must avoid and what a chain or routing rule may name.
        let mut claimed_tags = BTreeSet::new();
        let mut claimed_ids = BTreeSet::new();
        for (index, profile) in servers.profiles.iter().enumerate() {
            if neutralized.contains(&(index + 1)) {
                continue;
            }
            let incoming = candidates
                .iter()
                .find(|candidate| candidate.id == profile.id)
                .unwrap_or(profile);
            claimed_tags.insert(incoming.tag());
            claimed_ids.insert(incoming.id.clone());
        }
        for number in &neutralized {
            let original = &servers.profiles[number - 1];
            let mut stand_in = stand_in(original);
            if original.name.trim().is_empty() || claimed_tags.contains(&stand_in.tag()) {
                stand_in.name = unique_stand_in_name(original, &claimed_tags);
            }
            if original.id.trim().is_empty() || claimed_ids.contains(&stand_in.id) {
                stand_in.id = uuid::Uuid::new_v4().simple().to_string();
            }
            claimed_tags.insert(stand_in.tag());
            claimed_ids.insert(stand_in.id.clone());
            servers.profiles[number - 1] = stand_in;
        }
        Self {
            servers: Arc::new(servers),
        }
    }

    /// Stage `profile` into the working file in place — replace the entry with
    /// the same id, else append ([`stage_profile`]) — and hand back the undo
    /// record a rejection applies.
    ///
    /// The staged file is the one the generator reads, so this is where the
    /// type's contract is checked: no row but the candidate's own may carry a
    /// blocking finding. A debug-only model pass pays for it; the build cannot
    /// check it, because before staging the candidate still holds its stored
    /// tag and a duplicate is expected to dissolve when it is replaced.
    fn stage(&mut self, profile: &ServerProfile) -> StagingUndo {
        let undo = stage_profile(Arc::make_mut(&mut self.servers), profile);
        debug_assert!(
            {
                let file = &*self.servers;
                let own = file
                    .profiles
                    .iter()
                    .position(|row| row.id == profile.id)
                    .map(|index| index + 1);
                blocking_profile_numbers(&file.profiles, file.active.as_deref())
                    .iter()
                    .all(|number| Some(*number) == own)
            },
            "PreparedSet::stage left a sibling blocking after the candidate was staged"
        );
        undo
    }

    /// Revert a rejected candidate's staging, restoring the file the
    /// accepted candidates left behind.
    fn revert(&mut self, staging: StagingUndo) {
        staging.revert(Arc::make_mut(&mut self.servers));
    }
}

/// The stand-in for a gated row: the row's identity (id, name, group,
/// position, `enabled`) with a default `freedom` outbound. The caller adjusts
/// the name or id when the row cannot hold them exclusively.
fn stand_in(profile: &ServerProfile) -> ServerProfile {
    ServerProfile {
        id: profile.id.clone(),
        name: profile.name.clone(),
        group: profile.group.clone(),
        enabled: profile.enabled,
        outbound: OutboundModel::new(Protocol::Freedom),
        group_title: profile.group_title.clone(),
        ..ServerProfile::default()
    }
}

/// The name a stand-in takes when it must give up its row's generated tag —
/// an unnamed row, or a tag another row already claims. Derived from the
/// original name so the scratch document reads as a stand-in, advanced until
/// no claimed tag matches: a duplicate-tag row cannot be made legal by
/// changing only its outbound.
fn unique_stand_in_name(profile: &ServerProfile, claimed_tags: &BTreeSet<String>) -> String {
    let stem = if profile.name.trim().is_empty() {
        "stand-in"
    } else {
        profile.name.as_str()
    };
    let mut stand_in = stand_in(profile);
    for suffix in 1.. {
        stand_in.name = format!("{stem} (stand-in {suffix})");
        if !claimed_tags.contains(&stand_in.tag()) {
            return stand_in.name;
        }
    }
    unreachable!("the numeric suffix always escapes a finite claimed-tag set")
}

/// Run one accepted request to its terminal: per profile, stage it, generate
/// a config, validate the generated config with `xray run -test`, and
/// accumulate the verdict. `cancel` is observed before the first profile and
/// between profiles — never inside a validation child, whose open file the
/// guard must be allowed to remove.
///
/// An import logs each accepted profile's advisory findings through `log`:
/// the profile imports (they never gate), but the emitted document drops what
/// they name, and the user who pasted a link may never open the editors that
/// would show them amber.
pub(crate) async fn validate(
    request: ProfileValidationRequest,
    cancel: &Cancel,
    log: &AppLogSink,
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
    // One owned working file for the whole request: the caller's file is
    // moved into it, and the blocking leg shares it by pointer while staging
    // mutates the sole owner in place (`Arc::make_mut`), so no candidate ever
    // pays a whole-file copy. The settings travel the same way.
    let mut prepared = PreparedSet::build(servers, &profiles);
    let settings = Arc::new(settings);
    // The scratch directory is created by the write leg, after generation:
    // a candidate whose generation fails reports that error, never a
    // directory failure it would not have reached. The cancel boundary is
    // observed first: a request cancelled before it started does no
    // filesystem work at all.
    if cancel.is_cancelled() {
        return Err(validation_cancelled());
    }
    let directory = crate::sys::paths::config_dir();
    for profile in profiles {
        // Cooperative cancel boundary: the previous iteration's staging was
        // either committed or already reverted, so nothing is left behind
        // and no partial verdict is reported — a cancelled run commits
        // nothing.
        if cancel.is_cancelled() {
            return Err(validation_cancelled());
        }
        let label = if profile.name.is_empty() {
            profile.tag()
        } else {
            profile.name.clone()
        };
        if origin == ProfileValidationOrigin::Import {
            // The advisory findings never refuse the import — they are the
            // profile that is xray-legal and cannot behave as written — so
            // they are logged, one line each, and the import proceeds.
            match links::profile_advisories(&profile) {
                Ok(advisories) => {
                    for issue in &advisories {
                        log.log(
                            Diag::new(Key::LogConfigWarning)
                                .arg(validation_issue_message(issue, lang)),
                        );
                    }
                }
                Err(error) => {
                    rejected.push((label, error.text(lang)));
                    continue;
                }
            }
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

        match stage_and_validate(&mut prepared, &profile, &settings, &directory, lang).await {
            Ok(Ok(())) => accepted.push(profile),
            Ok(Err(message)) => rejected.push((label, message)),
            // The filesystem worker itself failed: terminal for the request,
            // not a verdict for this profile.
            Err(error) => return Err(error),
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
/// config for the staged file and validate it with `xray run -test`.
/// `Ok(Err(..))` is the rejection text as the screen renders it, and the
/// staging has already been reverted: a rejected profile leaves the file that
/// later profiles are generated against holding only accepted candidates.
/// `Err` is the filesystem worker's own failure, which ends the request
/// instead of producing a verdict. (The per-profile whole-file copy this
/// replaced deep-copied every other profile once per candidate, so an import
/// batch of N profiles cost O(N²) copies.)
async fn stage_and_validate(
    prepared: &mut PreparedSet,
    profile: &ServerProfile,
    settings: &Arc<Settings>,
    directory: &Path,
    lang: Language,
) -> Result<Result<(), String>, DiagError> {
    let staging = prepared.stage(profile);
    // The blocking leg holds a pointer clone only while it runs; it has
    // finished by the time the next candidate stages.
    match generate_and_validate(
        Arc::clone(&prepared.servers),
        Arc::clone(settings),
        directory.to_path_buf(),
        lang,
    )
    .await?
    {
        Ok(()) => Ok(Ok(())),
        Err(message) => {
            prepared.revert(staging);
            Ok(Err(message))
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
    // The candidate is what the validation document must exercise: a
    // switched-off profile would otherwise be absent from the generated
    // config, and `xray run -test` would never see its wire shape. The flag
    // lives only in this snapshot — the saved list keeps the user's switch.
    let mut staged_profile = profile.clone();
    staged_profile.enabled = true;
    let mut displaced = None;
    match staged
        .profiles
        .iter()
        .position(|existing| existing.id == profile.id)
    {
        Some(index) => {
            let previous = std::mem::replace(&mut staged.profiles[index], staged_profile);
            displaced = Some((index, previous));
        }
        None => staged.profiles.push(staged_profile),
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

/// One candidate's blocking leg: generate the staged file's config,
/// serialize it, and write it to a scratch file in `directory`, all off the
/// executor ([`apply::on_blocking_pool`]) so the current-thread control
/// plane keeps polling the validation child's pumps and `wait` while the
/// disk works. The snapshot and settings are shared by pointer, so one
/// candidate costs no copy of either. `Ok(Err(..))` is the candidate's
/// rejection text; `Err` is the worker itself failing.
///
/// The scratch file's [`ScratchConfigGuard`] is created inside the blocking
/// leg, the moment the file exists: a cancel while this leg is still in
/// flight drops the guard together with the discardable result instead of
/// stranding plaintext secrets on disk.
async fn write_scratch_config(
    staged: Arc<ServersFile>,
    settings: Arc<Settings>,
    directory: PathBuf,
    lang: Language,
) -> Result<Result<(PathBuf, ScratchConfigGuard), String>, DiagError> {
    apply::on_blocking_pool(move || {
        let outcome: Result<(PathBuf, ScratchConfigGuard), String> = (|| {
            let config =
                crate::r#gen::generate(&staged, &settings).map_err(|error| error.text(lang))?;
            // Generation is judged before the directory is touched: a
            // candidate the generator refuses reports its own error, the
            // same precedence the pre-pool leg had.
            std::fs::create_dir_all(&directory)
                .map_err(|error| t_fmt(lang, Key::SrvScratchConfigDirFailed, &[&error]))?;
            let path = directory.join(scratch_config_file_name(&uuid::Uuid::new_v4()));
            let bytes = serde_json::to_vec_pretty(&config)
                .map_err(|error| t_fmt(lang, Key::SrvScratchConfigSerializeFailed, &[&error]))?;
            std::fs::write(&path, bytes)
                .map_err(|error| t_fmt(lang, Key::SrvScratchConfigWriteFailed, &[&error]))?;
            Ok((path.clone(), ScratchConfigGuard::new(path)))
        })();
        Ok::<_, DiagError>(outcome)
    })
    .await
}

/// Validate one staged candidate: write its generated config to a scratch
/// file ([`write_scratch_config`]) and run that file through `xray run
/// -test` ([`apply::validate`]). The run itself stays on the executor, so
/// the child it spawns is polled by the runtime that owns it. The guard
/// lives to the end of this function, so the scratch config is removed on
/// every path — normal completion, rejection, cancellation, and panic
/// unwinding alike.
async fn generate_and_validate(
    staged: Arc<ServersFile>,
    settings: Arc<Settings>,
    directory: PathBuf,
    lang: Language,
) -> Result<Result<(), String>, DiagError> {
    let (path, _scratch) = match write_scratch_config(staged, settings, directory, lang).await? {
        Ok(written) => written,
        Err(message) => return Ok(Err(message)),
    };
    // The guard is already armed (with the write, before this first
    // cancellable await), so a mid-flight abort cannot leave plaintext
    // profile secrets on disk.
    let (ok, output) = apply::validate(&path).await;
    if ok {
        return Ok(Ok(()));
    }
    let output = output.text(lang);
    if output.trim().is_empty() {
        Ok(Err(t(lang, Key::SrvXrayTestSilent).to_string()))
    } else {
        Ok(Err(output))
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
/// dies with the process; this sweep is the next-launch backstop, driven by
/// the shared [`sweep`](super::sweep::sweep) rule. Only regular files whose
/// names match the exact scratch naming contract
/// ([`is_scratch_config_file_name`]) are ever considered — user configs,
/// lookalikes, and subdirectories survive no matter how old. Young files from
/// a concurrent second instance survive via `max_age`. Returns the number of
/// files removed; a missing `dir` is a no-op.
fn cleanup_old_scratch_configs(
    dir: &Path,
    now: std::time::SystemTime,
    max_age: std::time::Duration,
) -> std::io::Result<usize> {
    super::sweep::sweep(
        dir,
        now,
        max_age,
        super::sweep::Matcher::files(SCRATCH_CONFIG_PREFIX, SCRATCH_CONFIG_SUFFIX)
            .requiring(is_scratch_config_file_name),
        None,
    )
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
    use super::{
        PreparedSet, ProfileValidationOrigin, ProfileValidationRequest, SCRATCH_CONFIG_MAX_AGE,
        ScratchConfigGuard, cleanup_old_scratch_configs, is_scratch_config_file_name,
        scratch_config_file_name, stage_and_validate, stage_profile, validate,
    };
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::validation::{
        Severity, blocking_profile_numbers, validate_outbound, validate_profiles,
    };
    use crate::model::{OutboundModel, Protocol, ServerProfile, ServersFile, Settings};
    use crate::rt::cancel::Cancel;
    use crate::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect};
    use std::sync::Arc;

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

    /// A worker log sink plus the receiver its lines land on, so a test can
    /// assert exactly what an import reported to the Logs screen.
    fn log_sink() -> (
        super::AppLogSink,
        std::sync::mpsc::Receiver<super::super::CoreEvt>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        let sink = super::super::events::EventStream::new(tx, egui::Context::default()).sink();
        (sink, rx)
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
            active: Some(existing.id),
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
        let servers = ServersFile {
            profiles: vec![existing.clone()],
            active: Some(existing.id.clone()),
            ..ServersFile::default()
        };
        let settings = Arc::new(Settings {
            raw_override: Some("not json".to_string()),
            ..Settings::default()
        });
        let directory = crate::sys::paths::config_dir();
        let candidate = import_profile("candidate", "fedcba9876543210");
        let mut prepared = PreparedSet::build(servers, std::slice::from_ref(&candidate));
        let error = stage_and_validate(
            &mut prepared,
            &candidate,
            &settings,
            &directory,
            Language::En,
        )
        .await
        .expect("the filesystem worker itself must not fail")
        .expect_err("an unparsable raw override must reject the candidate");
        let prefix = t(Language::En, Key::GenRawOverride)
            .split_once("{}")
            .expect("the raw-override sentence carries one placeholder")
            .0;
        assert!(error.starts_with(prefix), "{error}");
        assert_eq!(
            prepared.servers.profiles.len(),
            1,
            "the rejected candidate must be gone"
        );
        assert_eq!(prepared.servers.profiles[0].id, "0123456789abcdef");
        assert_eq!(prepared.servers.active.as_deref(), Some("0123456789abcdef"));
    }

    // ---------- sibling gates ----------

    /// A profile carrying the retired `proxySettings` mark a stale stored
    /// file loads: an `Error`-severity finding on its outbound.
    fn marked_profile(name: &str, id: &str) -> ServerProfile {
        let mut profile = import_profile(name, id);
        profile.outbound.retired_proxy_settings = Some(serde_json::json!({"tag": "direct"}));
        profile
    }

    #[test]
    fn a_marked_sibling_does_not_veto_an_unrelated_candidate() {
        // `gen` refuses to generate while the model's profile-set pass blocks
        // on *any* profile in the set, so one unresolved row (a stored
        // `proxySettings` mark) would veto every other row's draft save with
        // the sibling's message. `PreparedSet` stands such siblings in; this
        // drives the same stage-then-generate sequence the worker runs.
        let sibling = marked_profile("stale-sibling", "0123456789abcdef");
        let candidate = import_profile("candidate", "fedcba9876543210");
        let servers = ServersFile {
            profiles: vec![sibling.clone()],
            active: Some(sibling.id.clone()),
            ..ServersFile::default()
        };

        let mut prepared = PreparedSet::build(servers, std::slice::from_ref(&candidate));
        prepared.stage(&candidate);

        match crate::r#gen::generate(&prepared.servers, &Settings::default()) {
            Ok(_) => {}
            Err(error) => panic!(
                "a sibling's mark must not veto an unrelated candidate's generation: {}",
                error.text(Language::En)
            ),
        }

        // The stand-in sits in the sibling's own slot and keeps its identity,
        // so its generated tag still resolves for chain, routing, and
        // balancer references, while carrying no gate of its own.
        assert_eq!(prepared.servers.profiles.len(), 2);
        let stand_in = &prepared.servers.profiles[0];
        assert_eq!(stand_in.id, sibling.id);
        assert_eq!(stand_in.name, sibling.name);
        assert_eq!(stand_in.tag(), sibling.tag());
        assert!(
            validate_outbound(&stand_in.outbound).is_empty(),
            "the stand-in must carry no gate"
        );
        assert_eq!(
            prepared.servers.active.as_deref(),
            Some(sibling.id.as_str()),
            "the file's active choice must survive the stand-in"
        );

        // The request's row keeps the mark it was staged with: building
        // stands a row in inside the working copy it owns, and the caller's
        // data (here the profile captured before the move) is untouched.
        assert_eq!(
            sibling.outbound.retired_proxy_settings,
            Some(serde_json::json!({"tag": "direct"})),
            "the request's row must keep its stored mark"
        );
    }

    #[test]
    fn a_chain_to_a_stood_in_sibling_keeps_its_target_and_the_real_set_stays_gated() {
        // A dial-through profile aims at another row's generated tag. The
        // stand-in keeps that row's id, so the tag still resolves and the
        // chain is not falsely rejected; the real set still yields the
        // sibling's own finding, which is what keeps apply blocked until the
        // user repairs that row.
        let sibling = marked_profile("stale-sibling", "0123456789abcdef");
        let mut candidate = import_profile("dial-through", "fedcba9876543210");
        candidate.outbound.chain_via(sibling.tag());
        let servers = ServersFile {
            profiles: vec![sibling.clone()],
            active: Some(sibling.id.clone()),
            ..ServersFile::default()
        };

        let mut prepared = PreparedSet::build(servers, std::slice::from_ref(&candidate));
        prepared.stage(&candidate);
        let config = crate::r#gen::generate(&prepared.servers, &Settings::default())
            .expect("a chain to a stood-in sibling must still generate");
        let text = serde_json::to_string(&config).expect("the config serializes");
        assert!(
            text.contains(&format!("\"dialerProxy\":\"{}\"", sibling.tag())),
            "the emitted chain target must stay the sibling's tag: {text}"
        );

        assert!(
            validate_profiles(std::slice::from_ref(&sibling), Some(&sibling.id), true)
                .iter()
                .any(|finding| finding.severity == Severity::Error),
            "the real set must keep the sibling's blocking finding for apply"
        );
    }

    /// One sibling that the model's profile-set pass blocks on, beside a
    /// healthy candidate the request validates. The worker must be able to
    /// generate the candidate's document, which means the sibling cannot
    /// reach the generator still gated.
    fn sibling_does_not_veto(siblings: Vec<ServerProfile>) {
        let candidate = import_profile("candidate", "fedcba9876543210");
        let active = siblings
            .first()
            .map(|sibling| sibling.id.clone())
            .unwrap_or_default();
        let servers = ServersFile {
            profiles: siblings,
            active: Some(active),
            ..ServersFile::default()
        };
        let mut prepared = PreparedSet::build(servers, std::slice::from_ref(&candidate));
        prepared.stage(&candidate);
        crate::r#gen::generate(&prepared.servers, &Settings::default()).unwrap_or_else(|error| {
            panic!(
                "a profile-set gate on a sibling must not veto an unrelated candidate: {}",
                error.text(Language::En)
            )
        });
    }

    #[test]
    fn an_unnamed_sibling_does_not_veto_an_unrelated_candidate() {
        // An empty name is the profile-set pass's own gate (`ProfileNameEmpty`)
        // and generates the `[Manual] ` tag: the stand-in carries a name no
        // other row claims, so its tag is legal without naming the user's row.
        sibling_does_not_veto(vec![import_profile("", "0123456789abcdef")]);
    }

    #[test]
    fn a_duplicate_tag_sibling_does_not_veto_an_unrelated_candidate() {
        // Two rows generating one tag block (`ProfileTagDuplicated`), and
        // changing only their outbounds would leave the duplicate in place:
        // the first stand-in keeps the tag, the second takes a name no other
        // row claims.
        sibling_does_not_veto(vec![
            import_profile("duplicate", "0123456789abcdef"),
            import_profile("duplicate", "fedcba9876543210"),
        ]);
    }

    #[test]
    fn a_renamed_duplicate_keeps_the_tag_a_chain_still_names() {
        // Two rows generate one tag and the candidate is one of them, renamed
        // to break the duplicate. The sibling must keep the tag: it is the row
        // that carries it once the candidate is staged under its new name, and
        // a chain through that tag would otherwise lose its target.
        let first = import_profile("duplicate", "0123456789abcdef");
        let second = import_profile("duplicate", "fedcba9876543210");
        let mut dialer = import_profile("dial-through", "0011223344556677");
        dialer.outbound.chain_via(first.tag());
        let servers = ServersFile {
            profiles: vec![first.clone(), second, dialer],
            active: Some(first.id.clone()),
            ..ServersFile::default()
        };
        let mut renamed = first.clone();
        renamed.name = "duplicate fixed".into();

        let mut prepared = PreparedSet::build(servers, std::slice::from_ref(&renamed));
        prepared.stage(&renamed);

        crate::r#gen::generate(&prepared.servers, &Settings::default()).unwrap_or_else(|error| {
            panic!(
                "a renamed duplicate must not orphan a chain to its tag: {}",
                error.text(Language::En)
            )
        });
        assert!(
            prepared
                .servers
                .profiles
                .iter()
                .any(|profile| profile.tag() == first.tag()),
            "the tag the chain names must survive the rename"
        );
    }

    #[test]
    fn a_dangling_chain_sibling_does_not_veto_an_unrelated_candidate() {
        // The dial graph's dangling hop (`OutboundChainMissing`) names only
        // the source tag, so the stand-in set is read from the finding rather
        // than from a per-profile outbound predicate.
        let mut sibling = import_profile("dangling", "0123456789abcdef");
        sibling.outbound.chain_via("no-such-outbound");
        sibling_does_not_veto(vec![sibling]);
    }

    #[test]
    fn building_leaves_no_blocking_finding_on_a_profile_it_did_not_stage() {
        // `PreparedSet::build`'s contract, stated as observable behaviour:
        // the built file's own profile-set verdict blocks only on rows the
        // request validates. Everything else is stood in for, and the
        // candidate's own mark survives — it is staged real so its own
        // findings reject it with its own message.
        let candidate = marked_profile("candidate", "fedcba9876543210");
        let profiles = vec![
            candidate.clone(),
            import_profile("", "1111111111111111"),
            import_profile("duplicate", "2222222222222222"),
            import_profile("duplicate", "3333333333333333"),
            {
                let mut dangling = import_profile("dangling", "4444444444444444");
                dangling.outbound.chain_via("no-such-outbound");
                dangling
            },
        ];
        let servers = ServersFile {
            profiles,
            active: Some("1111111111111111".to_string()),
            ..ServersFile::default()
        };

        let prepared = PreparedSet::build(servers, std::slice::from_ref(&candidate));
        let blocking = blocking_profile_numbers(
            &prepared.servers.profiles,
            prepared.servers.active.as_deref(),
        );
        assert_eq!(
            blocking,
            std::collections::BTreeSet::from([1]),
            "only the candidate's own row may still block: {:?}",
            prepared.servers.profiles
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_candidate_carrying_its_own_mark_is_still_rejected() {
        // The stand-in covers siblings only: the candidate is staged from the
        // request's own profiles, so its own retired-key mark still rejects
        // it — with its own label, not the sibling's.
        let sibling = marked_profile("stale-sibling", "0123456789abcdef");
        let candidate = marked_profile("marked-candidate", "fedcba9876543210");
        let mut request = request(vec![candidate]);
        // The draft flow: the import flow's share-link check would reject a
        // freedom candidate before generation ever sees its mark.
        request.origin = ProfileValidationOrigin::Draft;
        request.servers = ServersFile {
            profiles: vec![sibling],
            active: Some("0123456789abcdef".to_string()),
            ..ServersFile::default()
        };
        let verdict = validate(request, &Cancel::new(), &log_sink().0)
            .await
            .expect("the worker walks the profile list");
        assert!(verdict.accepted.is_empty(), "{:?}", verdict.accepted);
        assert_eq!(verdict.rejected.len(), 1, "{:?}", verdict.rejected);
        let (label, message) = &verdict.rejected[0];
        assert_eq!(label, "marked-candidate");
        assert_eq!(
            message,
            &format!(
                "marked-candidate: {}",
                t(Language::En, Key::SrvProxySettingsRemoved)
            ),
            "the candidate must fail on its own finding"
        );
    }

    // ---------- the real core ----------

    /// The five managed-core files the release verify hashes before the
    /// validation child runs. The managed core is user-local state; the test
    /// below seeds a redirected core dir from the real one and skips when the
    /// machine never installed it.
    const MANAGED_CORE_FILES: [&str; 5] = [
        ".broccoli-official-release.json",
        "xray.exe",
        "wintun.dll",
        "geoip.dat",
        "geosite.dat",
    ];

    #[tokio::test(flavor = "current_thread")]
    async fn a_marked_sibling_does_not_veto_a_draft_save_through_the_real_core() {
        // The worker's full path: with the marked sibling stood in for, a
        // healthy candidate reaches `xray run -test` and comes back accepted
        // — the trapped draft save of the reported deadlock now commits.
        //
        // The tree copied below lives in the real `%APPDATA%` root, so the
        // redirect lock is held across the whole body: a concurrent test's
        // redirect must never decide what this test copies, and this test's own
        // redirect must never race a concurrent reader.
        let _appdata_lock = APPDATA_ENV_LOCK.lock().await;
        let managed_core = crate::sys::paths::core_dir();
        let missing: Vec<&str> = MANAGED_CORE_FILES
            .iter()
            .copied()
            .filter(|name| !managed_core.join(name).is_file())
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "skipping the marked-sibling draft-save test: the managed core at {} lacks {}",
                managed_core.display(),
                missing.join(", ")
            );
            return;
        }
        // The copied tree must verify against the compiled release pins;
        // otherwise the worker's `xray -test` leg fails on the core, not on
        // the candidate, and the assertion below would blame the candidate.
        if crate::sys::core_dl::open_verified_core(&managed_core).is_err() {
            eprintln!(
                "skipping the marked-sibling draft-save test: the managed core at {} does not \
                 match the compiled release pins",
                managed_core.display()
            );
            return;
        }
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let seeded_core = crate::sys::paths::core_dir();
        std::fs::create_dir_all(&seeded_core).expect("create redirected core dir");
        for name in MANAGED_CORE_FILES {
            let target = seeded_core.join(name);
            std::fs::copy(managed_core.join(name), &target)
                .unwrap_or_else(|error| panic!("seed {name}: {error}"));
        }

        let sibling = marked_profile("stale-sibling", "0123456789abcdef");
        let candidate = import_profile("candidate", "fedcba9876543210");
        let mut request = request(vec![candidate.clone()]);
        request.origin = ProfileValidationOrigin::Draft;
        request.draft_target = Some(super::ToolTarget::AddDraft {
            profile_id: candidate.id.clone(),
            generation: 1,
        });
        request.servers = ServersFile {
            profiles: vec![sibling.clone()],
            active: Some(sibling.id.clone()),
            ..ServersFile::default()
        };
        let verdict = validate(request, &Cancel::new(), &log_sink().0)
            .await
            .expect("the worker walks the profile list");
        assert!(
            verdict.rejected.is_empty(),
            "the healthy candidate must reach the core and pass: {:?}",
            verdict.rejected
        );
        assert_eq!(verdict.accepted.len(), 1, "{:?}", verdict.accepted);
        assert_eq!(verdict.accepted[0].id, candidate.id);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_import_logs_every_advisory_finding_it_accepts() {
        // The finding never gates the import, but the emitted document drops
        // what it names, and a user who pasted a link never opens the editor
        // that would show it amber. The line must reach the log whatever the
        // core test then reports about the profile.
        let mut outbound = OutboundModel::new(Protocol::Vmess);
        let crate::model::ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings
            .extra
            .insert("alterId".into(), serde_json::json!(1));
        let profile = ServerProfile::new("advisory", outbound);

        let (log, rx) = log_sink();
        let _ = validate(request(vec![profile]), &Cancel::new(), &log).await;

        let lines: Vec<String> = rx
            .try_iter()
            .filter_map(|event| match event {
                super::super::CoreEvt::AppLog(message) => Some(message.text(Language::En)),
                _ => None,
            })
            .collect();
        assert_eq!(lines.len(), 1, "one line per finding: {lines:#?}");
        // Both halves come from the locale table: the log key's template and
        // the finding's own message.
        let template = t(Language::En, Key::LogConfigWarning);
        let prefix = template
            .split_once("{}")
            .expect("the log key carries the finding it reports")
            .0;
        assert!(lines[0].starts_with(prefix), "{lines:#?}");
        assert!(
            lines[0].contains(t(Language::En, Key::OutboundVmessAlterIdIgnored)),
            "the line must name the finding it reports: {lines:#?}"
        );
    }

    // ---------- cooperative cancellation ----------

    #[tokio::test(flavor = "current_thread")]
    async fn an_already_cancelled_request_returns_the_cancel_terminal() {
        // The worker's first cancel boundary runs before any filesystem work,
        // so a request cancelled that early writes no scratch config and
        // reports no partial verdict.
        let profile = ServerProfile::new("cancelled", OutboundModel::new(Protocol::Freedom));
        let cancel = Cancel::new();
        cancel.cancel();
        match validate(request(vec![profile]), &cancel, &log_sink().0).await {
            Ok(_) => panic!("a cancelled request must not report a verdict"),
            Err(error) => assert_eq!(error.diag().key(), Key::SeatValidationCancelled),
        }
    }
}

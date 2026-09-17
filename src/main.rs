#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use broccoli::sys::single_instance::SingleInstance;

/// Crash reports older than this are removed at the next launch.
const REPORT_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// Per-user directory that holds persisted panic reports — the same state dir
/// the app already uses (`%APPDATA%\broccoli\state`), never the system temp
/// dir. Resolved lazily so the hook sees test-time `APPDATA` redirects.
fn panic_report_dir() -> PathBuf {
    broccoli::sys::paths::state_dir()
}

/// File name for a crash report, mirroring human-panic's `report-<uuid>.toml`.
fn report_file_name(uuid: &uuid::Uuid) -> String {
    format!("report-{}.toml", uuid.hyphenated())
}

/// On-disk path for the next crash report — a pure function of the report
/// directory and the report id.
fn report_path(dir: &Path, uuid: &uuid::Uuid) -> PathBuf {
    dir.join(report_file_name(uuid))
}

/// Serialize `toml` to `dir/report-<uuid>.toml`, creating `dir` on demand.
fn write_report(dir: &Path, toml: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = report_path(dir, &uuid::Uuid::new_v4());
    std::fs::write(&path, toml)?;
    Ok(path)
}

/// Remove `report-*.toml` files in `dir` whose mtime is at least `max_age`
/// old. Never touches other files or subdirectories, so the state-dir
/// neighbors (settings.json, servers.json, `.broken-*` quarantines) survive.
/// Returns the number of reports removed; a missing `dir` is a no-op.
fn cleanup_old_reports(
    dir: &Path,
    now: SystemTime,
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
        // inspected must not abort cleanup of the remaining reports.
        let Ok(entry) = entry else { continue };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("report-") || !name.ends_with(".toml") {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        // A file stamped in the future (clock skew) counts as recent and is
        // kept — cleanup must never delete a report that may be new.
        let age = now
            .duration_since(modified)
            .unwrap_or(std::time::Duration::ZERO);
        if age >= max_age && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Install the custom panic hook that persists a human-panic report into the
/// per-user state dir and prints the human-readable crash message.
///
/// human-panic 2.0.8 has no API for a custom report path — `handle_dump`
/// hardcodes `env::temp_dir()` inside `Report::persist()` — so the report is
/// generated with human-panic's public `Report::with_panic`/`serialize` and
/// written by us. Console output mirrors `setup_panic!()` exactly.
fn install_panic_hook(meta: human_panic::Metadata) {
    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write as _;

        let report = human_panic::report::Report::with_panic(&meta, info);
        let file_path = match report.serialize() {
            Some(toml) => match write_report(&panic_report_dir(), &toml) {
                Ok(path) => Some(path),
                Err(error) => {
                    // human-panic's fallback: dump the report to stderr when
                    // it cannot be persisted, and print the message without a
                    // file path. `let _ =` is deliberate — panicking inside a
                    // panic hook aborts the process, so write errors here are
                    // ignored the same way human-panic's own hook ignores them.
                    let mut stderr = std::io::stderr().lock();
                    let _ = writeln!(stderr, "broccoli: could not write panic report: {error}");
                    let _ = writeln!(stderr, "{toml}");
                    None
                }
            },
            None => None,
        };
        if let Err(error) = human_panic::print_msg(file_path.as_deref(), &meta) {
            // Same double-panic-avoidance reasoning as above.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "broccoli: could not print panic message: {error}");
        }
    }));
}

/// Mirrors human-panic's `setup_panic!()` selection: only release builds
/// without `RUST_BACKTRACE` get the human-readable crash report; debug builds
/// and backtrace-enabled runs keep the default hook (raw message on stderr).
fn install_panic_reporting() {
    if cfg!(debug_assertions) || std::env::var_os("RUST_BACKTRACE").is_some() {
        return;
    }
    install_panic_hook(human_panic::Metadata::new(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    ));
}

fn main() {
    install_panic_reporting();

    // Next-launch housekeeping: crash reports live in the per-user
    // state dir and stale ones are removed here. Best-effort — a cleanup
    // failure must never block startup.
    if let Err(error) = cleanup_old_reports(&panic_report_dir(), SystemTime::now(), REPORT_MAX_AGE)
    {
        eprintln!("broccoli: panic-report cleanup failed: {error}");
    }

    let args: Vec<String> = std::env::args().collect();

    // Elevated helper mode: no GUI, owns the core on a unique authenticated
    // named pipe. Missing credentials are a hard failure, not a fallback to a
    // well-known privileged endpoint.
    if args.iter().any(|a| a == "--core-helper") {
        let pipe_id = args.iter().find_map(|a| a.strip_prefix("--helper-pipe="));
        // The one-shot auth token travels via the environment block the
        // elevated child inherited from `launch_core_helper`, never via argv:
        // argv is readable by any same-user process for the child's lifetime,
        // the environment block is not. It is removed right after parsing so
        // it cannot leak onward into the helper's own children (the xray core
        // process spawned later).
        let token = std::env::var(broccoli::sys::elevation::HELPER_TOKEN_ENV).ok();
        let parent_pid = broccoli::rt::helper::parse_helper_parent_arg(&args);
        // Cross-user UAC elevation rebuilds the child's environment for the
        // target admin account, so the env token may not survive; the
        // ProgramData token file written by the launching GUI is the fallback
        // channel (same-user elevations keep the env path).
        let token = match token {
            Some(token) => Some(token),
            None => pipe_id.and_then(broccoli::sys::elevation::read_helper_token_file),
        };
        match (pipe_id, token.as_deref(), parent_pid) {
            (Some(pipe_id), Some(token), Ok(parent_pid)) => {
                // SAFETY: this helper process is the sole consumer of
                // HELPER_TOKEN_ENV (the GUI removed it after the launch), and
                // the variable is deleted here before any child process (xray
                // core) is spawned, so no thread in this process reads a torn
                // value and no descendant inherits the secret.
                unsafe { std::env::remove_var(broccoli::sys::elevation::HELPER_TOKEN_ENV) };
                broccoli::rt::helper::run_helper(pipe_id, token, parent_pid)
            }
            _ => {
                eprintln!(
                    "broccoli core-helper: missing or invalid authenticated launch parameters"
                );
                std::process::exit(2);
            }
        }
    }

    // Single instance: a second launch focuses the existing window instead.
    // A mutex that cannot be created at all is a different condition — it is
    // reported and ends startup with a non-zero exit, never mistaken for a
    // quiet second launch (no tracing subscriber exists this early, so the
    // diagnostic goes to stderr).
    let _guard = match broccoli::sys::single_instance::acquire() {
        SingleInstance::Acquired(guard) => guard,
        SingleInstance::AlreadyRunning => return,
        SingleInstance::Unavailable(reason) => {
            eprintln!("broccoli: single-instance mutex unavailable: {reason}");
            std::process::exit(1);
        }
    };

    let run_result = broccoli::run();

    // Exit-time cleanup: `run` returns only after
    // eframe has dropped the app, so the core and the elevated helper are
    // stopped. The filesystem actions run here — after normal shutdown,
    // before the process exits — while the single-instance guard acquired
    // above stays held. The cleanup is idempotent; a residual failure is
    // logged, never fatal (the next launch recreates the app-data dirs via
    // `ensure_dirs`). The requested mode distinguishes a full wipe (Clean Up
    // and Exit) from a reset-to-default, which keeps state/servers.json and
    // core/.
    if let Some(mode) = broccoli::sys::cleanup::take_requested() {
        // Drop the tracing worker guard so no log-file handle stays open
        // when the app-data dirs are wiped below.
        broccoli::app::release_log_guard();
        if let Err(error) =
            broccoli::sys::cleanup::run(mode, &broccoli::sys::paths::broccoli_root())
        {
            eprintln!("broccoli cleanup: app-data cleanup failed: {error:#}");
        }
    }

    if let Err(e) = run_result {
        eprintln!("broccoli GUI failed: {e:?}");
        std::process::exit(1);
    }

    // The process's own teardown is done: state flushed, core and helper
    // stopped, exit-time maintenance finished. What is left is the OS exit
    // path, where third-party code in this process can stall for many seconds
    // and leave the window on screen after Quit. Bound it.
    broccoli::sys::exit_bound::arm(broccoli::sys::exit_bound::TEARDOWN_BOUND);
}

#[cfg(test)]
mod tests {
    use super::*;
    use broccoli::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect};
    use std::time::Duration;

    /// A known RFC-4122 test UUID so the expected file name is a literal.
    const TEST_UUID_STR: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    fn test_uuid() -> uuid::Uuid {
        uuid::Uuid::parse_str(TEST_UUID_STR).expect("static test uuid parses")
    }

    /// Rewrite `path`'s mtime so cleanup age computations are deterministic.
    fn set_mtime(path: &Path, time: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open file to set mtime")
            .set_modified(time)
            .expect("set file mtime");
    }
    /// The report file in `dir` whose *contents* embed `sentinel`, if any.
    ///
    /// Matching on content, not just the `report-*.toml` name, is deliberate:
    /// the panic-hook test installs a process-wide hook, so a sibling test
    /// panicking in the same window would dump a foreign report without the
    /// sentinel into the redirected state dir. `read_dir` order is arbitrary;
    /// such a report must never be selected, or this test would fail
    /// spuriously on top of the sibling's real failure.
    fn find_report_with_sentinel(dir: &Path, sentinel: &str) -> Option<PathBuf> {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("report-") && name.ends_with(".toml"))
                    && std::fs::read_to_string(path)
                        .is_ok_and(|contents| contents.contains(sentinel))
            })
    }

    /// Polls `dir` for a sentinel-bearing report. The hook writes the report
    /// synchronously while unwinding, so the poll only tolerates slow
    /// filesystems; reports without the sentinel are skipped every round.
    fn wait_for_report_with_sentinel(dir: &Path, sentinel: &str) -> Option<PathBuf> {
        for _ in 0..100 {
            if let Some(report) = find_report_with_sentinel(dir, sentinel) {
                return Some(report);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    /// The process-wide panic hook type (see `std::panic::set_hook`).
    type Hook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;
    /// Restores the panic hook taken before the test installed its own.
    struct RestoreHook(Option<Hook>);
    impl Drop for RestoreHook {
        fn drop(&mut self) {
            if let Some(hook) = self.0.take() {
                std::panic::set_hook(hook);
            }
        }
    }

    #[test]
    fn report_path_uses_human_panic_naming() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = report_path(dir.path(), &test_uuid());
        assert_eq!(
            path,
            dir.path().join(format!("report-{TEST_UUID_STR}.toml")),
            "report file names must match human-panic's report-<uuid>.toml pattern"
        );
        assert_eq!(
            report_file_name(&test_uuid()),
            format!("report-{TEST_UUID_STR}.toml")
        );
    }

    #[test]
    fn cleanup_removes_only_old_report_files() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let now = SystemTime::now();

        let old_report = dir
            .path()
            .join("report-11111111-2222-3333-4444-555555555555.toml");
        std::fs::write(&old_report, "old crash").expect("write old report");
        set_mtime(&old_report, now - REPORT_MAX_AGE - Duration::from_secs(1));

        let recent_report = dir
            .path()
            .join("report-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.toml");
        std::fs::write(&recent_report, "recent crash").expect("write recent report");
        // A freshly written file is "now" by default — it must be kept.

        // State-dir neighbors must never be touched, even when very old.
        let settings = dir.path().join("settings.json");
        std::fs::write(&settings, r#"{"proxy":{}}"#).expect("write settings");
        set_mtime(
            &settings,
            now - REPORT_MAX_AGE - Duration::from_secs(90 * 24 * 60 * 60),
        );
        let quarantine = dir.path().join("settings.json.broken-123");
        std::fs::write(&quarantine, "corrupt").expect("write quarantine");
        set_mtime(
            &quarantine,
            now - REPORT_MAX_AGE - Duration::from_secs(90 * 24 * 60 * 60),
        );

        let removed =
            cleanup_old_reports(dir.path(), now, REPORT_MAX_AGE).expect("cleanup succeeds");
        assert_eq!(removed, 1, "exactly the one old report must be removed");
        assert!(!old_report.exists(), "old report must be gone");
        assert!(recent_report.exists(), "recent report must be kept");
        assert!(
            settings.exists(),
            "settings.json must never be deleted by report cleanup"
        );
        assert!(
            quarantine.exists(),
            "quarantine copies must never be deleted by report cleanup"
        );
    }

    #[test]
    fn cleanup_keeps_reports_just_under_the_age_limit() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let now = SystemTime::now();
        let borderline = dir
            .path()
            .join("report-cccccccc-dddd-eeee-ffff-000000000000.toml");
        std::fs::write(&borderline, "crash").expect("write report");
        set_mtime(&borderline, now - REPORT_MAX_AGE + Duration::from_secs(60));

        let removed =
            cleanup_old_reports(dir.path(), now, REPORT_MAX_AGE).expect("cleanup succeeds");
        assert_eq!(removed, 0);
        assert!(borderline.exists());
    }

    #[test]
    fn cleanup_missing_dir_is_a_noop() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let missing = dir.path().join("no-such-dir");
        let removed = cleanup_old_reports(&missing, SystemTime::now(), REPORT_MAX_AGE)
            .expect("missing report dir must not be an error");
        assert_eq!(removed, 0);
    }

    #[test]
    fn cleanup_skips_subdirectories_even_when_old() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let now = SystemTime::now();
        // A directory whose name matches the report pattern must survive.
        // (Its mtime is irrelevant: cleanup filters by regular-file-ness
        // before consulting age, and a directory cannot be opened as a File
        // on Windows, so no mtime manipulation is attempted here.)
        let lookalike = dir
            .path()
            .join("report-deadbeef-dead-beef-dead-beefdeadbeef.toml");
        std::fs::create_dir(&lookalike).expect("create lookalike dir");
        let removed =
            cleanup_old_reports(dir.path(), now, REPORT_MAX_AGE).expect("cleanup succeeds");
        assert_eq!(removed, 0);
        assert!(lookalike.is_dir(), "directories must never be removed");
    }

    #[test]
    fn write_report_persists_toml_and_creates_dir() {
        let base = tempfile::tempdir().expect("create temp dir");
        let dir = base.path().join("state").join("reports"); // does not exist yet
        let toml = "name = \"broccoli\"\ncause = \"boom\"\n";
        let path = write_report(&dir, toml).expect("write_report succeeds");
        assert!(
            path.starts_with(&dir),
            "report must be written into the requested dir"
        );
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("report has a file name");
        assert!(name.starts_with("report-") && name.ends_with(".toml"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back report"),
            toml
        );
    }

    #[test]
    fn sentinel_matching_never_selects_a_foreign_report() {
        // Regression for the process-wide hook window: a sibling test that
        // panics while the panic-hook test's hook is installed would write a
        // foreign report (no sentinel) into the redirected state dir. The
        // matcher must not pick it — `read_dir` order is arbitrary.
        let dir = tempfile::tempdir().expect("create temp dir");
        let foreign = dir
            .path()
            .join("report-11111111-2222-3333-4444-555555555555.toml");
        std::fs::write(&foreign, "cause = \"sibling test panic\"\n").expect("write foreign report");

        assert_eq!(
            find_report_with_sentinel(dir.path(), "sentinel-6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
            None,
            "a report without the sentinel must never be matched"
        );
    }

    #[test]
    fn sentinel_matching_skips_foreign_reports_and_finds_ours() {
        // Both reports present: the sentinel-bearing one must win regardless
        // of `read_dir` order.
        let dir = tempfile::tempdir().expect("create temp dir");
        let foreign = dir
            .path()
            .join("report-11111111-2222-3333-4444-555555555555.toml");
        std::fs::write(&foreign, "cause = \"sibling test panic\"\n").expect("write foreign report");
        let sentinel = "sentinel-6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let ours = dir.path().join(format!("report-{TEST_UUID_STR}.toml"));
        std::fs::write(&ours, format!("cause = \"boom {sentinel}\"\n")).expect("write our report");

        let matched = find_report_with_sentinel(dir.path(), sentinel)
            .expect("the sentinel-bearing report must be found");
        assert_eq!(matched, ours, "the foreign report must be skipped");
    }

    #[test]
    fn panic_hook_writes_report_to_state_dir() {
        // The hook resolves the state dir through `%APPDATA%`; redirect it to
        // a temp dir for the duration of this test. APPDATA is process-global,
        // so the whole test holds the serialization lock.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let root = tempfile::tempdir().expect("create temp APPDATA root");
        let _appdata = AppDataRedirect::to(root.path());

        // The panic hook is process-wide: a sibling test panicking while it is
        // installed would be intercepted and dump a foreign report into the
        // redirected state dir. Restore the previous hook immediately after
        // the single synchronous panic below so the window is as small as the
        // test can make it — it must never cover the polling loop.
        let previous_hook = std::panic::take_hook();
        let hook_guard = RestoreHook(Some(previous_hook));
        install_panic_hook(human_panic::Metadata::new("broccoli-test", "0.0.0-test"));

        let sentinel = format!("sentinel-{}", uuid::Uuid::new_v4());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("{sentinel}");
        }));
        assert!(outcome.is_err(), "panic must be caught for inspection");
        // The hook ran synchronously while unwinding; the report is on disk.
        drop(hook_guard);

        // Poll briefly (slow filesystems cannot flake the assertion), matching
        // only a report that embeds our sentinel: a foreign report from a
        // sibling panic that slipped into the window carries no sentinel and
        // must never be selected (see find_report_with_sentinel's doc).
        let state_dir = root.path().join("broccoli").join("state");
        let report = wait_for_report_with_sentinel(&state_dir, &sentinel)
            .expect("panic hook must write a report into the state dir");
        assert!(
            report.parent() == Some(state_dir.as_path()),
            "report must land in %APPDATA%\\broccoli\\state, not the temp dir: {report:?}"
        );
        let contents = std::fs::read_to_string(&report).expect("read back report");
        assert!(
            contents.contains(&sentinel),
            "report must embed the panic payload"
        );
        assert!(
            contents.contains("crate_version"),
            "report must stay human-panic shaped"
        );
        assert!(
            contents.contains("backtrace"),
            "report must keep the human-panic backtrace"
        );
    }
}

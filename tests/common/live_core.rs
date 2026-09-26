//! The live-core fixture: the machine's core, the isolated app-data root a
//! suite points the app at, and the driver for the events the runtime
//! publishes while that core runs.
//!
//! A suite here needs a real pinned Xray core and a real runtime, and what its
//! siblings share are the pieces an isolated run cannot do without: a loopback
//! port that is free now and stays this suite's, the discovery of the installed
//! core (with the `XRAY_EXE` override that lets a checkout point at a core it
//! fetched itself), the redirect of the app's data root to a throwaway tree,
//! and the reading of the runtime's event channel while the suite waits for
//! what it wants to observe.
//!
//! Opt-in beside `common`, and compiled only by the binaries that declare it.
//! It is declared `pub`, unlike `screen` and `nav`, because these suites need
//! different subsets of it: the two bare-core oracles drive a child and a gRPC
//! client and never start a runtime, while the runtime suites never spawn a
//! child of their own. An item a binary does not call is dead code even when it
//! is `pub`, as long as its module is private, and the repository's
//! `no_lint_suppressions` check forbids the attribute that would silence it —
//! so the module is public and every binary uses the subset its scenario
//! needs:
//!
//! ```text
//! #[path = "common/live_core.rs"]
//! pub mod live_core;
//! ```

use std::ffi::OsString;
use std::fs::File;
use std::net::TcpListener;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use broccoli::rt::CoreEvt;
use parking_lot::{Mutex, MutexGuard};
use tempfile::TempDir;

/// How long one wait on the runtime's event channel blocks before the driver
/// reports a quiet poll. The poll doubles as the hook for work that is not
/// event-driven, so it stays short enough to serve a file that the core
/// rewrites on its own schedule.
const POLL: Duration = Duration::from_millis(250);

/// The managed core tree under the app-data root: the directory an installed
/// app keeps the core and its payloads in.
const MANAGED_CORE: &str = "broccoli/core";

/// The core executable's name, the file every core discovery looks for.
const XRAY_EXE: &str = "xray.exe";

/// The release metadata an installed managed core carries: the record of the
/// build its payloads came from.
const RELEASE_METADATA: &str = ".broccoli-official-release.json";

/// The two geo data payloads, the files whose compares a configured updater
/// suspends and whose retained pair the restore paths verify against.
const GEOIP_DAT: &str = "geoip.dat";
const GEOSITE_DAT: &str = "geosite.dat";

/// The payload set an installed managed core carries: the release metadata the
/// runtime verifies a launch against, and the four files it covers.
const MANAGED_PAYLOAD: [&str; 5] = [
    ".broccoli-official-release.json",
    "xray.exe",
    "wintun.dll",
    "geoip.dat",
    "geosite.dat",
];

/// Ports this process already handed to a suite.
static ISSUED_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// Allocate a free loopback TCP port, unique within this process.
///
/// The ephemeral bind asks the OS for a port it currently considers free; the
/// concrete re-bind right after proves it is still free (a port another
/// process took in that window is retried, not returned), and the record of
/// issued ports keeps two suites of one binary — which cargo runs on parallel
/// threads — from handing the same port to two children.
pub fn free_port() -> u16 {
    for _ in 0..64 {
        let probe =
            TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port for the suite");
        let port = probe
            .local_addr()
            .expect("read the bound loopback port")
            .port();
        drop(probe);
        let mut issued = ISSUED_PORTS.lock();
        if issued.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        issued.push(port);
        return port;
    }
    panic!("no free loopback port after 64 attempts");
}

/// The core a self-skipping suite runs: `XRAY_EXE` when it names a file, else
/// the managed core the app installs (`%APPDATA%\broccoli\core\xray.exe`).
///
/// `None` means this machine has no core, and the suite reports itself skipped.
/// A suite that must not skip takes [`require_managed_core_dir`] instead.
pub fn discover_xray() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("XRAY_EXE") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Some(path);
        }
    }
    let root = PathBuf::from(std::env::var_os("APPDATA")?);
    let managed = root.join(MANAGED_CORE).join(XRAY_EXE);
    managed.is_file().then_some(managed)
}

/// The installed managed core's directory — `%APPDATA%\broccoli\core` — or a
/// panic carrying `reason`.
///
/// The guard for the suites that cannot run without the payloads an install
/// left behind: a missing core must stop the suite where it names its
/// requirement, not halfway through a copy of a tree that was never there. The
/// real `%APPDATA%` is read here, so a suite resolves this directory before it
/// installs any redirect.
pub fn require_managed_core_dir(reason: &str) -> PathBuf {
    let root = PathBuf::from(std::env::var_os("APPDATA").expect("real APPDATA must be available"));
    let core = root.join(MANAGED_CORE);
    assert!(core.join(XRAY_EXE).is_file(), "{reason}");
    core
}

/// Serializes the live-core suites of one binary that redirect `APPDATA`.
///
/// A binary with more than one such test runs them on parallel threads, and an
/// environment variable changed while another thread reads it is undefined
/// behavior: each test takes this lock before it reads the real `%APPDATA%` or
/// installs a redirect, and holds it until everything that read the redirect is
/// gone. A guard bound before the others drops after them.
pub fn appdata_lock() -> MutexGuard<'static, ()> {
    APPDATA_LOCK.lock()
}

/// The process-wide lock [`appdata_lock`] hands out.
static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// Redirect the app's data root (`APPDATA`) to `root` until the guard drops.
///
/// This is the production seam the app itself uses to find its tree under
/// `%APPDATA%\broccoli`, not a test-only override. A binary with more than one
/// live-core suite holds [`appdata_lock`] across the whole redirect, and every
/// runtime and core that reads the tree is stopped before the guard drops.
pub fn redirect_appdata(root: &Path) -> AppDataRedirect {
    let previous = std::env::var_os("APPDATA");
    // SAFETY: the caller serializes this mutation (`appdata_lock`), and the
    // guard restores the variable before the lock it was taken under is
    // released.
    unsafe { std::env::set_var("APPDATA", root) };
    AppDataRedirect { previous }
}

/// [`redirect_appdata`]'s guard: restores the previous `APPDATA` on drop.
pub struct AppDataRedirect {
    previous: Option<OsString>,
}

impl Drop for AppDataRedirect {
    fn drop(&mut self) {
        // SAFETY: restores what the redirect replaced, under the same
        // serialization the redirect itself was installed under.
        unsafe {
            match self.previous.take() {
                Some(previous) => std::env::set_var("APPDATA", previous),
                None => std::env::remove_var("APPDATA"),
            }
        }
    }
}

/// Drain the runtime's event channel until `observe` breaks or `deadline`
/// passes.
///
/// `observe` runs once per event and, with `None`, once after every quiet poll —
/// the hook for work that is not event-driven (reading a file the core
/// rewrites, asking the API for stats), and for a stop condition that a quiet
/// channel must still see. The channel is synchronous and bounded
/// (`rt::EVT_CHANNEL_CAPACITY`), so the runtime blocks when it fills: every
/// event is drained, including the ones the caller has no use for, which is why
/// the driver owns the `recv_timeout` loop instead of leaving each suite to
/// poll the receiver. The stop condition is re-checked after every drained
/// event, so an event that arrives together with the condition's flip is
/// observed by this wait rather than left for the next one.
///
/// A disconnected channel panics with `"runtime stopped {stopped}"`: the
/// runtime is gone, and a suite waiting on it must fail with that fact instead
/// of looking like a slow timeout.
pub fn drive_events(
    receiver: &Receiver<CoreEvt>,
    deadline: Instant,
    stopped: &str,
    mut observe: impl FnMut(Option<CoreEvt>) -> ControlFlow<()>,
) {
    while Instant::now() < deadline {
        match receiver.recv_timeout(POLL) {
            Ok(event) => {
                if observe(Some(event)).is_break() {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if observe(None).is_break() {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => panic!("runtime stopped {stopped}"),
        }
    }
}

/// A throwaway app-data root for one suite: a temporary directory that removes
/// itself, with everything a runtime writes under it, when the value drops.
///
/// The root starts empty; a suite that runs the supervised core fills
/// `broccoli/core` through [`IsolatedRoot::install_managed_core`] or
/// [`IsolatedRoot::install_pinned_core`], then points the app at
/// [`IsolatedRoot::path`] with [`redirect_appdata`]. Bind the root before the
/// redirect guard, so the guard (and the environment restore) drops before the
/// directory is deleted, and keep both alive until every runtime and core that
/// writes here has stopped.
pub struct IsolatedRoot {
    dir: TempDir,
}

impl IsolatedRoot {
    /// A fresh, empty root: no app tree inside yet.
    pub fn empty() -> Self {
        Self {
            dir: tempfile::tempdir().expect("create an isolated APPDATA root"),
        }
    }

    /// The path to redirect `APPDATA` to.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Copy the payload set an installed managed core carries into
    /// `broccoli/core`, and return the created core directory.
    ///
    /// `source` is that installed core's directory
    /// ([`require_managed_core_dir`]); the copy is what an app update finds on
    /// disk: the payloads and the release metadata that names the build they
    /// came from.
    pub fn install_managed_core(&self, source: &Path) -> PathBuf {
        let core = self.core_dir();
        for name in MANAGED_PAYLOAD {
            std::fs::copy(source.join(name), core.join(name)).expect("copy managed core payload");
        }
        core
    }

    /// Copy a discovered core — every file of its own directory, and its
    /// executable as `xray.exe` — into `broccoli/core`, stamp this build's
    /// release pins over the copy, and return the created core directory.
    ///
    /// The pins are what the runtime's managed-core verification reads, so a
    /// copied tree must carry them or the runtime refuses to spawn it. A
    /// core path with no directory to walk (a bare `xray.exe`) still gets the
    /// executable and the pins.
    pub fn install_pinned_core(&self, xray: &Path) -> PathBuf {
        let core = self.core_dir();
        if let Some(source) = xray.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            for entry in std::fs::read_dir(source).expect("list the discovered core directory") {
                let entry = entry.expect("discovered core entry");
                if entry
                    .file_type()
                    .expect("discovered core entry type")
                    .is_file()
                {
                    std::fs::copy(entry.path(), core.join(entry.file_name()))
                        .expect("copy the discovered core file");
                }
            }
        }
        std::fs::copy(xray, core.join(XRAY_EXE)).expect("copy the discovered xray.exe");
        write_release_pins(&core);
        core
    }

    /// `broccoli/core` inside the root, created if it does not exist yet.
    fn core_dir(&self) -> PathBuf {
        let core = self.dir.path().join(MANAGED_CORE);
        std::fs::create_dir_all(&core).expect("create the isolated managed core");
        core
    }
}

/// A managed core for a suite to install from: staged from the pinned release
/// archive when the fixture names one, else the machine's installed core.
///
/// The archive route is what lets a suite run on a machine — and in a CI job —
/// that has no installed core, since the archive the workflow downloads
/// carries the payloads the compiled pins describe. The install route needs
/// `%APPDATA%\broccoli\core` to hold a core; a source with no usable
/// `xray.exe` fails here rather than handing the suite a broken tree.
pub fn managed_core_source(destination: &Path) -> PathBuf {
    if let Some(core) = stage_managed_core_from_archive(destination) {
        return core;
    }
    require_managed_core_dir(
        "the managed core must come from the pinned release archive \
         (BROCCOLI_TEST_XRAY_ARCHIVE) or from an installed core",
    )
}

/// Stage an installed managed core from the pinned release archive.
///
/// The archive a test workflow downloads and verifies already carries the four
/// payloads the compiled pins describe (`xray.exe`, `wintun.dll`, `geoip.dat`,
/// `geosite.dat`), so extracting them yields a tree that passes this build's
/// managed-core verification without an installed core on the machine. The
/// staged tree also gets the retained pristine pair the restore paths verify
/// against, and the release metadata [`write_release_pins`] stamps.
///
/// Returns `None` when `BROCCOLI_TEST_XRAY_ARCHIVE` names no readable file, so
/// a caller can fall back to the machine's install.
pub fn stage_managed_core_from_archive(destination: &Path) -> Option<PathBuf> {
    let archive = PathBuf::from(std::env::var_os("BROCCOLI_TEST_XRAY_ARCHIVE")?);
    if !archive.is_file() {
        return None;
    }
    let file = File::open(&archive).expect("open the pinned release archive");
    let mut zip = zip::ZipArchive::new(file).expect("read the pinned release archive");
    let core = destination.join(MANAGED_CORE);
    std::fs::create_dir_all(&core).expect("create the staged managed core");
    for name in MANAGED_PAYLOAD {
        // The metadata file is this build's own: the archive carries payloads.
        if name == RELEASE_METADATA {
            continue;
        }
        let mut entry = zip.by_name(name).unwrap_or_else(|error| {
            panic!("the pinned release archive must carry {name}: {error}")
        });
        let mut payload = File::create(core.join(name)).expect("create the staged payload");
        std::io::copy(&mut entry, &mut payload).expect("extract the staged payload");
    }
    write_release_pins(&core);
    let pristine = core.join("pristine");
    std::fs::create_dir_all(&pristine).expect("create the retained pristine pair");
    for name in [GEOIP_DAT, GEOSITE_DAT] {
        std::fs::copy(core.join(name), pristine.join(name)).expect("retain the pristine payload");
    }
    Some(core)
}

/// Stamp `core` with the release metadata this build's runtime verifies a
/// managed core against: the archive and payload digests the build compiled
/// in, so a tree copied from the machine's core passes as this build's.
fn write_release_pins(core: &Path) {
    let metadata = serde_json::json!({
        "schema": 3,
        "archive_asset": env!("BROCCOLI_XRAY_ARCHIVE"),
        "archive_sha256": env!("BROCCOLI_XRAY_SHA256"),
        "xray_sha256": env!("BROCCOLI_XRAY_EXE_SHA256"),
        "wintun_sha256": env!("BROCCOLI_WINTUN_SHA256"),
        "geoip_sha256": env!("BROCCOLI_GEOIP_SHA256"),
        "geosite_sha256": env!("BROCCOLI_GEOSITE_SHA256"),
        "version": env!("BROCCOLI_XRAY_VERSION").trim_start_matches('v'),
    });
    std::fs::write(
        core.join(".broccoli-official-release.json"),
        serde_json::to_vec(&metadata).expect("serialize pinned core metadata"),
    )
    .expect("write pinned core metadata");
}

//! Geodata picker search memoization: the picker scans the catalog only when
//! the query text or the dataset changes. An open menu must never rescan per
//! frame (idle purity) and typing must cost exactly one scan per changed query.
//!
//! Safety: same conventions as tests/ui_smoke.rs — APPDATA_LOCK + tempdir
//! isolate env mutation (UB without the process lock), the first-run wizard
//! is dismissed before navigation, and the real `BroccoliApp` is driven
//! headlessly. The geodata catalog fixture is written into the scratch core
//! dir as real protobuf-format files (the `sys::geodata` reader decodes
//! them), so the picker exercises its actual load path.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use std::ffi::OsString;
use std::time::{Duration, Instant};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

struct TempDirectoryEnv {
    tmp: Option<OsString>,
    temp: Option<OsString>,
}

impl TempDirectoryEnv {
    fn set(path: &std::path::Path) -> Self {
        let previous = Self {
            tmp: std::env::var_os("TMP"),
            temp: std::env::var_os("TEMP"),
        };
        // SAFETY: APPDATA_LOCK serializes every test that changes process
        // environment variables used by Broccoli and tempfile.
        unsafe {
            std::env::set_var("TMP", path);
            std::env::set_var("TEMP", path);
        }
        previous
    }
}

impl Drop for TempDirectoryEnv {
    fn drop(&mut self) {
        // SAFETY: the guard restores values while APPDATA_LOCK is held.
        unsafe {
            match self.tmp.take() {
                Some(value) => std::env::set_var("TMP", value),
                None => std::env::remove_var("TMP"),
            }
            match self.temp.take() {
                Some(value) => std::env::set_var("TEMP", value),
                None => std::env::remove_var("TEMP"),
            }
        }
    }
}

fn harness() -> (
    MutexGuard<'static, ()>,
    TempDirectoryEnv,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    let env = TempDirectoryEnv::set(tmp.path());
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes or
    // reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, env, tmp, h)
}

// ---------------------------------------------------------------------------
// geodata fixture: the `sys::geodata` reader decodes real protobuf envelopes
// (outer list: repeated field 1 = entries; entry: string field 1 = code).
// The encoder mirrors `sys::geodata::tests` so the fixture is exact.
// ---------------------------------------------------------------------------

const GEOSITE_CODES: &[&str] = &[
    "cn",
    "google",
    "github",
    "geolocation-!cn",
    "telegram",
    "netflix",
    "cloudflare",
];
const GEOIP_CODES: &[&str] = &["cn", "cloudflare", "netflix"];

fn push_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn push_bytes_field(output: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    push_varint(output, (field_number << 3) | 2);
    push_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn entry(code: &str) -> Vec<u8> {
    let mut output = Vec::new();
    push_bytes_field(&mut output, 1, code.as_bytes());
    output
}

fn list(codes: &[&str]) -> Vec<u8> {
    let mut output = Vec::new();
    for code in codes {
        push_bytes_field(&mut output, 1, &entry(code));
    }
    output
}

/// Write the fixture geodata files into the scratch core dir, so the picker's
/// worker thread loads real catalogs (not error states).
fn seed_geodata(root: &std::path::Path) {
    let core = root.join("broccoli/core");
    std::fs::create_dir_all(&core).unwrap();
    std::fs::write(core.join("geosite.dat"), list(GEOSITE_CODES)).unwrap();
    std::fs::write(core.join("geoip.dat"), list(GEOIP_CODES)).unwrap();
}

// ---------------------------------------------------------------------------
// picker driving helpers
// ---------------------------------------------------------------------------

/// Dismiss the first-run wizard, navigate to Routing, add a rule (opening
/// its inline editor), and open the geosite picker menu.
fn open_geosite_picker(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Routing.label(Language::En),
    )
    .click();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::RoutingAddRule),
    )
    .click();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::GeodataAddGeosite),
    )
    .click();
    // The picker menu opens with a loading spinner while its worker thread
    // reads the catalog; `run()` panics when frames do not settle within
    // its step cap (the load can outlast it under CPU contention), so step
    // explicitly — the caller polls for the loaded-catalog label.
    h.run_steps(4);
}

/// Wall-clock bound for the picker's real-clock catalog load: generous
/// enough that a loaded CI machine cannot fail the wait, finite so a dead
/// worker still fails the test.
const WORKER_DEADLINE: Duration = Duration::from_secs(30);

/// Wait until the picker shows the loaded catalog ("{} codes · {} bytes"),
/// bounded by wall-clock rather than by an iteration budget, so a slow
/// machine only makes the wait longer. Steps explicitly: the loading spinner
/// requests repaints, and `run()` panics when frames do not settle within
/// its step cap while the worker is still loading.
fn wait_for_geodata_load(h: &mut Harness<'static, BroccoliApp>) {
    let deadline = Instant::now() + WORKER_DEADLINE;
    while h.query_by_label_contains("codes").is_none() {
        assert!(
            Instant::now() < deadline,
            "geodata catalog did not load in the picker within {WORKER_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
        h.run_steps(4);
    }
}

/// The picker's search field: the TextInput of the open menu popup. egui
/// builds the AccessKit tree in area order (central panel before popup
/// foreground), so the search box is the last TextInput in the tree.
fn picker_search_input<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .last()
        .expect("the picker search field must be in the tree while the menu is open")
}

// ---------------------------------------------------------------------------
// perf contract tests
// ---------------------------------------------------------------------------

/// Idle-frame purity: with the picker open and a query typed, N idle frames
/// must not rescan the catalog (geodata_searches delta == 0).
#[test]
fn open_picker_idle_frames_never_rescan() {
    let (_lock, _env, _tmp, mut h) = harness();
    seed_geodata(_tmp.path());
    open_geosite_picker(&mut h);
    wait_for_geodata_load(&mut h);

    picker_search_input(&h).focus();
    h.run();
    // A single Text event ("cn" inserted at once) is one query change: one scan.
    picker_search_input(&h).type_text("cn");
    h.run_steps(4);
    assert_eq!(
        h.state().metrics_snapshot().geodata_searches,
        1,
        "the first query must scan exactly once"
    );

    const IDLE_FRAMES: usize = 60;
    let before = h.state().metrics_snapshot().geodata_searches;
    h.run_steps(IDLE_FRAMES);
    let after = h.state().metrics_snapshot().geodata_searches;
    assert_eq!(
        after - before,
        0,
        "idle frames with the picker open must not rescan the catalog"
    );

    // The memoized list still renders the matches of the typed query.
    assert!(
        h.query_all_by_label("geolocation-!cn").next().is_some(),
        "the filtered picker must keep showing matching codes"
    );
}

/// Generation gating: every keystroke that changes the query costs exactly
/// one scan; nothing else does.
#[test]
fn typing_scans_exactly_once_per_keystroke() {
    let (_lock, _env, _tmp, mut h) = harness();
    seed_geodata(_tmp.path());
    open_geosite_picker(&mut h);
    wait_for_geodata_load(&mut h);

    picker_search_input(&h).focus();
    h.run();

    // Build the query "geo" one keystroke at a time; each changed query is
    // exactly one real scan, and nothing else scans (settle frames between).
    for ch in ['g', 'e', 'o'] {
        let before = h.state().metrics_snapshot().geodata_searches;
        picker_search_input(&h).type_text(&ch.to_string());
        h.run_steps(4);
        let after = h.state().metrics_snapshot().geodata_searches;
        assert_eq!(
            after - before,
            1,
            "typing {ch:?} must scan exactly once (before={before}, after={after})"
        );
    }

    // Behavior parity: the filtered list matches a fresh scan of "geo"
    // (only "geolocation-!cn" contains the substring).
    assert!(
        h.query_all_by_label("geolocation-!cn").next().is_some(),
        "the picker must keep rendering codes matching the typed query"
    );
    assert!(
        h.query_all_by_label("google").next().is_none(),
        "codes not matching the typed query must be filtered out"
    );
}

/// The picker's selectable codes come from the loaded catalog (load-path
/// smoke: the fixture files are real geodata format, the worker thread and
/// channel round-trip works, and the menu renders the codes list).
#[test]
fn picker_renders_codes_from_the_loaded_catalog() {
    let (_lock, _env, _tmp, mut h) = harness();
    seed_geodata(_tmp.path());
    open_geosite_picker(&mut h);
    wait_for_geodata_load(&mut h);

    // The catalog label proves the load landed with the full fixture.
    assert!(
        h.query_by_label_contains("7 codes").is_some(),
        "the picker must report the loaded catalog size"
    );
    // The scroll list renders the visible rows of the sorted catalog; the
    // first row is always visible.
    assert!(
        h.query_all_by_label("cn").next().is_some(),
        "picker must render code rows from the fixture catalog"
    );
}

// ---------------------------------------------------------------------------
// routing screen churn: generation-gated tag vectors + rule rows
// ---------------------------------------------------------------------------

/// Dismiss the first-run wizard and navigate to the routing screen.
fn open_routing(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Routing.label(Language::En),
    )
    .click();
    h.run_steps(4);
}

/// Perf contract (acceptance a): idle frames on the routing screen rebuild
/// no tag vectors and no rule-row text — with a rule present and its inline
/// editor open, so the memoized structures are actually exercised.
#[test]
fn routing_idle_frames_rebuild_nothing() {
    let (_lock, _env, _tmp, mut h) = harness();
    open_routing(&mut h);

    // A rule gives the cache real rows; the click also settles the initial
    // build and the post-edit rebuild before the idle window starts.
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::RoutingAddRule),
    )
    .click();
    h.run_steps(8);

    const IDLE_FRAMES: usize = 60;
    let before = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES);
    let after = h.state().metrics_snapshot();
    assert_eq!(
        after.routing_tag_rebuilds - before.routing_tag_rebuilds,
        0,
        "idle frames on the routing screen must not rebuild the tag vectors"
    );
    assert_eq!(
        after.routing_rule_formats - before.routing_rule_formats,
        0,
        "idle frames on the routing screen must not reformat the rule rows"
    );

    // The memoized row still renders (the cache is the live source).
    assert!(
        h.query_all_by_label(t(Language::En, Key::RuleSummaryMatchAll))
            .next()
            .is_some(),
        "the rule row must keep rendering after idle frames"
    );
}

/// Perf contract (acceptance b): one model change through the GUI — adding
/// a rule — triggers exactly one tag-vector rebuild and one rule-row format
/// pass, and the new row renders.
#[test]
fn routing_model_change_rebuilds_exactly_once() {
    let (_lock, _env, _tmp, mut h) = harness();
    open_routing(&mut h);

    // Settle past the first build; the deltas below count only the edit.
    let before = h.state().metrics_snapshot();

    // One model change via the GUI: Add Rule pushes a new rule and opens
    // its inline editor.
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::RoutingAddRule),
    )
    .click();
    h.run_steps(8);

    let after = h.state().metrics_snapshot();
    assert_eq!(
        after.routing_tag_rebuilds - before.routing_tag_rebuilds,
        1,
        "one model change must rebuild the tag vectors exactly once"
    );
    assert_eq!(
        after.routing_rule_formats - before.routing_rule_formats,
        1,
        "one model change must format the rule rows exactly once"
    );

    // Behavior parity: the new (empty) rule renders its memoized match-all
    // summary instead of the "no rules" hint.
    assert!(
        h.query_all_by_label(t(Language::En, Key::RuleSummaryMatchAll))
            .next()
            .is_some(),
        "the new rule's row must render its memoized summary"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::RoutingNoRules))
            .next()
            .is_none(),
        "the no-rules hint must be gone once a rule exists"
    );
}

//! Headless frame benchmark.
//!
//! Boots the real `BroccoliApp` in the kittest eframe harness under a temp
//! `APPDATA` (the `tests/ui_smoke.rs` convention: [`APPDATA_LOCK`] + tempdir
//! isolation), navigates to every instrumented screen, runs a fixed frame
//! window per screen, and prints per-screen frame-time stats — frame count and
//! mean from the metrics frame accumulator, p95 from the wall-clock per-frame
//! distribution of the window (nearest rank). Runs at 0/5/20/50/100 seeded
//! profiles so the O(profiles) curve is measured across the spread (100p is
//! this round's head-of-curve cell).
//!
//! The harness is headless: `Harness::new_eframe` builds a plain
//! `egui::Context` and a stub `CreationContext`/`Frame` (no winit window, no
//! event loop), and the benchmark boots the app through
//! [`BroccoliApp::new_headless`] so a test run neither opens a window nor
//! lights up the notification area. Nothing in this binary spawns the app
//! binary — a long-running sampling session has no place in the suite and is
//! deliberately not provided here.
//!
//! Safety: every test that mutates or reads the process `APPDATA`/`TMP`/`TEMP`
//! env vars holds [`APPDATA_LOCK`].

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::settings::Language;
use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// shared test plumbing
// ---------------------------------------------------------------------------

/// Serializes every test in this binary that mutates or reads the process
/// env vars (the `tests/ui_smoke.rs` convention: env mutation while another
/// thread reads is undefined behavior). Tests in other binaries have their
/// own process, so nothing crosses binaries.
static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// Saves the env vars this suite redirects and restores them on drop. Tests
/// within one binary run in arbitrary order, so a leaked redirect would corrupt
/// whatever runs next.
struct EnvGuard {
    appdata: Option<OsString>,
    tmp: Option<OsString>,
    temp: Option<OsString>,
}

impl EnvGuard {
    /// Redirect `APPDATA`/`TMP`/`TEMP` to `appdata`. Callers hold
    /// [`APPDATA_LOCK`].
    fn redirect(appdata: &Path) -> Self {
        let guard = Self {
            appdata: std::env::var_os("APPDATA"),
            tmp: std::env::var_os("TMP"),
            temp: std::env::var_os("TEMP"),
        };
        // SAFETY: every caller holds APPDATA_LOCK, which serializes all env
        // mutation and reads in this test binary; no other thread observes a
        // torn variable.
        unsafe {
            std::env::set_var("APPDATA", appdata);
            std::env::set_var("TMP", appdata);
            std::env::set_var("TEMP", appdata);
        }
        guard
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        fn restore(name: &str, previous: &Option<OsString>) {
            // SAFETY: the guard drops while its caller still holds
            // APPDATA_LOCK (the guard is stored next to the lock guard in the
            // same tuple), so the restore cannot race another env access.
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        restore("APPDATA", &self.appdata);
        restore("TMP", &self.tmp);
        restore("TEMP", &self.temp);
    }
}
/// The 12 client-side outbound protocols, cycled so every seed size mixes
/// protocol types (vmess/trojan/… next to vless).
const PROTOCOLS: [Protocol; 12] = [
    Protocol::Vless,
    Protocol::Vmess,
    Protocol::Trojan,
    Protocol::Shadowsocks,
    Protocol::Socks,
    Protocol::Http,
    Protocol::Wireguard,
    Protocol::Freedom,
    Protocol::Blackhole,
    Protocol::Dns,
    Protocol::Loopback,
    Protocol::Hysteria,
];

/// Every Nth profile carries a deliberately large raw config (tens of KiB),
/// so the raw-preservation editor paths have realistic bulk to render.
const LARGE_RAW_EVERY: usize = 5;

/// Generate a `servers.json` with `count` profiles: mixed protocols, every
/// 5th profile carrying a large raw-config payload. Valid per
/// `ServersFile::load` semantics (round-trips through serde).
fn build_servers_file(count: usize) -> ServersFile {
    let profiles = (0..count)
        .map(|index| {
            let mut profile = ServerProfile::new(
                format!("baseline-{index:02}"),
                OutboundModel::new(PROTOCOLS[index % PROTOCOLS.len()]),
            );
            if index % LARGE_RAW_EVERY == LARGE_RAW_EVERY - 1 {
                profile
                    .extra
                    .insert("rawConfig".into(), large_raw_config(index));
            }
            profile
        })
        .collect();
    ServersFile {
        version: 1,
        active: None,
        profiles,
        extra: Map::new(),
    }
}

/// A deliberately large raw-config payload (~40 KiB, structured) so the
/// preserved-raw paths in the profile editor deal with realistic bulk.
fn large_raw_config(seed: usize) -> Value {
    json!({
        "kind": "baseline-large-raw",
        "seed": seed,
        "payload": {
            "entries": (0..1024)
                .map(|i| json!({"i": i, "tag": format!("item-{i:04}"), "ok": i % 7 != 0}))
                .collect::<Vec<_>>(),
            "blob": "x".repeat(16 * 1024),
        },
    })
}
// ---------------------------------------------------------------------------
// kittest frame benchmark
// ---------------------------------------------------------------------------

const WARMUP_FRAMES: usize = 10;
const WINDOW_FRAMES: usize = 120;
/// The seeded-profile spread of the frame benchmark: empty, small, medium,
/// large, and the 100p head-of-curve cell.
const BENCH_PROFILE_COUNTS: [usize; 5] = [0, 5, 20, 50, 100];

/// Per-screen frame-window stats.
#[derive(Clone, Copy)]
struct ScreenStats {
    screen: Screen,
    /// Completed frame intervals counted by the metrics accumulator.
    frames: u64,
    /// Mean frame time from the metrics accumulator (ns total / count).
    mean_ms: f64,
    /// Nearest-rank p95 of the wall-clock per-frame distribution.
    p95_ms: f64,
}

/// Nearest-rank percentile of a sorted series: the smallest value at or above
/// the p-quantile. Deterministic for a fixed series.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile of an empty series");
    assert!(p > 0.0 && p <= 1.0, "percentile must be in (0, 1]");
    let rank = (p * sorted.len() as f64).ceil() as usize;
    sorted[rank - 1]
}

/// Boot the app under a temp `APPDATA`, optionally seeding `profile_count`
/// profiles first (written as `state/servers.json` before the harness runs,
/// exactly like the real state layout).
fn harness_with(
    profile_count: usize,
) -> (
    MutexGuard<'static, ()>,
    EnvGuard,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
    Duration,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().expect("benchmark tempdir");
    let guard = EnvGuard::redirect(tmp.path());
    if profile_count > 0 {
        let state = tmp.path().join("broccoli/state");
        std::fs::create_dir_all(&state).expect("seed state dir");
        let servers = build_servers_file(profile_count);
        let bytes = serde_json::to_vec_pretty(&servers).expect("serialize seeded servers");
        std::fs::write(state.join("servers.json"), bytes).expect("write seeded servers.json");
    }
    // Startup timing: the whole blocking first-paint path (font loading,
    // config generation, core payload verification) sits in the app
    // constructor — here the headless one, same code path as `new`.
    let started = Instant::now();
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, guard, tmp, h, started.elapsed())
}

/// A label rendered by the visited screen's own body, proving the nav click
/// actually switched screens (the `ui_smoke` convention). Seeded configs
/// differ on Dashboard (profile list instead of the empty state) and Servers
/// (a profile row instead of the empty state).
fn screen_evidence(screen: Screen, seeded: bool) -> String {
    match screen {
        Screen::Dashboard => {
            if seeded {
                // The phase badge ("Stopped") renders on every screen, so it
                // cannot prove navigation; the active-server section header is
                // Dashboard-only and renders whenever profiles exist.
                t(Language::En, Key::DashboardActiveServer).to_string()
            } else {
                t(Language::En, Key::DashboardNoServers).to_string()
            }
        }
        Screen::Servers => {
            if seeded {
                // The seeded file names no active profile, so the app marks
                // the first row as the default server (● prefix, the config's
                // first outbound): a bare second-row name proves the list
                // rendered without depending on that marker's rendering.
                "baseline-01".into()
            } else {
                t(Language::En, Key::NoServersYet).to_string()
            }
        }
        Screen::ProfilePreview => t(Language::En, Key::PreviewNoLaunch).to_string(),
        Screen::Routing => t(Language::En, Key::RoutingRulesSection).to_string(),
        Screen::Dns => t(Language::En, Key::DnsSectionServers).to_string(),
        Screen::Inbounds => t(Language::En, Key::LocalListeners).to_string(),
        Screen::Tun => t(Language::En, Key::TunSectionIdentity).to_string(),
        Screen::Logs => t(Language::En, Key::LogsCopyAll).to_string(),
        Screen::Settings => t(Language::En, Key::SettingsAppearance).to_string(),
        Screen::About => t_fmt(
            Language::En,
            Key::AboutBroccoliVersion,
            &[&env!("CARGO_PKG_VERSION")],
        ),
    }
}

/// Navigate to `screen`, settle, warm up, then measure a fixed frame window:
/// frame count + mean from the metrics accumulator (the always-on
/// instrumentation), p95 from the wall-clock duration of each step in the
/// window. The accumulator delta must equal the window exactly — any queued
/// event would inflate it and fail loudly instead of silently mis-measuring.
fn bench_screen(
    h: &mut Harness<'static, BroccoliApp>,
    screen: Screen,
    seeded: bool,
) -> ScreenStats {
    h.get_by_role_and_label(egui::accesskit::Role::Button, screen.label(Language::En))
        .click();
    h.run_steps(4);

    // Seeded config: open a profile so the editor (which renders the
    // large raw-config preservation) is part of the Servers window. The
    // seeded file names no active profile, so the first row carries the ●
    // default-server prefix; the second row renders its bare name.
    if seeded && screen == Screen::Servers {
        h.get_by_role_and_label(egui::accesskit::Role::Button, "baseline-01")
            .click();
        h.run_steps(4);
    }

    let evidence = screen_evidence(screen, seeded);
    assert!(
        h.query_all_by_label(evidence.as_str()).next().is_some(),
        "screen {} did not render: its body label {evidence:?} is missing after clicking the nav item",
        screen.label(Language::En),
    );

    h.run_steps(WARMUP_FRAMES);

    let before = h.state().metrics_snapshot();
    let mut wall = Vec::with_capacity(WINDOW_FRAMES);
    for _ in 0..WINDOW_FRAMES {
        let started = Instant::now();
        h.step();
        wall.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let after = h.state().metrics_snapshot();

    let frames = after.frames - before.frames;
    assert_eq!(
        frames,
        WINDOW_FRAMES as u64,
        "screen {}: the frame accumulator must count exactly the window (queued events would inflate it)",
        screen.label(Language::En),
    );
    let mean_ms = (after.frame_ns_total - before.frame_ns_total) as f64 / frames as f64 / 1e6;
    wall.sort_by(|a, b| a.total_cmp(b));
    let p95_ms = percentile(&wall, 0.95);
    ScreenStats {
        screen,
        frames,
        mean_ms,
        p95_ms,
    }
}

/// Boot the app and measure a frame window on every instrumented screen.
fn run_frame_benchmark(profile_count: usize) -> (Vec<ScreenStats>, Duration) {
    let (_lock, _guard, _tmp, mut h, startup) = harness_with(profile_count);
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA → no core → the first-run wizard modal covers the
    // whole screen and swallows nav clicks; dismiss it like ui_smoke.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before benchmarking"
    );

    (
        Screen::ALL
            .iter()
            .copied()
            .map(|screen| bench_screen(&mut h, screen, profile_count > 0))
            .collect(),
        startup,
    )
}

/// The frame benchmark, headless: every instrumented screen, a fixed frame
/// window per screen, per-screen frame count / mean / p95 printed in a table
/// plus a machine-readable `[BASELINE]` line. Run with
/// `-- --nocapture` to see the table.
#[test]
fn frame_benchmark_emits_per_screen_stats() {
    for profile_count in BENCH_PROFILE_COUNTS {
        let (stats, startup) = run_frame_benchmark(profile_count);
        assert_eq!(
            stats.len(),
            Screen::ALL.len(),
            "every screen must be benchmarked"
        );
        for stat in &stats {
            assert_eq!(stat.frames, WINDOW_FRAMES as u64);
            assert!(
                stat.mean_ms > 0.0,
                "{}: mean frame time must be positive",
                stat.screen.label(Language::En)
            );
            assert!(
                stat.p95_ms > 0.0,
                "{}: p95 must be positive",
                stat.screen.label(Language::En)
            );
        }

        println!("==== perf baseline: kittest frame benchmark (profiles={profile_count}) ====");
        println!(
            "{:<14} {:>8} {:>10} {:>10}",
            "screen", "frames", "mean(ms)", "p95(ms)"
        );
        for stat in &stats {
            println!(
                "{:<14} {:>8} {:>10.3} {:>10.3}",
                stat.screen.label(Language::En),
                stat.frames,
                stat.mean_ms,
                stat.p95_ms,
            );
        }
        let screens: Vec<Value> = stats
            .iter()
            .map(|stat| {
                json!({
                    "screen": stat.screen.label(Language::En),
                    "frames": stat.frames,
                    "meanMs": stat.mean_ms,
                    "p95Ms": stat.p95_ms,
                })
            })
            .collect();
        println!(
            "[BASELINE] {}",
            json!({ "profiles": profile_count, "startupMs": startup.as_secs_f64() * 1e3, "screens": screens })
        );
    }
}

#[test]
fn percentile_uses_nearest_rank() {
    let short = vec![1.0, 2.0, 3.0, 4.0];
    assert_eq!(percentile(&short, 0.25), 1.0);
    assert_eq!(percentile(&short, 0.5), 2.0);
    assert_eq!(percentile(&short, 0.95), 4.0);
    assert_eq!(percentile(&short, 1.0), 4.0);
    let long: Vec<f64> = (0..100).map(|i| i as f64).collect();
    assert_eq!(percentile(&long, 0.5), 49.0);
    assert_eq!(percentile(&long, 0.95), 94.0);
    assert_eq!(percentile(&long, 1.0), 99.0);
}

/// The 5/20/50/100 spread: valid servers.json, mixed protocols, a few
/// profiles with deliberately large raw configs.
#[test]
fn servers_file_spread_is_valid_and_mixed() {
    for count in [5usize, 20, 50, 100] {
        let bytes = serde_json::to_vec_pretty(&build_servers_file(count)).expect("serialize");
        let loaded: ServersFile = serde_json::from_slice(&bytes).expect("round-trip parse");
        assert_eq!(loaded.version, 1);
        assert!(loaded.active.is_none());
        assert_eq!(loaded.profiles.len(), count);
        let protocols: HashSet<Protocol> = loaded
            .profiles
            .iter()
            .map(|profile| profile.outbound.protocol)
            .collect();
        assert_eq!(
            protocols.len(),
            count.min(PROTOCOLS.len()),
            "the seed must mix protocol types"
        );
        let with_raw = loaded
            .profiles
            .iter()
            .filter(|p| p.extra.contains_key("rawConfig"))
            .count();
        assert_eq!(
            with_raw,
            count.div_ceil(LARGE_RAW_EVERY),
            "every 5th profile is large"
        );
        let largest_raw = loaded
            .profiles
            .iter()
            .filter_map(|p| p.extra.get("rawConfig"))
            .map(|value| serde_json::to_string(value).expect("serialize raw").len())
            .max()
            .unwrap_or(0);
        assert!(
            largest_raw > 16 * 1024,
            "raw config payload must be large, got {largest_raw} bytes"
        );
    }
}

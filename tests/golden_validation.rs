//! Schema-drift oracle: every golden config in `src/gen/goldens/` must pass the
//! real core's validator (`xray run -test`, exit 0). Requires an xray.exe —
//! located via `$XRAY_EXE` or the managed `%APPDATA%\broccoli\core\xray.exe`.
//! The test is `#[ignore]`d by default so a core-less machine reports it as
//! ignored instead of green-without-running; the body still skips cleanly when
//! the ignore is lifted without a core present.
//! Run with: cargo test --test golden_validation -- --ignored
//! CI (test workflow) downloads the pinned core release (Cargo.toml
//! `[package.metadata.broccoli.release]`, SHA-256-verified), exports it as
//! `XRAY_EXE`, and runs this target with the ignore lifted, so the oracle
//! still executes on every commit.

use std::path::{Path, PathBuf};
use std::process::Command;

fn xray() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XRAY_EXE") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = PathBuf::from(std::env::var_os("APPDATA")?)
        .join("broccoli")
        .join("core")
        .join("xray.exe");
    p.is_file().then_some(p)
}

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("gen")
        .join("goldens")
}

#[test]
#[ignore = "needs a real xray.exe core"]
fn goldens_pass_xray_test() {
    let Some(xray) = xray() else {
        eprintln!("SKIP: no xray.exe (set XRAY_EXE or download the core)");
        return;
    };
    let dir = goldens_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no goldens found in {}", dir.display());

    let mut failures = Vec::new();
    for path in &entries {
        let out = Command::new(&xray)
            .args(["run", "-test", "-config"])
            .arg(path)
            .current_dir(xray.parent().unwrap()) // geoip.dat/geosite.dat lookup
            .output()
            .expect("spawn xray");
        if !out.status.success() {
            failures.push(format!(
                "== {} (exit {:?})\n{}",
                path.file_name().unwrap().to_string_lossy(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} golden(s) rejected by xray run -test:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "validated {} goldens against {}",
        entries.len(),
        xray.display()
    );
}

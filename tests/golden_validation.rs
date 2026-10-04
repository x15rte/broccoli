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

/// Run the real core's config validator on `config`, from the core's own
/// directory so its geo data lookup resolves.
fn run_xray_test(xray: &Path, config: &Path) -> std::process::Output {
    Command::new(xray)
        .args(["run", "-test", "-config"])
        .arg(config)
        .current_dir(xray.parent().expect("the core path has a parent directory"))
        .output()
        .expect("spawn xray")
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
        let out = run_xray_test(&xray, path);
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

/// The import-only schemes must generate a configuration the real core
/// accepts: the link grammar, the model mapping, and the generator are one
/// contract, and only the core judges the last of them. Also covers a #716
/// link whose out-of-grammar parameters are compatibility drops — the drops
/// must not change the accepted configuration.
#[test]
#[ignore = "needs a real xray.exe core"]
fn imported_links_pass_xray_test() {
    let Some(xray) = xray() else {
        eprintln!("SKIP: no xray.exe (set XRAY_EXE or download the core)");
        return;
    };
    // A 32-byte key pair in the hex spelling the model accepts, so the
    // wireguard link needs no encoder here.
    let secret = "01".repeat(32);
    let public = "02".repeat(32);
    let links = [
        "socks5://alice:s3cr3t@127.0.0.1:1080#Socks".to_string(),
        "http://127.0.0.1:8080#Http".to_string(),
        "hysteria2://letmein@example.com:8443?sni=example.com&alpn=h3&obfs=salamander&obfs-password=obfspw&mport=20000-30000&hop_interval=30&upmbps=10&downmbps=50#Hy2"
            .to_string(),
        // The hop range rides the authority in a provider link; no single port
        // names it.
        "hysteria2://letmein@hop.example.com:20000-30000?security=tls&sni=hop.example.com&allowInsecure=true#Hy2Hop"
            .to_string(),
        format!(
            "wg://198.51.100.9:51820?private_key={secret}&public_key={public}&local_address=10.0.0.2%2F32#WG"
        ),
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=example.com&mux=true&packetEncoding=xudp#Compat"
            .to_string(),
    ];
    let mut servers = broccoli::model::ServersFile::default();
    for link in &links {
        let parsed = broccoli::links::parse_link(link)
            .unwrap_or_else(|error| panic!("parse failed: {error}"));
        servers.profiles.push(parsed.profile);
    }
    let config = broccoli::r#gen::generate(&servers, &broccoli::model::Settings::default())
        .expect("generate config");
    let path = std::env::temp_dir().join(format!(
        "broccoli-imported-links-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, config.to_string()).expect("write config");
    let out = run_xray_test(&xray, &path);
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "xray run -test rejected the imported-link config (exit {:?}):\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "validated {} imported links against {}",
        links.len(),
        xray.display()
    );
}

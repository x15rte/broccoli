//! Guards the vendored-fork arrangement: every `[patch.crates-io]` entry must
//! still replace the published crate in `Cargo.lock`, and every fork must still
//! carry its cargo-vet policy.
//!
//! Cargo drops a patch as soon as a dependency moves its crate past the fork's
//! version, and it is quiet about it: the lock records the patch under
//! `[[patch.unused]]`, the build only warns, and `cargo build --locked` exits
//! zero — so a dependency-update pull request that moves the egui family or
//! wgpu silently deletes the fix a fork carries while every gate stays green.
//! That is how an `egui_kittest` bump once dropped both window fixes. This scan
//! reads the three files that encode the arrangement — the patch table in
//! `Cargo.toml`, the resolution in `Cargo.lock`, and the policy in
//! `supply-chain/config.toml` — and fails naming the fork and the step that puts
//! it back.
//!
//! The lock's `[[patch.unused]]` shape cannot be produced on disk here without
//! leaving the tree unresolvable, so it is pinned against a fixture instead
//! (`a_lock_recording_an_unused_patch_is_detected`); every other assertion runs
//! against the repository's own files.

use std::path::Path;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// One `[patch.crates-io]` entry: the patched crate and the fork replacing it.
struct Fork {
    name: String,
    /// The fork's directory, as written in the manifest.
    path: String,
}

/// One `[[package]]` or `[[patch.unused]]` block of `Cargo.lock`.
struct LockEntry {
    name: String,
    version: String,
    /// `Some` when the lock resolved the crate from a registry, `None` when it
    /// resolved locally — which is what a patch that is in effect looks like.
    source: Option<String>,
}

fn read(relative: &str) -> String {
    let path = Path::new(ROOT).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Parse the `[patch.crates-io]` table of `Cargo.toml`.
///
/// Every line of the table must be a `name = { path = "…" }` entry, a comment,
/// or blank; anything else panics, so a patch written in a shape this scan
/// cannot read fails loudly here instead of silently escaping the checks.
fn patch_forks(manifest: &str) -> Vec<Fork> {
    let mut forks = Vec::new();
    let mut in_table = false;
    for (index, raw) in manifest.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_table = line == "[patch.crates-io]";
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_number = index + 1;
        let (name, value) = line.split_once('=').unwrap_or_else(|| {
            panic!(
                "Cargo.toml:{line_number} is not a `name = {{ path = \"…\" }}` patch entry: {line}"
            )
        });
        let path = value
            .trim()
            .strip_prefix('{')
            .and_then(|inner| inner.strip_suffix('}'))
            .and_then(|inner| inner.trim().split_once('='))
            .filter(|(key, _)| key.trim() == "path")
            .map(|(_, path)| path.trim().trim_matches('"'));
        let Some(path) = path else {
            panic!(
                "Cargo.toml:{line_number} carries a patch key this scan does not read (expected `path`): {line}"
            )
        };
        forks.push(Fork {
            name: name.trim().to_string(),
            path: path.to_string(),
        });
    }
    forks
}

/// Parse every `[[package]]` and `[[patch.unused]]` block of `Cargo.lock`.
///
/// Returns the resolved packages and the dropped patches, in file order.
fn lock_entries(lock: &str) -> (Vec<LockEntry>, Vec<LockEntry>) {
    let mut packages = Vec::new();
    let mut unused = Vec::new();
    let mut current: Option<(LockEntry, bool)> = None;
    for raw in lock.lines() {
        let line = raw.trim();
        let start = match line {
            "[[package]]" => Some(false),
            "[[patch.unused]]" => Some(true),
            _ => None,
        };
        if let Some(is_unused) = start {
            if let Some((entry, was_unused)) = current.take() {
                keep(&mut packages, &mut unused, entry, was_unused);
            }
            current = Some((
                LockEntry {
                    name: String::new(),
                    version: String::new(),
                    source: None,
                },
                is_unused,
            ));
            continue;
        }
        let Some((entry, _)) = current.as_mut() else {
            continue;
        };
        if let Some(value) = line.strip_prefix("name = ") {
            entry.name = value.trim().trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("version = ") {
            entry.version = value.trim().trim_matches('"').to_string();
        } else if line.starts_with("source = ") {
            entry.source = Some(line.to_string());
        }
    }
    if let Some((entry, is_unused)) = current {
        keep(&mut packages, &mut unused, entry, is_unused);
    }
    (packages, unused)
}

fn keep(
    packages: &mut Vec<LockEntry>,
    unused: &mut Vec<LockEntry>,
    entry: LockEntry,
    is_unused: bool,
) {
    if is_unused {
        unused.push(entry);
    } else {
        packages.push(entry);
    }
}

/// Parse the crate names `supply-chain/config.toml` marks
/// `audit-as-crates-io = false`.
fn vet_policy_forks(config: &str) -> Vec<String> {
    let mut forks = Vec::new();
    let mut current: Option<String> = None;
    let mut marked = false;
    for raw in config.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            if let Some(name) = current.take()
                && marked
            {
                forks.push(name);
            }
            marked = false;
            current = line
                .strip_prefix("[policy.")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_string);
            continue;
        }
        if current.is_some() && line == "audit-as-crates-io = false" {
            marked = true;
        }
    }
    if let Some(name) = current
        && marked
    {
        forks.push(name);
    }
    forks
}

/// The remedy every failure names, so the red run says what puts the fix back.
fn remedy(fork: &Fork) -> String {
    format!(
        "Re-vendor `{}` at the version the graph now requires, keep its hunks (the patch \
         comment in Cargo.toml lists them), and re-run `cargo update` so the lock resolves \
         the fork again.",
        fork.path
    )
}

#[test]
fn every_vendored_fork_resolves_in_the_lock() {
    let forks = patch_forks(&read("Cargo.toml"));
    assert!(
        !forks.is_empty(),
        "the [patch.crates-io] table parsed as empty, so this scan checks nothing"
    );
    let (packages, unused) = lock_entries(&read("Cargo.lock"));
    assert!(
        unused.is_empty(),
        "Cargo.lock records dropped patches ({}): cargo stopped applying them because a \
         dependency moved those crates past the vendored forks, so the fixes they carry are \
         out of the graph. Re-vendor each fork at the version the graph now requires, keep \
         its hunks (the patch comment in Cargo.toml lists them), and re-run `cargo update` \
         so the lock resolves it again.",
        unused
            .iter()
            .map(|entry| format!("{} {}", entry.name, entry.version))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for fork in &forks {
        assert!(
            packages
                .iter()
                .any(|entry| entry.name == fork.name && entry.source.is_none()),
            "`{}` is patched to `{}`, but Cargo.lock holds no package by that name without a \
             registry source: the patch is not in effect and the published crate is what ships. \
             {}",
            fork.name,
            fork.path,
            remedy(fork)
        );
    }
}

#[test]
fn every_vendored_fork_is_marked_for_cargo_vet() {
    let forks = patch_forks(&read("Cargo.toml"));
    let policy = vet_policy_forks(&read("supply-chain/config.toml"));
    for fork in &forks {
        assert!(
            policy.contains(&fork.name),
            "`{}` is patched to `{}`, but supply-chain/config.toml has no `[policy.{}]` with \
             `audit-as-crates-io = false`: cargo-vet would judge the fork by the published \
             crate's audits. Add the policy entry.",
            fork.name,
            fork.path,
            fork.name
        );
    }
    for name in &policy {
        assert!(
            forks.iter().any(|fork| &fork.name == name),
            "supply-chain/config.toml exempts `{name}` from cargo-vet as a patched crate, but \
             Cargo.toml patches no crate by that name: the entry hides a published crate from \
             the provenance store. Remove it."
        );
    }
}

#[test]
fn a_lock_recording_an_unused_patch_is_detected() {
    // The shape cargo writes when a patch stops applying, in the file's own
    // layout: a resolved package, an unused patch, and a `[[package]]` whose
    // name only appears inside its dependency list.
    let lock = r#"
[[package]]
name = "eframe"
version = "0.36.2"
dependencies = [
 "egui",
]

[[patch.unused]]
name = "wgpu-hal"
version = "30.0.0"

[[package]]
name = "egui"
version = "0.36.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
    let (packages, unused) = lock_entries(lock);
    assert_eq!(
        packages
            .iter()
            .map(|entry| (entry.name.as_str(), entry.source.is_some()))
            .collect::<Vec<_>>(),
        vec![("eframe", false), ("egui", true)],
        "the resolved packages must keep their source so a fork is told apart from a crate"
    );
    assert_eq!(
        unused
            .iter()
            .map(|entry| (entry.name.as_str(), entry.version.as_str()))
            .collect::<Vec<_>>(),
        vec![("wgpu-hal", "30.0.0")],
        "a dropped patch must be reported with the version the fork was pinned to"
    );
}

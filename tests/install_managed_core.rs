//! Install the pinned release into this machine's managed-core tree.
//!
//! The ignored lib oracles that exercise geo-data restore and provenance need
//! a managed core at `%APPDATA%\broccoli\core`: a developer's machine has one,
//! a bare runner does not. This fixture drives the same install funnel the app
//! drives — `core_dl::install_pinned_core_archive`, which refuses an archive
//! that does not match the compiled release pins — from the archive the
//! environment names, so those oracles can run where nothing is installed.
//!
//! It stays `#[ignore]`d because it writes into the machine's own AppData,
//! which the ordinary suite must never do.
//!
//! A machine that already holds an install keeps it: installing over one
//! opens the update path's swap, whose acknowledgement belongs to a runtime's
//! first readiness probe, and this fixture has no runtime to run one. The
//! existing tree is verified instead, so the oracles still find a usable core
//! (or fail naming the file that is not pin-matching, which is the developer's
//! cue to reinstall or remove the tree).

use std::path::PathBuf;

#[test]
#[ignore = "installs the pinned archive into this machine's own AppData for the installed-core oracles"]
fn install_the_pinned_archive_into_the_machine_appdata() {
    let root = PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA must be available"))
        .join("broccoli/core");
    if root.is_dir() {
        drop(
            broccoli::sys::core_dl::open_verified_core(&root)
                .expect("the existing managed core must verify before the oracles read it"),
        );
        return;
    }

    let archive = PathBuf::from(
        std::env::var_os("BROCCOLI_TEST_XRAY_ARCHIVE")
            .expect("BROCCOLI_TEST_XRAY_ARCHIVE must point to the official pinned ZIP"),
    );
    assert!(
        archive.is_file(),
        "BROCCOLI_TEST_XRAY_ARCHIVE must point to a readable ZIP: {}",
        archive.display()
    );

    let installed = broccoli::sys::core_dl::install_pinned_core_archive(&archive)
        .expect("the pinned archive must install into this machine's AppData");
    let expected = broccoli::sys::core_dl::pinned_release_version()
        .strip_prefix('v')
        .expect("the compiled pinned version must carry a v prefix");
    assert_eq!(
        installed, expected,
        "the install must report the compiled pinned version"
    );

    for name in [
        ".broccoli-official-release.json",
        "xray.exe",
        "wintun.dll",
        "geoip.dat",
        "geosite.dat",
    ] {
        assert!(
            root.join(name).is_file(),
            "the installed tree must carry {name}: {}",
            root.display()
        );
    }
    // The oracles below read this tree expecting pin-matching bytes, so the
    // fixture asserts the same full verification every traffic-carrying spawn
    // runs before it hands the tree over.
    drop(broccoli::sys::core_dl::open_verified_core(&root).expect("installed core must verify"));
}

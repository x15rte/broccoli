//! The exe's file icon — what Explorer and the taskbar show for `broccoli.exe`
//! — is the first `RT_GROUP_ICON` resource in the compiled binary: Windows'
//! shell icon extraction (`PrivateExtractIcons`) returns the first group as
//! the file icon. `rc.exe` sorts named icon resources alphabetically and
//! always places named resources before numeric-ID resources, so the app icon
//! must be a *name* that sorts before every state-icon name. `BROCCOLI` is a
//! strict prefix of `BROCCOLI_STOPPED`, `BROCCOLI_CORE_RUNNING`,
//! `BROCCOLI_TUN`, and `BROCCOLI_ERROR`, so it sorts first.
//!
//! This guards the gotcha that originally shipped the play-button broccoli as
//! the exe icon: the neutral icon was declared as `1 ICON` (a numeric ID),
//! rc.exe placed it after the named `BROCCOLI_*` groups, and the shell showed
//! `BROCCOLI_CORE_RUNNING` — the broccoli with the play button — as the file
//! icon even though the neutral broccoli was embedded.

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn app_icon_sorts_before_every_state_icon() {
    let rc = std::fs::read_to_string(std::path::Path::new(ROOT).join("broccoli.rc"))
        .expect("broccoli.rc readable");

    let mut app_icon: Option<&str> = None;
    let mut state_icons: Vec<&str> = Vec::new();
    for line in rc.lines() {
        // Icon group declarations are the only lines carrying ` ICON `; the
        // manifest (`1 24 ...`) and VERSIONINFO lines never do.
        let Some((name, _path)) = line.trim().split_once(" ICON ") else {
            continue;
        };
        if name.starts_with("BROCCOLI_") {
            state_icons.push(name);
        } else {
            assert!(
                app_icon.is_none(),
                "broccoli.rc must declare exactly one app icon, found a second: {name}"
            );
            app_icon = Some(name);
        }
    }

    let app_icon = app_icon.expect("broccoli.rc must declare an app icon");
    assert_eq!(
        state_icons.len(),
        4,
        "all four state icons (stopped/core-running/tun/error) must be declared"
    );
    for state in &state_icons {
        assert!(
            app_icon < *state,
            "app icon {app_icon} must sort before state icon {state} so rc.exe's \
             alphabetical ordering puts the neutral broccoli first for the shell"
        );
    }
}

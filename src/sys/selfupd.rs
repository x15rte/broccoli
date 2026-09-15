//! On-demand Broccoli update check.
//!
//! Broccoli never downloads or replaces its own executable; updating means
//! replacing the app folder with the new release zip. The Settings Updates
//! section offers a "Check for updates" button that fetches the repository's
//! default-branch Cargo.toml over HTTPS, parses the `[package]` version, and
//! compares it strictly against the compiled version. A strictly newer
//! version is surfaced with a link to the repository's `releases/latest`
//! page; every failure degrades to a retryable failed state, and no request
//! is ever made at launch.

use std::fmt;
use std::time::Duration;

/// Repository slug (compile-time constant; moving the repository later is a
/// one-line change here).
const RELEASE_REPO: &str = "x15rte/broccoli";

/// HTTP timeout for one update-check request.
const UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Default-branch guesses, in order. GitHub's default branch is normally
/// `main`; `master` is the historical default of older repositories.
const DEFAULT_BRANCHES: [&str; 2] = ["main", "master"];

fn valid_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn split_repo(repo: &str) -> Option<(&str, &str)> {
    let (owner, name) = repo.split_once('/')?;
    if name.contains('/') || !valid_owner(owner) || !valid_repository_name(name) {
        None
    } else {
        Some((owner, name))
    }
}

fn github_url(repo: &str, suffix: &str) -> Option<String> {
    let (owner, name) = split_repo(repo)?;
    Some(format!("https://github.com/{owner}/{name}{suffix}"))
}

/// Repository home for About-page attribution.
pub fn repository_url() -> Option<String> {
    github_url(RELEASE_REPO, "")
}

/// Manual update destination: the repository's `releases/latest` page. The
/// page is only discovery; the user downloads the versioned zip and replaces
/// the app folder.
pub fn release_url() -> Option<String> {
    github_url(RELEASE_REPO, "/releases/latest")
}

/// A parsed `MAJOR.MINOR.PATCH` version with an optional pre-release suffix
/// (e.g. `1.2.3-alpha.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

impl Version {
    /// Parse a `MAJOR.MINOR.PATCH[-(pre)]` version string (also tolerates
    /// `+build` metadata, which does not affect precedence).
    pub fn parse(text: &str) -> Option<Version> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => {
                // Build metadata (`1.2.3-alpha+build`) does not affect
                // precedence; drop it from the suffix.
                let pre = pre.split_once('+').map_or(pre, |(pre, _)| pre);
                if pre.is_empty() {
                    return None;
                }
                (core, Some(pre.to_string()))
            }
            None => (text.split_once('+').map_or(text, |(core, _)| core), None),
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Strict-greater comparison: the numeric triple
    /// decides first; on equal triples, a version without a pre-release is
    /// greater than one with a pre-release; otherwise `self` is not greater.
    pub fn is_newer_than(&self, other: &Version) -> bool {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
        match self.minor.cmp(&other.minor) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
        match self.patch.cmp(&other.patch) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.pre.is_none() && other.pre.is_some(),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// Recoverable failure parsing a Cargo.toml `[package]` version. Every
/// variant degrades to the check-failed UI state; nothing here panics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// The document has no `[package]` section.
    NoPackageSection,
    /// The `[package]` section has no `version` key.
    NoVersionKey,
    /// The `version` key is not a quoted string literal (e.g.
    /// `version = { workspace = true }`).
    UnsupportedVersion,
    /// The `version` string is not `MAJOR.MINOR.PATCH[-(pre)]`.
    MalformedVersion(String),
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPackageSection => write!(f, "no [package] section in Cargo.toml"),
            Self::NoVersionKey => write!(f, "[package] has no version key"),
            Self::UnsupportedVersion => {
                write!(f, "[package] version is not a quoted string literal")
            }
            Self::MalformedVersion(value) => {
                write!(f, "[package] version {value:?} is not MAJOR.MINOR.PATCH")
            }
        }
    }
}

impl std::error::Error for VersionParseError {}

/// Extracts the `[package]` version from Cargo.toml text.
///
/// Tolerates surrounding whitespace and comments; ignores every other
/// section including `[workspace.package]`; treats
/// `version = { workspace = true }` as unparseable. Missing or malformed
/// content is a recoverable error — callers degrade to the failed state.
pub fn parse_package_version(cargo_toml: &str) -> Result<Version, VersionParseError> {
    let mut in_package = false;
    let mut saw_package = false;
    for line in cargo_toml.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let header = line.trim_matches(['[', ']']).trim();
            in_package = header == "package";
            saw_package |= in_package;
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "version" {
            continue;
        }
        return parse_version_value(value.trim());
    }
    if saw_package {
        Err(VersionParseError::NoVersionKey)
    } else {
        Err(VersionParseError::NoPackageSection)
    }
}

/// Cuts a `#` comment, honoring double-quoted strings (a `#` inside a
/// version string must survive).
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

fn parse_version_value(value: &str) -> Result<Version, VersionParseError> {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return Err(VersionParseError::UnsupportedVersion);
    };
    Version::parse(inner).ok_or_else(|| VersionParseError::MalformedVersion(inner.to_string()))
}

/// The compiled broccoli version, from Cargo metadata at compile time.
pub fn compiled_version() -> Version {
    // `CARGO_PKG_VERSION` is generated by Cargo; build.rs already enforces
    // the MAJOR.MINOR.PATCH shape for the Windows VERSIONINFO resource, so
    // the parse cannot fail in a built binary.
    Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is MAJOR.MINOR.PATCH")
}

/// Terminal state of one on-demand update check. The UI holds an instance
/// (injected for rendering tests); the runtime emits the terminal states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckState {
    /// No check has been requested this session.
    Idle,
    /// A check is in flight; the button is disabled until the terminal state.
    Checking,
    /// The remote repository carries a strictly newer version.
    UpdateAvailable { version: Version },
    /// The remote repository is at or behind the compiled version.
    UpToDate { version: Version },
    /// The check failed (network, HTTP status, or unparseable content);
    /// pressing the button again retries.
    Failed,
}

/// Reduces a fetched remote version to the terminal check state against the
/// compiled version (pure and unit-testable).
pub fn check_outcome(remote: Version) -> UpdateCheckState {
    if remote.is_newer_than(&compiled_version()) {
        UpdateCheckState::UpdateAvailable { version: remote }
    } else {
        UpdateCheckState::UpToDate { version: remote }
    }
}

/// Recoverable failure of the whole check (fetch + parse). Every variant
/// degrades to the failed UI state, never a panic.
#[derive(Debug)]
pub enum UpdateCheckError {
    /// Network/transport failure.
    Http(reqwest::Error),
    /// The server answered with a non-success status.
    HttpStatus(u16),
    /// Neither default-branch guess carries the file (both 404).
    NotFound,
    /// The body could not be parsed into a package version.
    Unparseable(VersionParseError),
}

impl fmt::Display for UpdateCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(f, "update check request failed: {error}"),
            Self::HttpStatus(status) => {
                write!(f, "update check request failed with HTTP {status}")
            }
            Self::NotFound => write!(f, "Cargo.toml not found on main or master"),
            Self::Unparseable(error) => write!(f, "remote Cargo.toml unparseable: {error}"),
        }
    }
}

impl std::error::Error for UpdateCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Unparseable(error) => Some(error),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for UpdateCheckError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

impl From<VersionParseError> for UpdateCheckError {
    fn from(error: VersionParseError) -> Self {
        Self::Unparseable(error)
    }
}

/// Fetches the repository's default-branch Cargo.toml and returns the parsed
/// version. A 404 on `main` retries once with `master`; every other failure
/// (network error, non-2xx, unparseable body) degrades to the failed state.
pub async fn check_for_update(client: &reqwest::Client) -> Result<Version, UpdateCheckError> {
    for branch in DEFAULT_BRANCHES {
        let url = format!("https://raw.githubusercontent.com/{RELEASE_REPO}/{branch}/Cargo.toml");
        let response = client
            .get(&url)
            .header(
                reqwest::header::USER_AGENT,
                crate::sys::core_dl::user_agent(),
            )
            .timeout(UPDATE_CHECK_TIMEOUT)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        if !response.status().is_success() {
            return Err(UpdateCheckError::HttpStatus(response.status().as_u16()));
        }
        let body = response.text().await?;
        return Ok(parse_package_version(&body)?);
    }
    Err(UpdateCheckError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::{
        RELEASE_REPO, UpdateCheckState, Version, VersionParseError, check_outcome, github_url,
        parse_package_version, release_url, repository_url, split_repo,
    };

    #[test]
    fn repository_metadata_requires_a_safe_github_slug() {
        assert_eq!(split_repo("acme/broccoli"), Some(("acme", "broccoli")));
        for invalid in [
            "",
            "acme/",
            "/broccoli",
            "acme/broccoli/extra",
            " acme/broccoli",
            "acme/broccoli ",
            "-acme/broccoli",
            "acme-/broccoli",
            "acme/broccoli?download=1",
            "acme/broccoli#release",
            "https://github.com/acme/broccoli",
        ] {
            assert_eq!(split_repo(invalid), None, "{invalid:?} must be rejected");
        }
    }

    #[test]
    fn update_url_is_fixed_to_githubs_release_page() {
        assert_eq!(
            github_url("acme/broccoli", "/releases/latest").as_deref(),
            Some("https://github.com/acme/broccoli/releases/latest")
        );
        assert_eq!(
            github_url("acme/broccoli?redirect=evil", "/releases/latest"),
            None
        );
    }

    #[test]
    fn urls_point_at_the_compile_time_repository() {
        assert_eq!(RELEASE_REPO, "x15rte/broccoli");
        assert_eq!(
            release_url().as_deref(),
            Some("https://github.com/x15rte/broccoli/releases/latest")
        );
        assert_eq!(
            repository_url().as_deref(),
            Some("https://github.com/x15rte/broccoli")
        );
    }

    #[test]
    fn parses_stable_version() {
        let toml = "[package]\nname = \"broccoli\"\nversion = \"1.2.3\"\n";
        let version = parse_package_version(toml).expect("stable version");
        assert_eq!(version, Version::parse("1.2.3").expect("round trip"));
        assert_eq!(version.to_string(), "1.2.3");
    }

    #[test]
    fn parses_pre_release_version() {
        let toml = "[package]\nversion = \"2.0.0-rc.1\"\n";
        let version = parse_package_version(toml).expect("pre-release version");
        assert_eq!(version.to_string(), "2.0.0-rc.1");
    }

    #[test]
    fn parses_version_amid_whitespace_and_comments() {
        let toml = "\n# leading comment\n  [package]  # section\n\n  version = \"3.4.5\" # trailing comment\n";
        let version = parse_package_version(toml).expect("whitespace and comments tolerated");
        assert_eq!(version.to_string(), "3.4.5");
    }

    #[test]
    fn ignores_workspace_package_section() {
        let toml =
            "[workspace.package]\nversion = \"99.99.99\"\n\n[package]\nversion = \"1.0.0\"\n";
        let version = parse_package_version(toml).expect("workspace version ignored");
        assert_eq!(version.to_string(), "1.0.0");
    }

    #[test]
    fn ignores_package_subtables_and_other_sections() {
        let toml = "\
[workspace]
members = [\".\"]

[package.metadata.foo]
version = \"9.9.9\"

[dependencies]
foo = \"1.0.0\"

[package]
version = \"1.0.0\"
";
        let version = parse_package_version(toml).expect("only the [package] section counts");
        assert_eq!(version.to_string(), "1.0.0");
    }

    #[test]
    fn missing_package_section_is_an_error() {
        assert_eq!(
            parse_package_version(""),
            Err(VersionParseError::NoPackageSection)
        );
        assert_eq!(
            parse_package_version("# only a comment\n"),
            Err(VersionParseError::NoPackageSection)
        );
        assert_eq!(
            parse_package_version("[workspace.package]\nversion = \"1.0.0\"\n[dependencies]\n"),
            Err(VersionParseError::NoPackageSection)
        );
    }

    #[test]
    fn missing_version_key_is_an_error() {
        let toml = "[package]\nname = \"broccoli\"\n";
        assert_eq!(
            parse_package_version(toml),
            Err(VersionParseError::NoVersionKey)
        );
    }

    #[test]
    fn workspace_inherited_version_is_unparseable() {
        let toml = "[package]\nversion = { workspace = true }\n";
        assert_eq!(
            parse_package_version(toml),
            Err(VersionParseError::UnsupportedVersion)
        );
    }

    #[test]
    fn malformed_version_strings_are_errors() {
        for bad in [
            "1.2", "1.2.3.4", "abc", "1.2.x", "1.2.3-", "1..3", "1.2.3-+x",
        ] {
            let toml = format!("[package]\nversion = \"{bad}\"\n");
            assert!(
                matches!(
                    parse_package_version(&toml),
                    Err(VersionParseError::MalformedVersion(_))
                ),
                "{bad:?} must be malformed"
            );
        }
    }

    #[test]
    fn strict_greater_comparison() {
        let v = |text: &str| Version::parse(text).unwrap_or_else(|| panic!("{text}"));
        assert!(v("1.2.4").is_newer_than(&v("1.2.3")));
        assert!(v("1.3.0").is_newer_than(&v("1.2.9")));
        assert!(v("2.0.0").is_newer_than(&v("1.9.9")));
        assert!(!v("1.2.3").is_newer_than(&v("1.2.4")));
        assert!(!v("1.2.3").is_newer_than(&v("1.2.3")));
        // Equal triples: a release is greater than its pre-release.
        assert!(v("1.2.3").is_newer_than(&v("1.2.3-alpha.1")));
        assert!(!v("1.2.3-alpha.1").is_newer_than(&v("1.2.3")));
        // Equal triples with pre-releases on both sides: not greater, even
        // when the suffix strings would order one ahead.
        assert!(!v("1.2.3-beta.1").is_newer_than(&v("1.2.3-alpha.1")));
        assert!(!v("1.2.3-alpha.1").is_newer_than(&v("1.2.3-beta.1")));
        // Pre-release comparisons still follow the numeric triple.
        assert!(v("1.2.4-alpha.1").is_newer_than(&v("1.2.3-beta.9")));
    }

    #[test]
    fn check_outcome_compares_against_the_compiled_version() {
        let compiled = Version::parse(env!("CARGO_PKG_VERSION")).expect("compiled version");
        let mut newer = compiled.clone();
        newer.patch += 1;
        assert_eq!(
            check_outcome(newer.clone()),
            UpdateCheckState::UpdateAvailable { version: newer }
        );
        assert_eq!(
            check_outcome(compiled.clone()),
            UpdateCheckState::UpToDate { version: compiled }
        );
        // The same triple as a pre-release is never newer than the build.
        let prerelease = Version::parse(&format!("{}-pre.1", env!("CARGO_PKG_VERSION")))
            .expect("pre-release of the compiled version");
        assert_eq!(
            check_outcome(prerelease.clone()),
            UpdateCheckState::UpToDate {
                version: prerelease
            }
        );
    }
}

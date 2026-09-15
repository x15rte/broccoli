//! Build-time Windows resources and Xray gRPC client generation.

#[cfg(not(test))]
use std::fs;

use std::{
    env, fmt,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::Command,
};

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(not(test))]
fn windows_file_version(semver: &str) -> Result<[u16; 4], io::Error> {
    let core = semver.split_once('-').map_or(semver, |(core, _)| core);
    let core = core.split_once('+').map_or(core, |(core, _)| core);
    let mut fields = core.split('.');
    let mut version = [0_u16; 4];
    for slot in version.iter_mut().take(3) {
        let field = fields.next().ok_or_else(|| {
            invalid_data(format!(
                "CARGO_PKG_VERSION is not major.minor.patch SemVer: {semver}"
            ))
        })?;
        *slot = field.parse::<u16>().map_err(|_| {
            invalid_data(format!(
                "SemVer component `{field}` does not fit a Windows VERSIONINFO field"
            ))
        })?;
    }
    if fields.next().is_some() {
        return Err(invalid_data(format!(
            "CARGO_PKG_VERSION is not major.minor.patch SemVer: {semver}"
        )));
    }
    Ok(version)
}

/// Renders a path for inclusion in the generated Windows resource script.
///
/// rc.exe reads the resource script as ANSI text, so a non-ASCII component
/// (e.g. an accented username in the build path) cannot be written
/// losslessly: silently substituting U+FFFD corrupts the include path.
/// Such paths are rejected with an error naming the offending
/// component. Verbatim (`\\?\`) prefixes are stripped so the rendered path
/// is a plain drive/UNC path using forward slashes.
fn rc_path(path: &Path) -> Result<String, io::Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from(
            env::var_os("CARGO_MANIFEST_DIR")
                .ok_or_else(|| invalid_data("Cargo did not provide CARGO_MANIFEST_DIR"))?,
        )
        .join(path)
    };
    let rendered = absolute.to_str().ok_or_else(|| {
        invalid_data(format!(
            "resource path {} is not valid Unicode; rc.exe cannot embed it, move the \
                 crate to an ASCII-only path (see build.rs)",
            absolute.display()
        ))
    })?;
    if !rendered.is_ascii() {
        let offending = absolute
            .components()
            .find_map(|component| {
                let component = component.as_os_str().to_string_lossy();
                (!component.is_ascii()).then(|| component.into_owned())
            })
            .unwrap_or_else(|| absolute.to_string_lossy().into_owned());
        return Err(invalid_data(format!(
            "resource path {} contains non-ASCII component {offending}; rc.exe cannot \
             embed it, move the crate to an ASCII-only path (see build.rs)",
            absolute.display()
        )));
    }
    let mut rendered = rendered.to_owned();
    const VERBATIM_UNC: &str = r"\\?\UNC\";
    const VERBATIM_LOCAL: &str = r"\\?\";
    if rendered.starts_with(VERBATIM_UNC) {
        rendered.replace_range(..VERBATIM_UNC.len(), r"\\");
    } else if rendered.starts_with(VERBATIM_LOCAL) {
        rendered.replace_range(..VERBATIM_LOCAL.len(), "");
    }
    Ok(rendered.replace('\\', "/"))
}

#[cfg(not(test))]
fn require_token(template: &str, token: &str, source: &str) -> Result<(), io::Error> {
    if template.contains(token) {
        Ok(())
    } else {
        Err(invalid_data(format!("{source} is missing token {token}")))
    }
}

#[cfg(not(test))]
fn release_metadata_value(manifest: &str, key: &str) -> Result<String, io::Error> {
    let mut in_release = false;
    let mut found = None;
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_release = line == "[package.metadata.broccoli.release]";
            continue;
        }
        if !in_release || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((candidate, value)) = line.split_once('=') else {
            continue;
        };
        if candidate.trim() != key {
            continue;
        }
        let value = value.trim();
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return Err(invalid_data(format!(
                "Cargo release metadata `{key}` must be a quoted string"
            )));
        };
        if found.replace(value.to_owned()).is_some() {
            return Err(invalid_data(format!(
                "Cargo release metadata `{key}` is declared more than once"
            )));
        }
    }
    found.ok_or_else(|| invalid_data(format!("Cargo release metadata `{key}` is missing")))
}

#[cfg(not(test))]
fn emit_xray_release_metadata() -> Result<(), io::Error> {
    let manifest = fs::read_to_string("Cargo.toml")?;
    let values = [
        ("BROCCOLI_XRAY_VERSION", "xray_version"),
        ("BROCCOLI_XRAY_ARCHIVE", "xray_archive"),
        ("BROCCOLI_XRAY_SHA256", "xray_sha256"),
        ("BROCCOLI_XRAY_EXE_SHA256", "xray_executable_sha256"),
        ("BROCCOLI_WINTUN_SHA256", "wintun_sha256"),
        ("BROCCOLI_GEOIP_SHA256", "geoip_sha256"),
        ("BROCCOLI_GEOSITE_SHA256", "geosite_sha256"),
    ];
    for (environment, key) in values {
        let value = release_metadata_value(&manifest, key)?;
        let valid = match key {
            "xray_version" => value.strip_prefix('v').is_some_and(|version| {
                let fields: Vec<_> = version.split('.').collect();
                fields.len() == 3
                    && fields.iter().all(|field| {
                        !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit())
                    })
            }),
            "xray_archive" => value == "Xray-windows-64.zip",
            _ => {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
        };
        if !valid {
            return Err(invalid_data(format!(
                "Cargo release metadata `{key}` is invalid"
            )));
        }
        println!("cargo:rustc-env={environment}={value}");
    }
    Ok(())
}

#[cfg(not(test))]
fn generate_windows_resources() -> Result<(), Box<dyn std::error::Error>> {
    let semver = env::var("CARGO_PKG_VERSION")?;
    let [major, minor, patch, revision] = windows_file_version(&semver)?;
    let file_version = format!("{major}.{minor}.{patch}.{revision}");
    let file_version_commas = format!("{major},{minor},{patch},{revision}");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
        invalid_data("Cargo did not provide OUT_DIR for Windows resource generation")
    })?);

    let manifest_template = fs::read_to_string("assets/app.manifest")?;
    require_token(
        &manifest_template,
        "@BROCCOLI_FILE_VERSION@",
        "assets/app.manifest",
    )?;
    let generated_manifest = out_dir.join("broccoli.manifest");
    fs::write(
        &generated_manifest,
        manifest_template.replace("@BROCCOLI_FILE_VERSION@", &file_version),
    )?;

    let rc_template = fs::read_to_string("broccoli.rc")?;
    for token in [
        "@BROCCOLI_ICON_PATH@",
        "@BROCCOLI_STOPPED_ICON_PATH@",
        "@BROCCOLI_CORE_RUNNING_ICON_PATH@",
        "@BROCCOLI_TUN_ICON_PATH@",
        "@BROCCOLI_ERROR_ICON_PATH@",
        "@BROCCOLI_MANIFEST_PATH@",
        "@BROCCOLI_FILE_VERSION_COMMAS@",
        "@BROCCOLI_SEMVER@",
    ] {
        require_token(&rc_template, token, "broccoli.rc")?;
    }
    let generated_rc = out_dir.join("broccoli.rc");
    let rendered_rc = rc_template
        .replace(
            "@BROCCOLI_ICON_PATH@",
            &rc_path(Path::new("assets/icon.ico"))?,
        )
        .replace(
            "@BROCCOLI_STOPPED_ICON_PATH@",
            &rc_path(Path::new("assets/icons/ico/broccoli-stopped.ico"))?,
        )
        .replace(
            "@BROCCOLI_CORE_RUNNING_ICON_PATH@",
            &rc_path(Path::new("assets/icons/ico/broccoli-core-running.ico"))?,
        )
        .replace(
            "@BROCCOLI_TUN_ICON_PATH@",
            &rc_path(Path::new("assets/icons/ico/broccoli-tun.ico"))?,
        )
        .replace(
            "@BROCCOLI_ERROR_ICON_PATH@",
            &rc_path(Path::new("assets/icons/ico/broccoli-error.ico"))?,
        )
        .replace(
            "@BROCCOLI_MANIFEST_PATH@",
            &rc_path(generated_manifest.as_path())?,
        )
        .replace("@BROCCOLI_FILE_VERSION_COMMAS@", &file_version_commas)
        .replace("@BROCCOLI_SEMVER@", &semver);
    fs::write(&generated_rc, rendered_rc)?;

    embed_resource::compile(&generated_rc, embed_resource::NONE)
        .manifest_required()
        .map_err(|error| {
            invalid_data(format!(
                "rc.exe resource compile failed for {}: {error}; install the Windows SDK \
                 or run cargo from a developer prompt (see build.rs)",
                generated_rc.display()
            ))
        })?;
    Ok(())
}

/// First vendored proto that is missing on disk, if any.
///
/// Codegen is unconditional: a missing vendored proto must fail the build
/// loudly (naming the file) instead of silently skipping codegen, which would
/// leave `tonic::include_proto!` against an opaque compile error on fresh
/// builds or stale generated gRPC definitions in a retained OUT_DIR.
fn missing_proto<'a>(protos: &'a [&'a str]) -> Option<&'a str> {
    protos
        .iter()
        .find(|proto| !Path::new(*proto).exists())
        .copied()
}

/// Version of protoc the crate's codegen is tested with. The vendored-protoc
/// feature vendors protobuf 27.1 (protobuf-src 2.1.1, see Cargo.lock), so a
/// `PROTOC` env var is only considered verified when `protoc --version`
/// reports exactly this version.
const KNOWN_GOOD_PROTOC_VERSION: &str = "27.1";

/// Whether the current cargo profile is a debug or an optimized build.
///
/// Cargo always sets `OPT_LEVEL` for build scripts: `"0"` is the debug
/// profile; `"1"`..`"3"`/`"s"`/`"z"` are optimized (release) profiles.
#[derive(Debug)]
enum BuildMode {
    Debug,
    Release,
}

/// Outcome of running the known-good version check on a `PROTOC` env var.
enum ProtocVerification {
    /// `protoc --version` reports the known-good version.
    Verified,
    /// The version could not be confirmed; `reason` explains why.
    Unverified { reason: String },
}

/// All protoc candidates for one build, injected by the caller so the
/// decision in [`resolve_protoc`] is pure and unit-testable without a real
/// protoc binary or a Cargo invocation.
struct ProtocResolution<'a> {
    mode: BuildMode,
    /// Value of the `PROTOC` env var, if set.
    env_protoc: Option<&'a Path>,
    /// Why the `PROTOC` binary failed verification, if it did. `None` when
    /// `PROTOC` is unset or verified.
    env_unverified_reason: Option<String>,
    /// Path of the vendored protoc (protobuf-src) when the feature is enabled.
    vendored_protoc: Option<&'a Path>,
    /// protoc discovered on PATH, if any.
    path_protoc: Option<&'a Path>,
}

/// The chosen protoc plus the loud warning the caller MUST print, if any.
#[derive(Debug)]
struct ProtocDecision {
    path: PathBuf,
    warning: Option<String>,
}

/// Why protoc resolution failed. Reported to the user verbatim (guard style:
/// fail loudly naming the missing prerequisite).
#[derive(Debug)]
enum BuildError {
    /// The protoc that would be used is neither vendored nor verified.
    UnverifiedProtoc { path: PathBuf, reason: String },
    /// No protoc is available anywhere.
    MissingProtoc { detail: String },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::UnverifiedProtoc { path, reason } => write!(
                f,
                "unverified protoc {}: {reason} (see build.rs proto guard)",
                path.display()
            ),
            BuildError::MissingProtoc { detail } => {
                write!(
                    f,
                    "missing protoc prerequisite: {detail} (see build.rs proto guard)"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Parses `protoc --version` stdout (`libprotoc 27.1`) into the version
/// string (`27.1`), or `None` when the output is not from a protoc binary.
fn parse_protoc_version(output: &str) -> Option<&str> {
    output
        .lines()
        .next()?
        .trim()
        .strip_prefix("libprotoc")?
        .split_whitespace()
        .next()
}

/// Runs `protoc --version` and reports whether the binary is the known-good
/// version the crate's codegen was tested with (vendored protobuf 27.1).
fn verify_protoc(protoc: &Path) -> ProtocVerification {
    match Command::new(protoc).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match parse_protoc_version(&stdout) {
                Some(found) if found == KNOWN_GOOD_PROTOC_VERSION => ProtocVerification::Verified,
                Some(found) => ProtocVerification::Unverified {
                    reason: format!(
                        "found libprotoc {found}, expected libprotoc {KNOWN_GOOD_PROTOC_VERSION}"
                    ),
                },
                None => ProtocVerification::Unverified {
                    reason: format!("unparseable `protoc --version` output: {}", stdout.trim()),
                },
            }
        }
        Ok(output) => ProtocVerification::Unverified {
            reason: format!("`protoc --version` exited with {}", output.status),
        },
        Err(error) => ProtocVerification::Unverified {
            reason: format!("could not run `protoc --version`: {error}"),
        },
    }
}

/// Chooses the protoc used for proto codegen and the warning to emit, if any.
///
/// Policy (SUPPLYCHAIN-06): an explicitly set `PROTOC` always wins, but in
/// release builds it must point at the known-good protoc version and the
/// vendored-protoc feature is the safe default; a PATH protoc is never
/// verified and is only tolerated in debug builds, with a loud warning that
/// release builds will fail without vendored/verified protoc.
fn resolve_protoc(res: ProtocResolution<'_>) -> Result<ProtocDecision, BuildError> {
    if let Some(path) = res.env_protoc {
        if let Some(reason) = res.env_unverified_reason {
            return match res.mode {
                BuildMode::Release => Err(BuildError::UnverifiedProtoc {
                    path: path.to_path_buf(),
                    reason: format!(
                        "{reason}; release builds require the vendored-protoc feature or a \
                         PROTOC env var pointing at a known-good protoc \
                         (libprotoc {KNOWN_GOOD_PROTOC_VERSION})"
                    ),
                }),
                BuildMode::Debug => Ok(ProtocDecision {
                    path: path.to_path_buf(),
                    warning: Some(format!(
                        "warning: using unverified protoc from PROTOC={} ({reason}); \
                         release builds will fail unless the vendored-protoc feature is \
                         enabled or PROTOC points at a known-good protoc \
                         (libprotoc {KNOWN_GOOD_PROTOC_VERSION})",
                        path.display()
                    )),
                }),
            };
        }
        return Ok(ProtocDecision {
            path: path.to_path_buf(),
            warning: None,
        });
    }
    // protobuf-src is compiled from source at a version pinned by Cargo.lock,
    // so the vendored protoc is verified by construction.
    if let Some(path) = res.vendored_protoc {
        return Ok(ProtocDecision {
            path: path.to_path_buf(),
            warning: None,
        });
    }
    if let Some(path) = res.path_protoc {
        return match res.mode {
            BuildMode::Release => Err(BuildError::UnverifiedProtoc {
                path: path.to_path_buf(),
                reason: format!(
                    "protoc found on PATH ({}) is never verified; release builds require \
                     the vendored-protoc feature or a PROTOC env var pointing at a \
                     known-good protoc (libprotoc {KNOWN_GOOD_PROTOC_VERSION})",
                    path.display()
                ),
            }),
            BuildMode::Debug => Ok(ProtocDecision {
                path: path.to_path_buf(),
                warning: Some(format!(
                    "warning: using unverified protoc from PATH ({}); release builds will \
                     fail unless the vendored-protoc feature is enabled or PROTOC points at \
                     a known-good protoc (libprotoc {KNOWN_GOOD_PROTOC_VERSION})",
                    path.display()
                )),
            }),
        };
    }
    Err(BuildError::MissingProtoc {
        detail: format!(
            "no protoc found: set PROTOC to a known-good protoc \
             (libprotoc {KNOWN_GOOD_PROTOC_VERSION}) or enable the vendored-protoc feature"
        ),
    })
}

/// Path of the vendored protoc (protobuf-src, version pinned by Cargo.lock),
/// decided by cfg alone.
///
/// Cargo mirrors enabled features into the `cfg(feature = ...)` of every
/// target it compiles, so probing `CARGO_FEATURE_VENDORED_PROTOC` adds
/// nothing and leaves a panic arm reachable when a stale inherited variable
/// contradicts the compiled feature. The `not(test)` half keeps
/// the optional protobuf-src build-dependency out of the standalone
/// `[[test]] build` target's link graph (see Cargo.toml): test targets
/// cannot see build-dependencies and the harness never runs codegen.
fn vendored_protoc_path() -> Option<PathBuf> {
    #[cfg(all(feature = "vendored-protoc", not(test)))]
    {
        Some(protobuf_src::protoc())
    }
    #[cfg(not(all(feature = "vendored-protoc", not(test))))]
    {
        None
    }
}

#[cfg(not(test))]
/// Resolves the protoc for this build, enforcing the release/debug policy and
/// printing the loud warning when a debug build falls back to an unverified
/// protoc. The caller exports the chosen path as `PROTOC` so prost-build
/// codegen runs the verified/resolved binary instead of its own PATH lookup.
fn resolve_protoc_for_build() -> Result<PathBuf, BuildError> {
    let mode = if env::var("OPT_LEVEL").as_deref() == Ok("0") {
        BuildMode::Debug
    } else {
        BuildMode::Release
    };
    let env_protoc = env::var_os("PROTOC").map(PathBuf::from);
    let env_unverified_reason =
        env_protoc
            .as_deref()
            .and_then(|protoc| match verify_protoc(protoc) {
                ProtocVerification::Verified => None,
                ProtocVerification::Unverified { reason } => Some(reason),
            });
    let vendored_protoc = vendored_protoc_path();
    // Not on PATH is the ordinary negative case; the missing-protoc error
    // below names the actual prerequisites.
    let path_protoc = which::which("protoc").ok();
    let decision = resolve_protoc(ProtocResolution {
        mode,
        env_protoc: env_protoc.as_deref(),
        env_unverified_reason,
        vendored_protoc: vendored_protoc.as_deref(),
        path_protoc: path_protoc.as_deref(),
    })?;
    if let Some(warning) = decision.warning {
        eprintln!("{warning}");
    }
    Ok(decision.path)
}

#[cfg(not(test))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        "build.rs",
        "Cargo.toml",
        "broccoli.rc",
        "assets/app.manifest",
        "assets/icon.ico",
        "assets/icons/ico/broccoli-neutral.ico",
        "assets/icons/ico/broccoli-stopped.ico",
        "assets/icons/ico/broccoli-core-running.ico",
        "assets/icons/ico/broccoli-tun.ico",
        "assets/icons/ico/broccoli-error.ico",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    emit_xray_release_metadata()?;

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        generate_windows_resources()?;
        // Broccoli's elevated helper is the same executable as the unelevated GUI.
        // Restrict static dependency resolution to System32 from process load
        // time so an app-local DLL beside a per-user installation cannot ride
        // the UAC relaunch. Dynamically loaded Xray payloads use the separately
        // verified, protected runtime stage.
        if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            println!("cargo:rustc-link-arg-bin=broccoli=/DEPENDENTLOADFLAG:0x800");
        }
    }

    println!("cargo:rerun-if-env-changed=PROTOC");
    // Debug builds can fall back to a protoc found on PATH
    // (resolve_protoc_for_build); a PATH change must re-evaluate that
    // fallback instead of keeping a stale resolved protoc.
    println!("cargo:rerun-if-env-changed=PATH");
    let protoc = resolve_protoc_for_build()?;
    // SAFETY: build script is single-threaded at this point; no other thread
    // can read the environment concurrently (set_var contract). Exporting
    // PROTOC makes prost-build (via tonic-prost-build) run the resolved,
    // verified protoc instead of its own unverified PATH lookup.
    unsafe { env::set_var("PROTOC", &protoc) };

    let protos = [
        "proto/app/stats/command/command.proto",
        "proto/app/proxyman/command/command.proto",
        "proto/app/proxyman/config.proto",
        "proto/app/router/command/command.proto",
        "proto/app/router/config.proto",
        "proto/app/observatory/command/command.proto",
        "proto/app/log/command/config.proto",
        "proto/proxy/dokodemo/config.proto",
        "proto/transport/internet/config.proto",
        "proto/common/net/address.proto",
    ];
    if let Some(missing) = missing_proto(&protos) {
        return Err(invalid_data(format!(
            "vendored proto missing: {missing}; restore the file (see build.rs proto guard)"
        ))
        .into());
    }
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&protos, &["proto"])?;
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        BuildError, BuildMode, ProtocResolution, ProtocVerification, missing_proto,
        parse_protoc_version, rc_path, resolve_protoc, vendored_protoc_path, verify_protoc,
    };

    fn resolution(mode: BuildMode) -> ProtocResolution<'static> {
        ProtocResolution {
            mode,
            env_protoc: None,
            env_unverified_reason: None,
            vendored_protoc: None,
            path_protoc: None,
        }
    }

    #[test]
    fn missing_proto_reports_missing_file() {
        let dir = tempdir().unwrap();
        let present = dir.path().join("present.proto");
        let missing = dir.path().join("missing.proto");
        fs::write(&present, "syntax = \"proto3\";").unwrap();
        let protos = [present.to_str().unwrap(), missing.to_str().unwrap()];
        assert_eq!(missing_proto(&protos), Some(missing.to_str().unwrap()));
    }

    #[test]
    fn missing_proto_returns_none_when_all_present() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("first.proto");
        let second = dir.path().join("second.proto");
        fs::write(&first, "syntax = \"proto3\";").unwrap();
        fs::write(&second, "syntax = \"proto3\";").unwrap();
        let protos = [first.to_str().unwrap(), second.to_str().unwrap()];
        assert_eq!(missing_proto(&protos), None);
    }

    #[test]
    fn missing_proto_reports_first_missing_in_list_order() {
        let dir = tempdir().unwrap();
        let present = dir.path().join("present.proto");
        let first_missing = dir.path().join("first-missing.proto");
        let second_missing = dir.path().join("second-missing.proto");
        fs::write(&present, "syntax = \"proto3\";").unwrap();
        let protos = [
            present.to_str().unwrap(),
            first_missing.to_str().unwrap(),
            second_missing.to_str().unwrap(),
        ];
        assert_eq!(
            missing_proto(&protos),
            Some(first_missing.to_str().unwrap())
        );
    }

    #[test]
    fn parse_protoc_version_parses_libprotoc_output() {
        assert_eq!(parse_protoc_version("libprotoc 27.1"), Some("27.1"));
        assert_eq!(parse_protoc_version("libprotoc 3.21.12"), Some("3.21.12"));
    }

    #[test]
    fn parse_protoc_version_tolerates_surrounding_whitespace_and_crlf() {
        assert_eq!(parse_protoc_version("libprotoc 27.1\r\n"), Some("27.1"));
        assert_eq!(parse_protoc_version("  libprotoc  27.1  "), Some("27.1"));
    }

    #[test]
    fn parse_protoc_version_rejects_non_protoc_output() {
        assert_eq!(parse_protoc_version(""), None);
        assert_eq!(parse_protoc_version("garbage output"), None);
        assert_eq!(parse_protoc_version("protoc 27.1"), None);
        assert_eq!(parse_protoc_version("libprotoc"), None);
    }

    #[test]
    fn release_accepts_verified_protoc_without_warning() {
        let path = Path::new("C:/verified/protoc.exe");
        let res = ProtocResolution {
            env_protoc: Some(path),
            ..resolution(BuildMode::Release)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, path);
        assert!(decision.warning.is_none());
    }

    #[test]
    fn release_accepts_vendored_protoc_without_warning() {
        let vendored = Path::new("C:/vendored/protoc.exe");
        let res = ProtocResolution {
            vendored_protoc: Some(vendored),
            ..resolution(BuildMode::Release)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, vendored);
        assert!(decision.warning.is_none());
    }

    #[test]
    fn release_rejects_unverified_protoc() {
        let path = Path::new("C:/other/protoc.exe");
        let res = ProtocResolution {
            env_protoc: Some(path),
            env_unverified_reason: Some("found libprotoc 35.1, expected libprotoc 27.1".to_owned()),
            ..resolution(BuildMode::Release)
        };
        match resolve_protoc(res) {
            Err(BuildError::UnverifiedProtoc {
                path: err_path,
                reason,
            }) => {
                assert_eq!(err_path, path);
                assert!(reason.contains("27.1"), "reason: {reason}");
                assert!(reason.contains("vendored-protoc"), "reason: {reason}");
            }
            other => panic!("expected UnverifiedProtoc error, got {other:?}"),
        }
    }

    #[test]
    fn release_rejects_path_fallback() {
        let path = Path::new("C:/Windows/protoc.exe");
        let res = ProtocResolution {
            path_protoc: Some(path),
            ..resolution(BuildMode::Release)
        };
        match resolve_protoc(res) {
            Err(BuildError::UnverifiedProtoc {
                path: err_path,
                reason,
            }) => {
                assert_eq!(err_path, path);
                assert!(
                    reason.contains("release builds require"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected UnverifiedProtoc error, got {other:?}"),
        }
    }

    #[test]
    fn release_rejects_missing_protoc() {
        match resolve_protoc(resolution(BuildMode::Release)) {
            Err(BuildError::MissingProtoc { detail }) => {
                assert!(detail.contains("vendored-protoc"), "detail: {detail}");
                assert!(detail.contains("27.1"), "detail: {detail}");
            }
            other => panic!("expected MissingProtoc error, got {other:?}"),
        }
    }

    #[test]
    fn debug_accepts_verified_protoc_without_warning() {
        let path = Path::new("C:/verified/protoc.exe");
        let res = ProtocResolution {
            env_protoc: Some(path),
            ..resolution(BuildMode::Debug)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, path);
        assert!(decision.warning.is_none());
    }

    #[test]
    fn debug_path_fallback_warns_loudly() {
        let path = Path::new("C:/Windows/protoc.exe");
        let res = ProtocResolution {
            path_protoc: Some(path),
            ..resolution(BuildMode::Debug)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, path);
        let warning = decision.warning.expect("debug PATH fallback must warn");
        assert!(warning.contains("unverified"), "warning: {warning}");
        assert!(
            warning.contains("release builds will fail"),
            "warning: {warning}"
        );
    }

    #[test]
    fn debug_unverified_protoc_warns_loudly() {
        let path = Path::new("C:/other/protoc.exe");
        let res = ProtocResolution {
            env_protoc: Some(path),
            env_unverified_reason: Some("found libprotoc 35.1, expected libprotoc 27.1".to_owned()),
            ..resolution(BuildMode::Debug)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, path);
        let warning = decision.warning.expect("debug unverified PROTOC must warn");
        assert!(
            warning.contains("release builds will fail"),
            "warning: {warning}"
        );
        assert!(warning.contains("27.1"), "warning: {warning}");
    }

    #[test]
    fn debug_missing_protoc_is_hard_error() {
        match resolve_protoc(resolution(BuildMode::Debug)) {
            Err(BuildError::MissingProtoc { .. }) => {}
            other => panic!("expected MissingProtoc error, got {other:?}"),
        }
    }

    #[test]
    fn env_protoc_wins_over_vendored() {
        let env = Path::new("C:/env/protoc.exe");
        let vendored = Path::new("C:/vendored/protoc.exe");
        let res = ProtocResolution {
            env_protoc: Some(env),
            vendored_protoc: Some(vendored),
            ..resolution(BuildMode::Release)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, env);
        assert!(decision.warning.is_none());
    }

    #[test]
    fn vendored_wins_over_path_fallback() {
        let vendored = Path::new("C:/vendored/protoc.exe");
        let path = Path::new("C:/Windows/protoc.exe");
        let res = ProtocResolution {
            vendored_protoc: Some(vendored),
            path_protoc: Some(path),
            ..resolution(BuildMode::Debug)
        };
        let decision = resolve_protoc(res).unwrap();
        assert_eq!(decision.path, vendored);
        assert!(decision.warning.is_none());
    }
    #[test]
    fn verify_protoc_reports_unrunnable_binary() {
        let missing = Path::new("C:/definitely/not/here/protoc.exe");
        match verify_protoc(missing) {
            ProtocVerification::Unverified { reason } => {
                assert!(reason.contains("could not run"), "reason: {reason}");
            }
            ProtocVerification::Verified => panic!("a missing binary must not verify"),
        }
    }

    #[test]
    fn vendored_protoc_is_decided_by_cfg_alone() {
        // The vendored branch is decided by cfg, never by a
        // CARGO_FEATURE_* env probe (which could contradict the compiled cfg
        // from a stale inherited variable and reach a panic arm). Under the
        // test harness the `not(test)` half of the cfg keeps the optional
        // protobuf-src build-dependency out of this target's link graph, so
        // the decision must be None here even when the feature cfg is on.
        assert_eq!(vendored_protoc_path(), None);
    }

    #[cfg(windows)]
    #[test]
    fn rc_path_renders_ascii_absolute_paths_with_forward_slashes() {
        assert_eq!(
            rc_path(Path::new(r"C:\Users\Ada\broccoli\assets\icon.ico")).unwrap(),
            "C:/Users/Ada/broccoli/assets/icon.ico"
        );
    }

    #[cfg(windows)]
    #[test]
    fn rc_path_strips_verbatim_prefixes() {
        assert_eq!(
            rc_path(Path::new(r"\\?\C:\Users\Ada\icon.ico")).unwrap(),
            "C:/Users/Ada/icon.ico"
        );
        assert_eq!(
            rc_path(Path::new(r"\\?\UNC\server\share\icon.ico")).unwrap(),
            "//server/share/icon.ico"
        );
    }

    #[cfg(windows)]
    #[test]
    fn rc_path_rejects_invalid_unicode_paths() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        // A lone surrogate has no UTF-8 form; to_str() must fail rather than
        // render U+FFFD into the generated resource script.
        let path = std::path::PathBuf::from(OsString::from_wide(&[
            0x43, 0x3A, 0x5C, // "C:\"
            0xD800,
        ]));
        match rc_path(&path) {
            Err(error) => {
                let message = error.to_string();
                assert!(message.contains("not valid Unicode"), "message: {message}");
            }
            Ok(rendered) => panic!("invalid-Unicode path must be rejected, got {rendered:?}"),
        }
    }

    #[test]
    fn rc_path_rejects_non_ascii_components_naming_the_offender() {
        // Legitimate machine state (an accented username in the build path)
        // must fail loudly naming the offending component instead of being
        // silently mangled into broccoli.rc.
        let path = Path::new(r"C:\Users\Müller\broccoli\assets\icon.ico");
        match rc_path(path) {
            Err(error) => {
                let message = error.to_string();
                assert!(message.contains("Müller"), "message: {message}");
                assert!(message.contains("non-ASCII"), "message: {message}");
                assert!(message.contains("rc.exe"), "message: {message}");
            }
            Ok(rendered) => panic!("non-ASCII path must be rejected, got {rendered:?}"),
        }
    }

    #[test]
    fn rc_path_joins_relative_paths_under_manifest_dir() {
        let rendered = rc_path(Path::new("assets/icon.ico")).unwrap();
        assert!(rendered.ends_with("assets/icon.ico"));
        assert!(!rendered.contains('\\'));
    }
}

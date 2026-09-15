// Runs the unit tests embedded in `build.rs` (see the `[[test]] build` target
// in Cargo.toml). The build script is pulled in as a module so cargo does not
// warn about build.rs belonging to two targets; the `#[cfg(test)]` module
// inside build.rs is only compiled when this crate is built with `--test`.

// The pure helpers under test (`missing_proto`, protoc resolution, rc path
// validation, the cfg-decided vendored-protoc branch) and the tests
// themselves are exercised by this crate; the rest of the build-script
// surface is compiled here solely so the tests run against the real file.
#[path = "../build.rs"]
mod build_rs;

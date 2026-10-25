//! Crash-durable file replacement.
//!
//! One owner for the write-then-rename protocol the app uses for every file
//! whose half-written state must never be observable: the persisted state
//! files, the DNS-takeover restore record, the generated configuration and
//! its stamp, and the geo data restored from the pinned copies.
//!
//! The staging name is fixed (`<file>.tmp`) rather than unique: several of
//! these files carry plaintext credentials, so a process killed between the
//! write and the rename must leave a temp the next write can find and delete.
//! A unique name would strand that plaintext where nothing looks for it.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// The sibling temp file one atomic write of `path` stages through.
pub fn temp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// Create the staged temp without ever opening an entry that already exists.
///
/// `CREATE_NEW` refuses a pre-placed file or link, so a path someone else
/// chose cannot redirect this write: a link left at the temp name is removed
/// (the link itself, never its target) and the create retried once, which
/// also clears the entry a killed writer stranded. A second failure is
/// returned, never followed.
fn create_staged(tmp: &Path) -> io::Result<File> {
    let create = || OpenOptions::new().write(true).create_new(true).open(tmp);
    match create() {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            discard_temp(tmp);
            create()
        }
        Err(error) => Err(error),
    }
}

/// Crash-durable atomic replace of `path`: flush the sibling temp, then
/// rename it over the target (Rust's Windows `rename` uses
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`).
///
/// Every failure path removes the temp best-effort before returning: a failed
/// save must not leave a stray staging file next to the live one. The writer
/// handle is closed by then, so the removal is not blocked by the open file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = temp_path(path);
    let result = (|| {
        let mut file = create_staged(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        discard_temp(&tmp);
    }
    result
}

/// Create or replace `path` with `bytes`, flushed to disk, without renaming.
///
/// For an artefact promoted by a later rename under its own ordering rule (a
/// configuration renamed before its stamp, so a crash cannot pair the new
/// bytes with the old stamp).
pub fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Copy `from` over `to` through the same temp-then-rename protocol.
pub fn copy_atomic(from: &Path, to: &Path) -> io::Result<()> {
    copy_file_atomic(File::open(from)?, to)
}

/// [`copy_atomic`] over an already-open source.
///
/// A caller that verified the source's bytes through a handle passes that
/// same handle, so the file it hashed is the file it copies: bytes cannot be
/// swapped by path between the check and the copy.
pub fn copy_file_atomic(mut source: File, to: &Path) -> io::Result<()> {
    let tmp = temp_path(to);
    let result = (|| {
        let mut output = create_staged(&tmp)?;
        io::copy(&mut source, &mut output)?;
        output.sync_all()?;
        drop(output);
        std::fs::rename(&tmp, to)
    })();
    if result.is_err() {
        discard_temp(&tmp);
    }
    result
}

/// Best-effort removal of a staged temp file. An absent temp is the normal
/// case.
pub fn discard_temp(tmp: &Path) {
    match std::fs::remove_file(tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::debug!(
                "removing the staged temp file {} failed: {error}",
                tmp.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_atomic, temp_path, write_atomic, write_synced};

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "broccoli-durable-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_temp() {
        let dir = scratch_dir("replace");
        let path = dir.join("state.json");
        std::fs::write(&path, b"old").expect("seed");

        write_atomic(&path, b"new").expect("write");

        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        assert!(!temp_path(&path).exists(), "the temp must be renamed away");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_creates_a_missing_target() {
        let dir = scratch_dir("create");
        let path = dir.join("state.json");

        write_atomic(&path, b"first").expect("write");

        assert_eq!(std::fs::read(&path).expect("read"), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_removes_its_temp_when_the_rename_cannot_land() {
        let dir = scratch_dir("failure");
        // A directory at the target makes the rename fail on every platform,
        // while the temp write itself succeeds.
        let path = dir.join("state.json");
        std::fs::create_dir(&path).expect("blocking dir");

        write_atomic(&path, b"bytes").expect_err("the rename must fail");

        assert!(
            !temp_path(&path).exists(),
            "a failed write must not strand the staged bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_replaces_a_stale_staging_entry() {
        let dir = scratch_dir("stale-temp");
        let path = dir.join("state.json");
        std::fs::write(&path, b"old").expect("seed");
        // A killed writer's leftover at the staging name: the create refuses
        // it, removes the entry (never a target it might name), and retries.
        std::fs::write(temp_path(&path), b"stranded plaintext").expect("seed temp");

        write_atomic(&path, b"new").expect("write");

        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        assert!(!temp_path(&path).exists(), "the temp must be renamed away");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_refuses_a_staging_entry_it_cannot_replace() {
        let dir = scratch_dir("blocked-temp");
        let path = dir.join("state.json");
        std::fs::write(&path, b"old").expect("seed");
        // A directory at the staging name cannot be removed by the retry, so
        // the write must fail without touching the target.
        std::fs::create_dir(temp_path(&path)).expect("blocking dir");

        write_atomic(&path, b"new").expect_err("the staging entry cannot be replaced");

        assert_eq!(std::fs::read(&path).expect("read"), b"old");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_synced_truncates_an_existing_file() {
        let dir = scratch_dir("synced");
        let path = dir.join("config.json");
        std::fs::write(&path, b"a much longer previous body").expect("seed");

        write_synced(&path, b"short").expect("write");

        assert_eq!(std::fs::read(&path).expect("read"), b"short");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_atomic_replaces_the_target_with_the_source_bytes() {
        let dir = scratch_dir("copy");
        let from = dir.join("pristine.dat");
        let to = dir.join("managed.dat");
        std::fs::write(&from, b"pristine").expect("seed source");
        std::fs::write(&to, b"stale").expect("seed target");

        copy_atomic(&from, &to).expect("copy");

        assert_eq!(std::fs::read(&to).expect("read"), b"pristine");
        assert!(!temp_path(&to).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

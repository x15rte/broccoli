//! Age-bounded startup sweeps: the one implementation for the leftovers a
//! crash or a kill strands — profile-validation scratch configs, the latency
//! probe's per-run temp directories, and panic reports.
//!
//! Each caller supplies only what is genuinely its own: the directory it owns,
//! the naming contract of the writer it cleans up after, and its age window.
//! The shared rules land here once: a missing directory is a no-op, every
//! entry is inspected best-effort so one failure cannot abort the rest, an
//! entry stamped in the future counts as new and survives clock skew, and only
//! an entry of the declared kind whose name the matcher accepts is ever
//! removed.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// What a sweep removes once a name matches and the age bound is met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// A regular file, removed with `remove_file`.
    File,
    /// A directory tree, removed with `remove_dir_all`.
    Directory,
}

/// The naming contract a sweep applies before it will consider an entry: the
/// filename prefix and suffix its writer emits, the entry kind, and an
/// optional stricter whole-name rule for contracts a prefix/suffix pair alone
/// would make too loose (the scratch config's fixed-width uuid stem).
#[derive(Debug, Clone, Copy)]
pub struct Matcher<'a> {
    prefix: &'a str,
    suffix: &'a str,
    entry: Entry,
    exact: Option<fn(&str) -> bool>,
}

impl<'a> Matcher<'a> {
    /// A matcher for regular files whose name starts with `prefix` and ends
    /// with `suffix`.
    pub const fn files(prefix: &'a str, suffix: &'a str) -> Self {
        Matcher {
            prefix,
            suffix,
            entry: Entry::File,
            exact: None,
        }
    }

    /// A matcher for directories whose name starts with `prefix` and ends
    /// with `suffix`.
    pub const fn directories(prefix: &'a str, suffix: &'a str) -> Self {
        Matcher {
            prefix,
            suffix,
            entry: Entry::Directory,
            exact: None,
        }
    }

    /// Narrows the matcher with a whole-name rule, so a sweep only deletes a
    /// name that satisfies every letter of its writer's contract — never a
    /// lookalike the prefix and suffix alone would accept.
    pub const fn requiring(mut self, exact: fn(&str) -> bool) -> Self {
        self.exact = Some(exact);
        self
    }

    /// Whether `name` satisfies this contract.
    fn accepts(&self, name: &str) -> bool {
        name.starts_with(self.prefix)
            && name.ends_with(self.suffix)
            && self.exact.is_none_or(|check| check(name))
    }
}

/// Remove the entries of `dir` that `matcher` accepts and whose modification
/// time is at least `max_age` old. `cap` bounds how many entries one pass
/// removes (`None` means no bound); entries left by the bound survive to the
/// next launch's sweep.
///
/// Returns the number of entries actually removed. A missing `dir` is not an
/// error. Failures stay confined to their own entry: an entry that races away
/// or cannot be inspected is skipped, a removal that fails leaves the entry
/// in place, and only successful removals are counted.
pub fn sweep(
    dir: &Path,
    now: SystemTime,
    max_age: Duration,
    matcher: Matcher<'_>,
    cap: Option<usize>,
) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for entry in entries {
        if cap.is_some_and(|cap| removed >= cap) {
            break;
        }
        // Best-effort housekeeping: an entry that races away or cannot be
        // inspected must not abort the sweep of the remaining entries.
        let Ok(entry) = entry else { continue };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let right_kind = match matcher.entry {
            Entry::File => metadata.is_file(),
            Entry::Directory => metadata.is_dir(),
        };
        if !right_kind {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !matcher.accepts(name) {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        // An entry stamped in the future (clock skew) counts as new and is
        // kept — a sweep must never delete what may be live.
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age < max_age {
            continue;
        }
        let path = entry.path();
        let removed_now = match matcher.entry {
            Entry::File => std::fs::remove_file(&path).is_ok(),
            Entry::Directory => std::fs::remove_dir_all(&path).is_ok(),
        };
        if removed_now {
            removed += 1;
        }
    }
    Ok(removed)
}

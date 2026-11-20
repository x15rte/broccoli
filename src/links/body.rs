//! Subscription body decoding and the import keys stored with a profile.
//!
//! A provider may answer with a plain link list or one Base64 blob around it;
//! [`decode_whole_body`] gives the text the [`super::import`] walk reads, and
//! [`content_key`]/[`identity_key`] are the opaque keys a subscription import
//! stores so the next refresh matches the same entries.

use super::to_link;
use crate::model::ServerProfile;
use crate::model::servers::ProfileOrigin;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// The bound on one refused entry's raw text: a hostile provider cannot make
/// the report — or the state file — grow without limit.
pub const MAX_RAW_CHARS: usize = 4096;

/// How much of the body the leading-metadata comments are read from.
pub const COMMENT_SCAN_BYTES: usize = 16 * 1024;

/// The leading `#`/`//` `key: value` comments of `text`, bounded to the first
/// [`COMMENT_SCAN_BYTES`].
pub(crate) fn leading_comments(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut comments = std::collections::BTreeMap::new();
    let mut scanned = 0_usize;
    for line in text.lines() {
        if scanned >= COMMENT_SCAN_BYTES {
            break;
        }
        scanned += line.len() + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = comment_metadata(trimmed) else {
            break;
        };
        comments.insert(key, value);
    }
    comments
}

/// One `# key: value` / `// key: value` line, or `None` when the line is not
/// a metadata comment.
fn comment_metadata(line: &str) -> Option<(String, String)> {
    let body = line
        .strip_prefix('#')
        .or_else(|| line.strip_prefix("//"))?
        .trim();
    let (key, value) = body.split_once(':')?;
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    Some((key, value.trim().to_owned()))
}

/// One compatibility parameter a parser dropped: the name the provider
/// spelled, the value it carried, and the bounded raw source line it came
/// from.
///
/// The report groups repeats of the same `parameter=value` under one heading,
/// so that pair is the grouping key. `raw` is bounded per item
/// ([`MAX_RAW_CHARS`]) instead of duplicating a whole provider link
/// unbounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompatibilityParameter {
    pub name: String,
    pub value: String,
    /// The bounded raw source line; empty when the source is a document the
    /// parser cannot point into.
    pub raw: String,
}

impl CompatibilityParameter {
    /// A parameter the parser named but the document carries no source line
    /// for: the shape a document converter produces.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: String::new(),
            raw: String::new(),
        }
    }
    /// The `parameter=value` pair, or the bare name when the link spelled no
    /// value.
    pub fn key(&self) -> String {
        if self.value.is_empty() {
            self.name.clone()
        } else {
            format!("{}={}", self.name, self.value)
        }
    }
}

impl From<&str> for CompatibilityParameter {
    fn from(name: &str) -> Self {
        Self::named(name)
    }
}

impl From<String> for CompatibilityParameter {
    fn from(name: String) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }
}

/// Whole-body Base64 (standard or URL-safe, padding optional, whitespace
/// ignored) or the text itself when it is not Base64. A decoded blob that is
/// not text falls back to the original.
pub fn decode_whole_body(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let compact: String = trimmed
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(compact.as_bytes())
            && let Ok(decoded) = String::from_utf8(bytes)
            && looks_like_body(&decoded)
        {
            return decoded;
        }
    }
    trimmed.to_owned()
}

/// Whether a decoded blob reads as a link list or a document shape rather
/// than binary noise.
pub(crate) fn looks_like_body(text: &str) -> bool {
    let trimmed = text.trim_start();
    text.contains("://")
        || text.contains('\n')
        || trimmed.starts_with('{')
        || text.contains("proxies:")
        || text.contains("mixed-port:")
        || text.contains("outbounds")
        || text.contains("[Interface]")
        || (text.contains("server:") && (text.contains("port:") || text.contains("auth:")))
}

/// The content key of an imported entry: a digest of its canonical share
/// link, or of the outbound model when the protocol has no share grammar.
/// Stored, never recomputed, so an edited row still matches its next fetch.
pub fn content_key(profile: &ServerProfile) -> String {
    let canonical = to_link(profile)
        .or_else(|_| serde_json::to_string(&profile.outbound).map_err(|_| unreachable!()))
        .unwrap_or_default();
    sha256_hex(canonical.as_bytes())
}

/// The identity key: protocol, endpoint, transport and security, with the
/// name excluded. This is what still matches when the user renamed an entry
/// and the provider changed its name.
pub fn identity_key(profile: &ServerProfile) -> String {
    let outbound = &profile.outbound;
    let endpoint = profile.server_address().unwrap_or_default();
    let identity = format!(
        "{:?}|{}|{:?}|{:?}",
        outbound.protocol, endpoint, outbound.stream.network, outbound.stream.security
    );
    sha256_hex(identity.as_bytes())
}

/// The origin keys stored with a subscription import.
pub fn origin_for(profile: &ServerProfile) -> ProfileOrigin {
    ProfileOrigin {
        content_key: content_key(profile),
        identity_key: identity_key(profile),
        ..ProfileOrigin::default()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::outbound::{OutboundModel, Protocol};

    #[test]
    fn compatibility_parameters_carry_the_pair_they_group_under() {
        let parameter = CompatibilityParameter {
            name: "allowInsecure".into(),
            value: "1".into(),
            raw: "trojan://pw@example.com:443?allowInsecure=1#One".into(),
        };
        assert_eq!(parameter.key(), "allowInsecure=1");
        let bare = CompatibilityParameter::from("mux");
        assert_eq!(bare.key(), "mux");
        assert!(bare.raw.is_empty());
    }

    #[test]
    fn keys_are_stable_and_identity_ignores_the_name() {
        let mut profile = ServerProfile::new("one", OutboundModel::new(Protocol::Trojan));
        let first = origin_for(&profile);
        profile.name = "renamed".into();
        let second = origin_for(&profile);
        assert_eq!(first.content_key, second.content_key);
        assert_eq!(first.identity_key, second.identity_key);
    }
}

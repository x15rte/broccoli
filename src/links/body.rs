//! Subscription body decoding: one fetched body in, profiles and diagnostics
//! out.
//!
//! A provider may answer with a plain link list or one Base64 blob around it;
//! each line may itself be Base64. Document shapes (Clash YAML, sing-box/Xray
//! JSON, SIP008, WireGuard, Hysteria 2) classify here too, so a converter
//! plugs into one pipeline instead of a second fetch path.

use super::{ParsedLink, parse_link, to_link};
use crate::model::ServerProfile;
use crate::model::servers::{ProfileOrigin, ReportKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

/// The bound on one refused entry's raw text: a hostile provider cannot make
/// the report — or the state file — grow without limit.
pub const MAX_RAW_CHARS: usize = 4096;

/// How much of the body the leading-metadata comments are read from.
pub const COMMENT_SCAN_BYTES: usize = 16 * 1024;

/// The leading `#`/`//` `key: value` comments of `text`, bounded to the first
/// [`COMMENT_SCAN_BYTES`].
fn leading_comments(text: &str) -> std::collections::BTreeMap<String, String> {
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

/// One accepted entry: the profile plus the raw text it came from.
#[derive(Debug, Clone)]
pub struct BodyEntry {
    pub profile: ServerProfile,
    pub raw: String,
    /// The compatibility parameters the link grammar dropped.
    pub ignored: Vec<String>,
}

/// One refused item: its raw text and the reason it was refused.
#[derive(Debug, Clone)]
pub struct BodyRefusal {
    pub raw: String,
    pub error: String,
}

/// One document section the converter ignored (rules, groups, routing), named
/// for the report.
#[derive(Debug, Clone)]
pub struct IgnoredSection {
    pub name: String,
}

/// A decoded body's outcome.
#[derive(Debug, Clone, Default)]
pub struct BodyParse {
    pub entries: Vec<BodyEntry>,
    pub refused: Vec<BodyRefusal>,
    pub ignored: Vec<IgnoredSection>,
    /// Leading `#`/`//` `key: value` comments, the metadata fallback when the
    /// provider sends no headers.
    pub comments: std::collections::BTreeMap<String, String>,
}

impl BodyParse {
    /// The report row a refusal contributes.
    pub fn refused_row(&self, refusal: &BodyRefusal) -> crate::model::servers::ReportRow {
        crate::model::servers::ReportRow {
            kind: ReportKind::Refused,
            name: String::new(),
            raw: refusal.raw.clone(),
        }
    }
}

pub fn parse_body(text: &str) -> BodyParse {
    parse_body_cancellable(text, &AtomicBool::new(false))
}

/// [`parse_body`] with a stop flag: a cancelled parse returns the entries
/// collected so far and the caller drops them.
pub fn parse_body_cancellable(text: &str, stop: &AtomicBool) -> BodyParse {
    let decoded = decode_whole_body(text);
    let comments = leading_comments(&decoded);
    let mut outcome = BodyParse {
        comments: comments.clone(),
        ..Default::default()
    };
    if let Some(converted) = super::convert::convert_document(&decoded) {
        let mut outcome = BodyParse {
            entries: converted.entries,
            refused: converted.refused,
            ignored: converted.ignored,
            comments,
        };
        for entry in &outcome.entries {
            for parameter in &entry.ignored {
                outcome.ignored.push(IgnoredSection {
                    name: format!("{}: {parameter}", entry.profile.name),
                });
            }
        }
        return outcome;
    }
    for line in decoded.lines() {
        if stop.load(Ordering::Relaxed) {
            return outcome;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match per_item_text(line) {
            Some(item) => match classify(&item) {
                Ok(link) => {
                    for parameter in &link.ignored {
                        outcome.ignored.push(IgnoredSection {
                            name: format!("{}: {parameter}", link.profile.name),
                        });
                    }
                    outcome.entries.push(BodyEntry {
                        profile: link.profile,
                        raw: bound_raw(line),
                        ignored: link.ignored,
                    });
                }
                Err(error) => outcome.refused.push(BodyRefusal {
                    raw: bound_raw(line),
                    error,
                }),
            },
            None => outcome.refused.push(BodyRefusal {
                raw: bound_raw(line),
                error: "entry is not Base64 text".into(),
            }),
        }
    }
    outcome
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

/// One line, decoded when the line itself is Base64.
fn per_item_text(line: &str) -> Option<String> {
    if !looks_base64(line) {
        return Some(line.to_owned());
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD, &STANDARD, &URL_SAFE] {
        if let Ok(bytes) = engine.decode(line.as_bytes())
            && let Ok(decoded) = String::from_utf8(bytes)
            && looks_like_body(&decoded)
        {
            return Some(decoded);
        }
    }
    // A line that is not Base64 at all is still an item; classification
    // reports why it is not a profile.
    Some(line.to_owned())
}

fn looks_like_body(text: &str) -> bool {
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

fn looks_base64(text: &str) -> bool {
    text.len() >= 8
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+/=_-".contains(character))
}

/// Classify one item: a share link, a nested subscription URL (refused), or a
/// document shape a converter must claim.
fn classify(item: &str) -> Result<ParsedLink, String> {
    let lower = item.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err("nested subscription URL".into());
    }
    if lower.contains("proxies:")
        || lower.starts_with('{')
        || lower.contains("[interface]")
        || lower.starts_with("server:")
        || lower.contains("outbounds")
        || lower.contains("\"servers\"")
    {
        return Err("unsupported document format".into());
    }
    parse_link(item).map_err(|error| error.to_string())
}

fn bound_raw(text: &str) -> String {
    text.chars().take(MAX_RAW_CHARS).collect()
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

    fn link(name: &str) -> String {
        format!("trojan://pw@example.com:443#{name}")
    }

    #[test]
    fn plain_lines_and_comments_decode_to_entries() {
        let body = format!("# provider\n{}\n\n// comment\n{}", link("one"), link("two"));
        let parsed = parse_body(&body);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].profile.name, "one");
        assert!(parsed.refused.is_empty());
    }

    #[test]
    fn whole_body_base64_decodes_once() {
        let body = format!("{}\n{}", link("one"), link("two"));
        let encoded = STANDARD.encode(body.as_bytes());
        let parsed = parse_body(&encoded);
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn url_safe_unpadded_and_per_item_base64_decode() {
        let item = STANDARD_NO_PAD.encode(link("one").as_bytes());
        let body = format!("{item}\n{}", link("two"));
        let parsed = parse_body(&body);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].profile.name, "one");
    }

    #[test]
    fn nested_subscription_urls_are_refused_with_their_text() {
        let body = "https://provider.example/sub";
        let parsed = parse_body(body);
        assert_eq!(parsed.entries.len(), 0);
        assert_eq!(parsed.refused.len(), 1);
        assert_eq!(parsed.refused[0].raw, body);
    }

    #[test]
    fn leading_comments_carry_metadata_and_later_ones_do_not() {
        let body = format!(
            "# subscription-userinfo: upload=1; download=2; total=3\n// profile-title: Feed\n{}\n# announce: late\n",
            link("one")
        );
        let parsed = parse_body(&body);
        assert_eq!(
            parsed
                .comments
                .get("subscription-userinfo")
                .map(String::as_str),
            Some("upload=1; download=2; total=3")
        );
        assert_eq!(
            parsed.comments.get("profile-title").map(String::as_str),
            Some("Feed")
        );
        assert!(!parsed.comments.contains_key("announce"));
    }

    #[test]
    fn link_compatibility_parameters_reach_the_report() {
        let body = "trojan://pw@example.com:443?allowInsecure=1#One";
        let parsed = parse_body(body);
        assert_eq!(parsed.entries.len(), 1, "{:?}", parsed.refused);
        assert!(
            parsed
                .ignored
                .iter()
                .any(|section| section.name.contains("allowInsecure")),
            "the dropped parameter is named: {:#?}",
            parsed.ignored
        );
    }

    #[test]
    fn base64_document_bodies_and_leading_comments_decode() {
        let body = "# profile-title: Feed\nproxies:\n  - name: One\n    type: ss\n    server: s.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: pw\n";
        let encoded = STANDARD.encode(body.as_bytes());
        let decoded = decode_whole_body(&encoded);
        assert!(decoded.contains("proxies:"), "decoded={decoded:?}");
        let converted = crate::links::convert::convert_document(&decoded)
            .expect("convert recognized the decoded document");
        assert_eq!(
            converted.entries.len(),
            1,
            "refused: {:?} ignored: {:?}",
            converted.refused,
            converted.ignored
        );
        let parsed = parse_body(&encoded);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(
            parsed.comments.get("profile-title").map(String::as_str),
            Some("Feed")
        );
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

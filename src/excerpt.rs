//! The crate-wide bound on attacker-controlled text in diagnostics.
//!
//! One owner for the rule every error surface echoes through: share-link
//! parse errors, parameterized `model::validation::ValidationCode` payloads,
//! state-load semantic errors, raw-override generation and parse errors, and
//! the dashboard's echoed generation errors. A hostile value can never
//! inflate rendered error text, and identity below the bound keeps short
//! values byte-identical.

/// Maximum characters of attacker-controlled input embedded in a rendered
/// diagnostic. Errors must never echo the full raw input; every bounded echo
/// surface shares this one bound.
pub const MAX_ERROR_EXCERPT_CHARS: usize = 48;

/// The first [`MAX_ERROR_EXCERPT_CHARS`] characters, truncated on a UTF-8
/// boundary with a trailing `…`.
pub fn excerpt(s: &str) -> String {
    match s.char_indices().nth(MAX_ERROR_EXCERPT_CHARS) {
        Some((end, _)) => format!("{}…", &s[..end]),
        None => s.to_owned(),
    }
}

/// Debug-escaped bounded excerpt, for `{:?}`-style error embeds.
pub(crate) fn excerpt_debug(s: &str) -> String {
    format!("{:?}", excerpt(s))
}

#[cfg(test)]
mod tests {
    use super::{MAX_ERROR_EXCERPT_CHARS, excerpt};

    /// The bound is a character count, so 48 CJK characters (144 bytes) fit
    /// whole and only the 49th is elided. Indexing by bytes would cut this
    /// input at 16 characters.
    #[test]
    fn excerpt_keeps_forty_eight_cjk_characters() {
        let exact: String = "错".repeat(MAX_ERROR_EXCERPT_CHARS);
        assert_eq!(excerpt(&exact), exact, "the bound itself is not a cut");

        let over: String = "错".repeat(MAX_ERROR_EXCERPT_CHARS + 1);
        let kept: String = "错".repeat(MAX_ERROR_EXCERPT_CHARS);
        assert_eq!(excerpt(&over), format!("{kept}…"));
    }

    /// The cut never splits a 4-byte emoji: the ellipsis follows the 48th
    /// whole character even when the string continues with another one.
    #[test]
    fn excerpt_cuts_after_a_whole_emoji_at_the_bound() {
        let exact: String = "🦀".repeat(MAX_ERROR_EXCERPT_CHARS);
        assert_eq!(excerpt(&exact), exact);

        let over: String = "🦀".repeat(MAX_ERROR_EXCERPT_CHARS + 1);
        let kept: String = "🦀".repeat(MAX_ERROR_EXCERPT_CHARS);
        assert_eq!(excerpt(&over), format!("{kept}…"));
        assert_eq!(
            excerpt(&over).chars().count(),
            MAX_ERROR_EXCERPT_CHARS + 1,
            "the bound counts characters, not bytes"
        );

        // Mixed widths: byte 48 would land inside an emoji, so a byte-indexed
        // cut would walk back and lose four characters.
        let mixed = format!("a{}", "🦀".repeat(MAX_ERROR_EXCERPT_CHARS));
        let kept = format!("a{}", "🦀".repeat(MAX_ERROR_EXCERPT_CHARS - 1));
        assert_eq!(excerpt(&mixed), format!("{kept}…"));

        // ASCII stays byte-identical to the previous byte-index semantics.
        let ascii = "a".repeat(MAX_ERROR_EXCERPT_CHARS + 1);
        assert_eq!(excerpt(&ascii), format!("{}…", "a".repeat(48)));
    }
}

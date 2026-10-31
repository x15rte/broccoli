//! Syntax colouring for the config preview's JSON.
//!
//! The preview shows the exact configuration the core received. Its colouring
//! exists to make the document's shape readable at a glance, not to be an
//! editor: one pass over the text splits it into the five classes a JSON
//! document carries (key, string, number, literal, punctuation), and each
//! class takes one palette role. A syntax engine would need to be brought in
//! with its own theme files for the one distinction this view needs — the
//! bundled code themes paint a key and a string value with the same colour —
//! so the pass runs here instead, on the text the preview already holds.
//!
//! The pass runs only when the memoized layout rebuilds — a new launch, a
//! theme flip or a wrap-width change — so the preview never tokenizes on an
//! idle frame.

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId, Visuals};

use crate::ui::status::status_colors;

/// The colours one JSON document's token classes take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JsonColors {
    pub(crate) key: Color32,
    pub(crate) string: Color32,
    pub(crate) number: Color32,
    pub(crate) literal: Color32,
    pub(crate) punctuation: Color32,
}

/// The palette for the theme `visuals` describes. Keys take a per-theme blue
/// because the theme's own hyperlink accent (egui light: `#009BFF`) sits at
/// 2.77:1 on the panel — this module's contrast test holds every semantic
/// class to AA, so the code view chooses the blue that passes. Strings and
/// numbers take the status palette's green and amber as code colours: the
/// hues read as value kinds here, not as verdicts, and they carry the same
/// contrast floor. Literals take the strong text colour, which keeps
/// `true`/`false`/`null` apart from numbers. Punctuation takes the body text
/// colour: the weak one measures 2.3:1 on the dark panel, under the AA floor
/// the rest of the classes hold.
pub(crate) fn json_colors(visuals: &Visuals) -> JsonColors {
    let status = status_colors(visuals.dark_mode);
    let key = if visuals.dark_mode {
        Color32::from_rgb(0x7a, 0xa2, 0xf7)
    } else {
        Color32::from_rgb(0x0b, 0x5c, 0xad)
    };
    JsonColors {
        key,
        string: status.ok,
        number: status.warn,
        literal: visuals.strong_text_color(),
        punctuation: visuals.text_color(),
    }
}

/// One laid-out job for `text`: every token in its class's colour, the text
/// copied byte for byte. Text that is not valid JSON is painted as
/// punctuation and never panics, so a hand-edited override reaching the
/// preview still renders.
pub(crate) fn layout_job(text: &str, font_id: &FontId, colors: JsonColors) -> LayoutJob {
    let mut job = LayoutJob::default();
    let mut start = 0;
    while start < text.len() {
        let (end, class) = scan_class(text, start);
        // `append` merges into the previous section when the format matches,
        // so a class run that continues the previous one stays one section.
        job.append(&text[start..end], 0.0, format(font_id, class, colors));
        start = end;
    }
    job
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Key,
    String,
    Number,
    Literal,
    Punctuation,
}

fn format(font_id: &FontId, class: Class, colors: JsonColors) -> TextFormat {
    let color = match class {
        Class::Key => colors.key,
        Class::String => colors.string,
        Class::Number => colors.number,
        Class::Literal => colors.literal,
        Class::Punctuation => colors.punctuation,
    };
    TextFormat {
        font_id: font_id.clone(),
        color,
        ..Default::default()
    }
}

/// The class of the token at `start` and the index just past it. Every arm
/// advances at least one character, so the caller always makes progress.
fn scan_class(text: &str, start: usize) -> (usize, Class) {
    let bytes = text.as_bytes();
    match bytes[start] {
        b'"' => {
            let end = string_end(bytes, start);
            let class = if followed_by_colon(bytes, end) {
                Class::Key
            } else {
                Class::String
            };
            (end, class)
        }
        b'-' | b'0'..=b'9' => (number_end(bytes, start), Class::Number),
        b't' if text[start..].starts_with("true") => (start + 4, Class::Literal),
        b'f' if text[start..].starts_with("false") => (start + 5, Class::Literal),
        b'n' if text[start..].starts_with("null") => (start + 4, Class::Literal),
        b' ' | b'\t' | b'\r' | b'\n' => (whitespace_end(bytes, start), Class::Punctuation),
        _ => (
            start + text[start..].chars().next().map_or(1, char::len_utf8),
            Class::Punctuation,
        ),
    }
}

/// Just past the string that opens at `start`, quotes included. An escaped
/// character consumes its backslash and the byte after it, so an escaped
/// quote never ends the string; an unterminated string runs to the end.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Whether the next non-whitespace byte is `:`, which makes the string just
/// read an object key rather than a string value.
fn followed_by_colon(bytes: &[u8], mut i: usize) -> bool {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    bytes.get(i) == Some(&b':')
}

/// Just past the JSON number that opens at `start`: optional sign, integer
/// digits, optional fraction, optional exponent.
fn number_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    i
}

fn whitespace_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while bytes
        .get(i)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_rig::wcag_contrast;

    const DOC: &str = "{\n  \"log\": {\"loglevel\": \"warning\"},\n  \"n\": -1.5,\n  \"on\": true,\n  \"none\": null\n}\n";

    fn colors() -> JsonColors {
        json_colors(&Visuals::dark())
    }

    fn painted(job: &LayoutJob) -> Vec<(String, Color32)> {
        job.sections
            .iter()
            .map(|section| {
                let text = &job.text[section.byte_range.start.0..section.byte_range.end.0];
                (text.to_owned(), section.format.color)
            })
            .collect()
    }

    /// Every JSON class takes its own colour: keys are not string values, and
    /// numbers and literals do not read as punctuation. The job copies the
    /// text byte for byte.
    #[test]
    fn each_json_class_takes_its_own_colour() {
        let colors = colors();
        let job = layout_job(DOC, &FontId::monospace(13.0), colors);
        assert_eq!(job.text, DOC, "colouring must not alter the text");

        let sections = painted(&job);
        let colored = |text: &str| -> Color32 {
            sections
                .iter()
                .find(|(painted, _)| painted == text)
                .unwrap_or_else(|| panic!("no painted run {text:?} in {sections:?}"))
                .1
        };
        assert_eq!(colored("\"log\""), colors.key, "an object key");
        assert_eq!(colored("\"warning\""), colors.string, "a string value");
        assert_eq!(colored("-1.5"), colors.number, "a number");
        assert_eq!(colored("true"), colors.literal, "a literal");
        assert_eq!(
            colored("{\n  "),
            colors.punctuation,
            "punctuation and whitespace share one run"
        );
        let palette = [
            colors.key,
            colors.string,
            colors.number,
            colors.literal,
            colors.punctuation,
        ];
        for (index, left) in palette.iter().enumerate() {
            for right in &palette[index + 1..] {
                assert_ne!(left, right, "each class must take its own colour");
            }
        }
    }

    /// Invalid or non-JSON text still renders: an unterminated string and a
    /// non-ASCII byte after a token both lay out without panicking, and the
    /// text survives.
    #[test]
    fn malformed_text_still_lays_out() {
        for text in ["\"unterminated", "{\"a\": 1} ✓ trailing", "✓", ""] {
            let job = layout_job(text, &FontId::monospace(13.0), colors());
            assert_eq!(job.text, text);
        }
    }

    /// The semantic classes clear WCAG AA on the panel each theme paints,
    /// so the palette role a class takes cannot make it unreadable.
    #[test]
    fn semantic_classes_clear_aa_on_both_themes() {
        for visuals in [Visuals::dark(), Visuals::light()] {
            let colors = json_colors(&visuals);
            for (class, color) in [
                ("key", colors.key),
                ("string", colors.string),
                ("number", colors.number),
                ("literal", colors.literal),
                ("punctuation", colors.punctuation),
            ] {
                let ratio = wcag_contrast(color, visuals.panel_fill);
                assert!(
                    ratio >= 4.5,
                    "{class} {color:?} on {:?} is {ratio:.2}:1, below AA",
                    visuals.panel_fill
                );
            }
        }
    }
}

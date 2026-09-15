//! Guards the repo's zero-lint-suppressions contract: authored source must
//! carry no `allow`/`expect` lint attributes and Cargo.toml must not enable
//! lint suppressions.
//!
//! Rust attribute grammar treats ASCII whitespace, newlines, and comments
//! between the tokens of an attribute as insignificant, so a per-line
//! substring scan is evadable: a suppression respelled with spaces, line
//! breaks, or a comment between its tokens still compiles while never
//! appearing as one line's substring. The scan here therefore strips
//! comments and collapses all whitespace per file before matching, and maps
//! every construct it finds back to the source line where it starts; string,
//! raw-string, and char literals are copied verbatim, so a comment marker
//! inside a literal is never read as a comment. A suppression riding inside
//! a multi-line conditional attribute is caught the same way: after the
//! collapse, its open-paren text sits between the conditional's open and the
//! attribute's closing bracket. The manifest check likewise treats any
//! section whose name mentions "lints" as lint configuration, covering
//! inherited `[workspace.lints.rust]` tables next to plain `[lints]` ones.
//!
//! The single permitted exception is the generated protobuf module in
//! `src/rt/grpc.rs`: a blanket allow attribute on `pub mod pb`, whose body is
//! `tonic::include_proto!` output. Generated code cannot carry its own
//! attributes (prost-build has no blanket-attribute emission option), so the
//! allow must live at the include site. The exception is machine-verified
//! below and stays the only accepted occurrence: it must be spelled exactly
//! as the single-line attribute immediately above the generated module in a
//! file embedding `tonic::include_proto!` output. Any respelling — inserting
//! whitespace or comments between the tokens — fails the test.
//!
//! This file is scanned by its own walker, so it never spells the forbidden
//! tokens verbatim: every match token and fixture below is assembled at
//! runtime with `concat!` from pieces that remain separate in the source
//! text, and the comments avoid bracket-plus-name sequences entirely.

use std::ops::Range;
use std::path::{Path, PathBuf};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

// Match tokens, reconstructed so this file cannot match its own scanner.
// The pieces are split so the joined forbidden spellings never appear
// contiguously in the source text above.
const ALLOW: &str = concat!("#[", "allow(");
const ALLOW_INNER: &str = concat!("#![", "allow(");
const EXPECT: &str = concat!("#[", "expect(");
const EXPECT_INNER: &str = concat!("#![", "expect(");
const ALLOW_OPEN: &str = concat!("allow", "(");
const EXPECT_OPEN: &str = concat!("expect", "(");
const CFG_ATTR_OPEN: &str = concat!("cfg", "_attr(");

/// The one permitted suppression, likewise reconstructed.
const GENERATED_MODULE_ALLOW: &str = concat!("#[", "allow(dead_code, clippy::all)]");

#[derive(Debug)]
struct Occurrence {
    file: PathBuf,
    line: usize,
    text: String,
}

fn walk_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("source directory readable") {
        let entry = entry.expect("directory entry readable");
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Comment- and whitespace-insensitive scan of one file's text for every
/// valid spelling of an allow/expect suppression attribute. Returns the
/// 1-based line each offending construct starts on, in file order and
/// without duplicates.
fn suppression_lines(source: &str) -> Vec<usize> {
    // rustc deletes comments before it parses attributes, so a comment
    // anywhere between an attribute's tokens leaves the same suppression
    // behind; drop comments first, then collapse the remaining ASCII
    // whitespace while remembering each surviving byte's original offset, so
    // hits can be mapped back to real lines.
    let (code, code_origin) = without_comments(source);
    let mut stripped = String::with_capacity(code.len());
    let mut origin = Vec::with_capacity(code.len());
    for (index, ch) in code.char_indices() {
        if !ch.is_ascii_whitespace() {
            stripped.push(ch);
            origin.push(code_origin[index]);
        }
    }

    // Directly written allow/expect attributes, outer and inner forms.
    let mut hits: Vec<usize> = Vec::new();
    for token in [ALLOW, ALLOW_INNER, EXPECT, EXPECT_INNER] {
        hits.extend(stripped.match_indices(token).map(|(at, _)| origin[at]));
    }
    // A suppression smuggled into a conditional attribute: after the
    // collapse the attribute is contiguous, so an allow/expect open paren
    // between the conditional's open and the closing bracket counts.
    for (at, _) in stripped.match_indices(CFG_ATTR_OPEN) {
        let rest = &stripped[at + CFG_ATTR_OPEN.len()..];
        if let Some(end) = rest.find(']') {
            let window = &rest[..end];
            if window.contains(ALLOW_OPEN) || window.contains(EXPECT_OPEN) {
                hits.push(origin[at]);
            }
        }
    }

    let mut lines: Vec<usize> = hits
        .into_iter()
        .map(|offset| {
            source.as_bytes()[..offset]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count()
                + 1
        })
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// Copies `source` with line (`//`) and block (`/* ... */`, nesting included)
/// comments removed. String, raw-string, and char literals are copied
/// verbatim, so a comment marker inside one stays data — `"https://x"`,
/// `r#"{"url":"https://x"}"#`, and `'/'` all survive. Returns the
/// comment-free text together with the source offset of each byte in it.
fn without_comments(source: &str) -> (String, Vec<usize>) {
    let bytes = source.as_bytes();
    let mut code = String::with_capacity(source.len());
    let mut origin = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            // Line comment: everything up to the newline is deleted; the
            // newline itself survives as a token separator.
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            // Rust block comments nest, so `/* /* */ */` is one comment.
            let mut depth = 1usize;
            index += 2;
            while index < bytes.len() && depth > 0 {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    depth += 1;
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else if let Some(end) = raw_string_end(source, index) {
            push_range(source, index..end, &mut code, &mut origin);
            index = end;
        } else if bytes[index] == b'"' {
            let end = quoted_end(source, index);
            push_range(source, index..end, &mut code, &mut origin);
            index = end;
        } else if bytes[index] == b'\'' {
            // A `'` opens a char literal only when a closing quote follows
            // the next char or escape; otherwise it is a lifetime or loop
            // label and copies as ordinary code.
            let end = char_literal_end(source, index).unwrap_or(index + 1);
            push_range(source, index..end, &mut code, &mut origin);
            index = end;
        } else {
            let ch = source[index..]
                .chars()
                .next()
                .expect("the scan resumes on char boundaries");
            push_range(source, index..index + ch.len_utf8(), &mut code, &mut origin);
            index += ch.len_utf8();
        }
    }
    (code, origin)
}

/// Appends `source[range]` to `code`, recording the source offset of every
/// appended byte.
fn push_range(source: &str, range: Range<usize>, code: &mut String, origin: &mut Vec<usize>) {
    code.push_str(&source[range.clone()]);
    origin.extend(range);
}

/// The offset just past the closing quote of the string literal opening at
/// `start`, or the end of the file when it is unterminated. Backslash
/// escapes are skipped so an escaped quote stays inside the literal.
fn quoted_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// The offset just past the closing delimiter of the raw string literal
/// opening at `start` (`r"`, `r#"`, ...), or `None` when no raw string
/// starts there. Byte-prefixed forms need no special case: the prefix byte
/// is ordinary code copied before the `r` is reached.
fn raw_string_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(start) != Some(&b'r') {
        return None;
    }
    let mut index = start + 1;
    let mut hashes = 0usize;
    while bytes.get(index) == Some(&b'#') {
        hashes += 1;
        index += 1;
    }
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'"'
            && (0..hashes).all(|offset| bytes.get(index + 1 + offset) == Some(&b'#'))
        {
            return Some(index + 1 + hashes);
        }
        index += 1;
    }
    Some(bytes.len())
}

/// The offset just past the closing quote of the char literal opening at
/// `start`, or `None` when the `'` starts a lifetime or loop label instead
/// (`&'a str`, `'outer: loop`). The escape search is bounded because no
/// valid char escape is longer than `\u{10FFFF}`.
fn char_literal_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start + 1;
    if bytes.get(index) == Some(&b'\\') {
        index += 1;
        let limit = (index + 12).min(bytes.len());
        while index < limit {
            if bytes[index] == b'\'' {
                return Some(index + 1);
            }
            index += 1;
        }
        return None;
    }
    let ch = source.get(index..)?.chars().next()?;
    if ch == '\'' {
        return None;
    }
    let after = index + ch.len_utf8();
    (bytes.get(after) == Some(&b'\'')).then_some(after + 1)
}

fn find_suppressions(path: &Path) -> Vec<Occurrence> {
    let source = std::fs::read_to_string(path).expect("source file readable");
    let lines: Vec<&str> = source.lines().collect();
    suppression_lines(&source)
        .into_iter()
        .map(|line| Occurrence {
            file: path.to_path_buf(),
            line,
            text: lines[line - 1].trim().to_owned(),
        })
        .collect()
}

/// The grpc.rs exception is valid only when it is exactly the generated-code
/// allow — one line, no respelling — immediately above `pub mod pb`, in a
/// file that embeds `tonic::include_proto!` output.
fn is_generated_module_exception(occ: &Occurrence) -> bool {
    if occ.text != GENERATED_MODULE_ALLOW {
        return false;
    }
    let source = std::fs::read_to_string(&occ.file).expect("grpc.rs readable");
    let lines: Vec<&str> = source.lines().collect();
    let next = lines.get(occ.line).map(|line| line.trim()).unwrap_or("");
    if !next.starts_with("pub mod pb") {
        return false;
    }
    source.contains("tonic::include_proto!")
}

/// True when the row configures `allow` as a lint level or as a grouped
/// table key: `allow = [...]`, dotted `rust.allow = [...]`, or the standard
/// per-lint spelling `dead_code = "allow"` (inline tables such as
/// `dead_code = { level = "allow" }` included). 'allow' must stand alone as
/// a word: a row for a lint whose own name merely contains the word is a
/// configuration, not a suppression.
fn row_sets_allow(row: &str) -> bool {
    let bytes = row.as_bytes();
    let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"allow")
            && (i == 0 || !is_ident(bytes[i - 1]))
            && bytes.get(i + 5).is_none_or(|&byte| !is_ident(byte))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Allow entries in the manifest: any non-comment row that sets allow,
/// inside any table whose name mentions "lints" (`[lints]`, `[lints.rust]`,
/// inherited `[workspace.lints.rust]`, ...). Returns (1-based line, text).
fn manifest_allow_rows(manifest: &str) -> Vec<(usize, String)> {
    let mut in_lints_table = false;
    let mut rows = Vec::new();
    for (index, line) in manifest.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_lints_table = trimmed.contains("lints");
            continue;
        }
        if in_lints_table && !trimmed.starts_with('#') && row_sets_allow(trimmed) {
            rows.push((index + 1, trimmed.to_owned()));
        }
    }
    rows
}

// Fixtures for the scanner unit tests. Their runtime values contain the
// forbidden spellings by design; the `concat!` pieces keep those spellings
// out of this file's own source text (this file is scanned too).
const SPACED_ATTR: &str = concat!("#[", " allow", "(dead_code)]\n");
const NEWLINE_SPLIT_ATTR: &str = concat!("fn a() {}\n", "#[", "\nallow", "(dead_code)]\n");
const INNER_EXPECT_ATTR: &str = concat!("#![", "expect", "(unused_imports)]\n");
const MULTILINE_CFG_ATTR: &str = concat!(
    "struct S;\n",
    "#[",
    "cfg",
    "_attr",
    "(\n",
    "    feature = \"x\",\n",
    "    ",
    "allow",
    "(dead_code)\n",
    ")]\n"
);
const HARMLESS_CFG_ATTR: &str = concat!(
    "#[",
    "cfg",
    "_attr",
    "(all(), windows_subsystem = \"windows\")]\n"
);

// Comment-split spellings: rustc deletes comments before parsing, so the
// suppression survives whether the comment sits between the lint name and
// its argument list, before the lint name, or between `#` and `[`.
const COMMENT_INSIDE_ATTR: &str = concat!("#[", "allow", " /*c*/ ", "(dead_code)]\n");
const COMMENT_BEFORE_NAME: &str = concat!("#[", " /*c*/ ", "allow", "(dead_code)]\n");
const COMMENT_BEFORE_BRACKET: &str = concat!("#", "/*c*/", "[", "allow", "(dead_code)]\n");
const LINE_COMMENT_INSIDE_ATTR: &str = concat!("#[", "allow", " //c\n", "(dead_code)]\n");
const COMMENTED_PREAMBLE: &str = concat!(
    "/* header */\n",
    "// explains the item\n",
    "fn a() {}\n",
    "#[",
    " /*c*/ ",
    "allow",
    "(dead_code)]\n"
);
const SUPPRESSION_IN_LINE_COMMENT: &str =
    concat!("// ", "#[", "allow", "(dead_code)]\n", "fn a() {}\n");
const SUPPRESSION_IN_BLOCK_COMMENT: &str = concat!(
    "/* ",
    "#[",
    "expect",
    "(dead_code)] ",
    "*/\n",
    "fn b() {}\n"
);
// `https://` sits inside a literal, so it is data, not a line comment.
const URL_STRING_THEN_ATTR: &str = concat!(
    "fn f() { let _ = \"https://example.com\"; }\n",
    "#[",
    "expect",
    "(unused)]\n"
);
const RAW_URL_STRING_THEN_ATTR: &str = concat!(
    "fn f() { let _ = r#\"https://example.com\"#; }\n",
    "#[",
    "expect",
    "(unused)]\n"
);

#[test]
fn scanner_finds_every_allow_spelling() {
    // Plain, space after the open bracket, and newline between the tokens
    // are the same attribute to rustc; each must be reported at the line
    // where the construct starts.
    assert_eq!(suppression_lines(concat!("#[", "allow(dead_code)]\n")), [1]);
    assert_eq!(suppression_lines(SPACED_ATTR), [1]);
    assert_eq!(suppression_lines(NEWLINE_SPLIT_ATTR), [2]);
}

#[test]
fn scanner_finds_comment_split_spellings() {
    // Comments are insignificant to rustc in attribute position: each of
    // these is the suppression the plain fixture spells, and each is
    // reported on the line where the construct starts — including when the
    // removed comment bytes shift the surviving ones.
    assert_eq!(suppression_lines(COMMENT_INSIDE_ATTR), [1]);
    assert_eq!(suppression_lines(COMMENT_BEFORE_NAME), [1]);
    assert_eq!(suppression_lines(COMMENT_BEFORE_BRACKET), [1]);
    assert_eq!(suppression_lines(LINE_COMMENT_INSIDE_ATTR), [1]);
    assert_eq!(suppression_lines(COMMENTED_PREAMBLE), [4]);
}

#[test]
fn scanner_ignores_suppression_spellings_inside_comments() {
    // A commented-out attribute is not a suppression rustc would apply.
    assert!(suppression_lines(SUPPRESSION_IN_LINE_COMMENT).is_empty());
    assert!(suppression_lines(SUPPRESSION_IN_BLOCK_COMMENT).is_empty());
}

#[test]
fn scanner_reads_comment_markers_inside_literals_as_data() {
    // A scheme's `//` inside a string or raw string is literal data; a scan
    // that read it as a comment would delete the rest of the line and lose
    // (or invent) hits below it.
    assert_eq!(suppression_lines(URL_STRING_THEN_ATTR), [2]);
    assert_eq!(suppression_lines(RAW_URL_STRING_THEN_ATTR), [2]);
}

#[test]
fn scanner_finds_expect_and_cfg_carried_suppressions() {
    assert_eq!(suppression_lines(INNER_EXPECT_ATTR), [1]);
    assert_eq!(suppression_lines(MULTILINE_CFG_ATTR), [2]);
}

#[test]
fn scanner_ignores_non_suppression_attributes() {
    assert!(suppression_lines(HARMLESS_CFG_ATTR).is_empty());
    assert!(suppression_lines(concat!("#[", "derive(Debug, Clone)]\n")).is_empty());
    assert!(suppression_lines("fn allow_list() {}\n").is_empty());
}

const WORKSPACE_LINTS_FIXTURE: &str = concat!(
    "[workspace.lints.rust]\n",
    "allow = [\n",
    "    \"dead_code\",\n",
    "]\n",
    "[workspace.lints.clippy]\n",
    "allow = [\n",
    "    \"all\",\n",
    "]\n",
);

const LINT_ROWS_FIXTURE: &str = concat!(
    "[lints.rust]\n",
    "unsafe_code = \"forbid\"\n",
    "dead_code = \"allow\"\n",
    "allow_attributes = \"warn\"\n",
    "rust.allow = [\"unused\"]\n",
);

const NON_LINTS_FIXTURE: &str = concat!(
    "[features]\n",
    "default = [\"allow-dev\"]\n",
    "[workspace]\n",
    "resolver = \"2\"\n",
    "[workspace.lints.rust]\n",
    "# allow list is maintained elsewhere\n",
    "warn = [\"unused\"]\n",
);

#[test]
fn manifest_check_covers_inherited_workspace_lints_tables() {
    assert_eq!(
        manifest_allow_rows(WORKSPACE_LINTS_FIXTURE),
        [(2, "allow = [".to_owned()), (6, "allow = [".to_owned())]
    );
}

#[test]
fn manifest_check_reads_levels_and_dotted_keys() {
    assert_eq!(
        manifest_allow_rows(LINT_ROWS_FIXTURE),
        [
            (3, "dead_code = \"allow\"".to_owned()),
            (5, "rust.allow = [\"unused\"]".to_owned()),
        ]
    );
}

#[test]
fn manifest_check_ignores_non_lint_tables_comments_and_warns() {
    assert!(manifest_allow_rows(NON_LINTS_FIXTURE).is_empty());
}

#[test]
fn authored_source_has_no_lint_suppressions() {
    let root = Path::new(ROOT);
    let mut files = Vec::new();
    walk_rs_files(&root.join("src"), &mut files);
    walk_rs_files(&root.join("tests"), &mut files);
    files.push(root.join("build.rs"));

    let mut violations = Vec::new();
    for file in files {
        for occ in find_suppressions(&file) {
            if is_generated_module_exception(&occ) {
                continue;
            }
            let relative = occ.file.strip_prefix(root).unwrap_or(&occ.file).display();
            violations.push(format!("{relative}:{}: {}", occ.line, occ.text));
        }
    }
    assert!(
        violations.is_empty(),
        "lint suppressions in authored source violate the zero-suppression contract:\n{}",
        violations.join("\n")
    );
}

#[test]
fn cargo_toml_enables_no_lint_suppressions() {
    let manifest =
        std::fs::read_to_string(Path::new(ROOT).join("Cargo.toml")).expect("Cargo.toml readable");
    let rows = manifest_allow_rows(&manifest);
    assert!(
        rows.is_empty(),
        "Cargo.toml lint allow entries violate the zero-suppression contract:\n{}",
        rows.iter()
            .map(|(line, text)| format!("Cargo.toml:{line}: {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

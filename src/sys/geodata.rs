//! Minimal readers for the managed Xray geosite and geoip protobuf files.
//!
//! The payloads can be large, so this module only decodes the outer entry
//! envelopes and each entry's code. Domain and CIDR fields are skipped in
//! place without allocating or decoding them.

use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MAX_FILE_SIZE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CODE_BYTES: usize = 256;
const MAX_CODES: usize = 65_536;
const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// A point-in-time read of both managed Xray geodata files.
#[derive(Debug)]
pub struct GeodataSnapshot {
    pub geosite: Result<GeodataCatalog, GeodataError>,
    pub geoip: Result<GeodataCatalog, GeodataError>,
}

impl GeodataSnapshot {
    /// Read `%APPDATA%\broccoli\core\geosite.dat` and `geoip.dat`.
    ///
    /// Each side is independent so a missing or corrupt file does not hide a
    /// usable catalog from the other file.
    pub fn load_managed() -> Self {
        Self::load_managed_at(&crate::sys::paths::core_dir())
    }

    /// Read `geosite.dat` and `geoip.dat` from `core_dir`.
    ///
    /// The directory-taking twin of [`GeodataSnapshot::load_managed`]: callers
    /// holding a core directory value (a fixture, a staged tree) parse it
    /// directly instead of redirecting the ambient root, while production
    /// entry points keep resolving `%APPDATA%\broccoli\core` themselves. Each
    /// side is independent so a missing or corrupt file does not hide a usable
    /// catalog from the other file.
    pub fn load_managed_at(core_dir: &Path) -> Self {
        Self {
            geosite: load_catalog(core_dir.join("geosite.dat")),
            geoip: load_catalog(core_dir.join("geoip.dat")),
        }
    }
}

/// Codes extracted from one Xray geodata file and the metadata of the bytes
/// from which they were extracted.
#[derive(Debug)]
pub struct GeodataCatalog {
    pub codes: Vec<String>,
    pub metadata: GeodataFileMetadata,
}

#[derive(Debug)]
pub struct GeodataFileMetadata {
    pub path: PathBuf,
    pub byte_len: u64,
    /// Some filesystems do not expose a modification timestamp.
    pub modified: Option<SystemTime>,
}

/// A load or validation failure tied to one managed geodata file.
#[derive(Debug)]
pub enum GeodataError {
    Io {
        operation: GeodataOperation,
        path: PathBuf,
        source: io::Error,
    },
    TooLarge {
        path: PathBuf,
        byte_len: u64,
        max_byte_len: u64,
    },
    Malformed {
        path: PathBuf,
        offset: usize,
        reason: String,
    },
}

/// The filesystem operation that failed on a managed geodata file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeodataOperation {
    Open,
    Inspect,
    Read,
}

impl GeodataOperation {
    /// The verb as it reads inside the keyed [`GeodataError::Io`] sentence.
    fn text(self, language: Language) -> &'static str {
        match self {
            Self::Open => t(language, Key::GeodataOperationOpen),
            Self::Inspect => t(language, Key::GeodataOperationInspect),
            Self::Read => t(language, Key::GeodataOperationRead),
        }
    }
}

impl GeodataError {
    /// The message in `language`. [`fmt::Display`] renders the English form
    /// through it for logs and tests. The path, byte counts, offset, and
    /// reason stay verbatim runtime values.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => t_fmt(
                language,
                Key::GeodataErrorIo,
                &[&operation.text(language), &path.display(), source],
            ),
            Self::TooLarge {
                path,
                byte_len,
                max_byte_len,
            } => t_fmt(
                language,
                Key::GeodataErrorTooLarge,
                &[&path.display(), byte_len, max_byte_len],
            ),
            Self::Malformed {
                path,
                offset,
                reason,
            } => t_fmt(
                language,
                Key::GeodataErrorMalformed,
                &[&path.display(), offset, reason],
            ),
        }
    }
}

impl fmt::Display for GeodataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

impl Error for GeodataError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::TooLarge { .. } | Self::Malformed { .. } => None,
        }
    }
}

fn load_catalog(path: PathBuf) -> Result<GeodataCatalog, GeodataError> {
    let mut file = File::open(&path).map_err(|source| GeodataError::Io {
        operation: GeodataOperation::Open,
        path: path.clone(),
        source,
    })?;
    let file_metadata = file.metadata().map_err(|source| GeodataError::Io {
        operation: GeodataOperation::Inspect,
        path: path.clone(),
        source,
    })?;
    let announced_len = file_metadata.len();
    if announced_len > MAX_FILE_SIZE_BYTES {
        return Err(GeodataError::TooLarge {
            path,
            byte_len: announced_len,
            max_byte_len: MAX_FILE_SIZE_BYTES,
        });
    }

    let capacity = usize::try_from(announced_len).map_err(|_| GeodataError::TooLarge {
        path: path.clone(),
        byte_len: announced_len,
        max_byte_len: MAX_FILE_SIZE_BYTES,
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| GeodataError::Io {
            operation: GeodataOperation::Read,
            path: path.clone(),
            source,
        })?;
    let byte_len = bytes.len() as u64;
    if byte_len > MAX_FILE_SIZE_BYTES {
        return Err(GeodataError::TooLarge {
            path,
            byte_len,
            max_byte_len: MAX_FILE_SIZE_BYTES,
        });
    }

    let codes = scan_codes(&bytes).map_err(|error| GeodataError::Malformed {
        path: path.clone(),
        offset: error.offset,
        reason: error.kind.to_string(),
    })?;

    Ok(GeodataCatalog {
        codes,
        metadata: GeodataFileMetadata {
            path,
            byte_len,
            modified: file_metadata.modified().ok(),
        },
    })
}

/// Scan a `GeoSiteList` or `GeoIPList`. Both use repeated field 1 for entries,
/// and both embedded entry messages use string field 1 for their code.
fn scan_codes(bytes: &[u8]) -> Result<Vec<String>, ScanError> {
    let mut cursor = 0;
    let mut codes = Vec::new();

    while cursor < bytes.len() {
        let key_offset = cursor;
        let key = read_varint(bytes, &mut cursor, 0)?;
        let (field_number, wire_type) = decode_key(key, key_offset)?;
        if field_number == 1 {
            if wire_type != 2 {
                return Err(ScanError::new(
                    key_offset,
                    ScanErrorKind::UnexpectedWireType {
                        field_number,
                        expected: 2,
                        actual: wire_type,
                    },
                ));
            }
            if codes.len() >= MAX_CODES {
                return Err(ScanError::new(
                    key_offset,
                    ScanErrorKind::TooManyEntries { max: MAX_CODES },
                ));
            }
            let entry_range = read_length_delimited_range(bytes, &mut cursor, 0)?;
            let code = scan_entry_code(&bytes[entry_range.clone()], entry_range.start)?;
            codes.push(code.to_owned());
        } else {
            skip_field(bytes, &mut cursor, wire_type, 0)?;
        }
    }

    // Xray codes are ASCII identifiers. Stable sorting retains the first
    // official spelling when a file repeats a code using different casing.
    codes.sort_by(|left, right| compare_ascii_case_insensitive(left, right));
    codes.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(codes)
}

fn scan_entry_code(entry: &[u8], base_offset: usize) -> Result<&str, ScanError> {
    let mut cursor = 0;
    let mut code = None;

    while cursor < entry.len() {
        let key_offset = base_offset + cursor;
        let key = read_varint(entry, &mut cursor, base_offset)?;
        let (field_number, wire_type) = decode_key(key, key_offset)?;
        if field_number == 1 {
            if wire_type != 2 {
                return Err(ScanError::new(
                    key_offset,
                    ScanErrorKind::UnexpectedWireType {
                        field_number,
                        expected: 2,
                        actual: wire_type,
                    },
                ));
            }
            if code.is_some() {
                return Err(ScanError::new(
                    key_offset,
                    ScanErrorKind::DuplicateCodeField,
                ));
            }
            let code_range = read_length_delimited_range(entry, &mut cursor, base_offset)?;
            if code_range.len() > MAX_CODE_BYTES {
                return Err(ScanError::new(
                    base_offset + code_range.start,
                    ScanErrorKind::CodeTooLong {
                        byte_len: code_range.len(),
                        max_byte_len: MAX_CODE_BYTES,
                    },
                ));
            }
            let code_bytes = &entry[code_range.clone()];
            let parsed = std::str::from_utf8(code_bytes).map_err(|error| {
                ScanError::new(
                    base_offset + code_range.start + error.valid_up_to(),
                    ScanErrorKind::InvalidCodeUtf8,
                )
            })?;
            if parsed.is_empty() {
                return Err(ScanError::new(
                    base_offset + code_range.start,
                    ScanErrorKind::EmptyCode,
                ));
            }
            code = Some(parsed);
        } else {
            skip_field(entry, &mut cursor, wire_type, base_offset)?;
        }
    }

    code.ok_or_else(|| ScanError::new(base_offset, ScanErrorKind::MissingCodeField))
}

fn compare_ascii_case_insensitive(left: &str, right: &str) -> Ordering {
    left.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(right.bytes().map(|byte| byte.to_ascii_lowercase()))
}

fn decode_key(key: u64, offset: usize) -> Result<(u64, u8), ScanError> {
    let field_number = key >> 3;
    let wire_type = (key & 0x07) as u8;
    if field_number == 0 || field_number > MAX_PROTOBUF_FIELD_NUMBER {
        return Err(ScanError::new(
            offset,
            ScanErrorKind::InvalidFieldNumber(field_number),
        ));
    }
    match wire_type {
        0 | 1 | 2 | 5 => Ok((field_number, wire_type)),
        3 | 4 => Err(ScanError::new(
            offset,
            ScanErrorKind::UnsupportedGroupWireType(wire_type),
        )),
        _ => Err(ScanError::new(
            offset,
            ScanErrorKind::InvalidWireType(wire_type),
        )),
    }
}

fn read_varint(bytes: &[u8], cursor: &mut usize, base_offset: usize) -> Result<u64, ScanError> {
    let start = *cursor;
    let mut value = 0_u64;

    for index in 0..10 {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| ScanError::new(base_offset + start, ScanErrorKind::TruncatedVarint))?;
        *cursor += 1;

        if index == 9 && byte > 1 {
            return Err(ScanError::new(
                base_offset + start,
                ScanErrorKind::VarintOverflow,
            ));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }

    Err(ScanError::new(
        base_offset + start,
        ScanErrorKind::VarintOverflow,
    ))
}

fn read_length_delimited_range(
    bytes: &[u8],
    cursor: &mut usize,
    base_offset: usize,
) -> Result<Range<usize>, ScanError> {
    let length_offset = *cursor;
    let encoded_len = read_varint(bytes, cursor, base_offset)?;
    let len = usize::try_from(encoded_len).map_err(|_| {
        ScanError::new(
            base_offset + length_offset,
            ScanErrorKind::LengthOverflow(encoded_len),
        )
    })?;
    let start = *cursor;
    let end = start.checked_add(len).ok_or_else(|| {
        ScanError::new(
            base_offset + length_offset,
            ScanErrorKind::LengthOverflow(encoded_len),
        )
    })?;
    if end > bytes.len() {
        return Err(ScanError::new(
            base_offset + length_offset,
            ScanErrorKind::TruncatedLengthDelimited {
                declared: encoded_len,
                remaining: bytes.len().saturating_sub(start),
            },
        ));
    }
    *cursor = end;
    Ok(start..end)
}

fn skip_field(
    bytes: &[u8],
    cursor: &mut usize,
    wire_type: u8,
    base_offset: usize,
) -> Result<(), ScanError> {
    match wire_type {
        0 => {
            read_varint(bytes, cursor, base_offset)?;
            Ok(())
        }
        1 => advance_fixed(bytes, cursor, 8, base_offset),
        2 => {
            read_length_delimited_range(bytes, cursor, base_offset)?;
            Ok(())
        }
        5 => advance_fixed(bytes, cursor, 4, base_offset),
        3 | 4 => Err(ScanError::new(
            base_offset + *cursor,
            ScanErrorKind::UnsupportedGroupWireType(wire_type),
        )),
        _ => Err(ScanError::new(
            base_offset + *cursor,
            ScanErrorKind::InvalidWireType(wire_type),
        )),
    }
}

fn advance_fixed(
    bytes: &[u8],
    cursor: &mut usize,
    width: usize,
    base_offset: usize,
) -> Result<(), ScanError> {
    let start = *cursor;
    let end = start.checked_add(width).ok_or_else(|| {
        ScanError::new(
            base_offset + start,
            ScanErrorKind::LengthOverflow(width as u64),
        )
    })?;
    if end > bytes.len() {
        return Err(ScanError::new(
            base_offset + start,
            ScanErrorKind::TruncatedFixed {
                width,
                remaining: bytes.len().saturating_sub(start),
            },
        ));
    }
    *cursor = end;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ScanError {
    offset: usize,
    kind: ScanErrorKind,
}

impl ScanError {
    fn new(offset: usize, kind: ScanErrorKind) -> Self {
        Self { offset, kind }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScanErrorKind {
    TruncatedVarint,
    VarintOverflow,
    InvalidFieldNumber(u64),
    InvalidWireType(u8),
    UnsupportedGroupWireType(u8),
    UnexpectedWireType {
        field_number: u64,
        expected: u8,
        actual: u8,
    },
    LengthOverflow(u64),
    TruncatedLengthDelimited {
        declared: u64,
        remaining: usize,
    },
    TruncatedFixed {
        width: usize,
        remaining: usize,
    },
    TooManyEntries {
        max: usize,
    },
    MissingCodeField,
    DuplicateCodeField,
    EmptyCode,
    CodeTooLong {
        byte_len: usize,
        max_byte_len: usize,
    },
    InvalidCodeUtf8,
}

impl fmt::Display for ScanErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedVarint => f.write_str("truncated varint"),
            Self::VarintOverflow => f.write_str("varint exceeds 64 bits"),
            Self::InvalidFieldNumber(number) => {
                write!(f, "invalid protobuf field number {number}")
            }
            Self::InvalidWireType(wire_type) => {
                write!(f, "invalid protobuf wire type {wire_type}")
            }
            Self::UnsupportedGroupWireType(wire_type) => {
                write!(f, "protobuf group wire type {wire_type} is unsupported")
            }
            Self::UnexpectedWireType {
                field_number,
                expected,
                actual,
            } => write!(
                f,
                "field {field_number} uses wire type {actual}; expected {expected}"
            ),
            Self::LengthOverflow(length) => {
                write!(
                    f,
                    "length-delimited field length {length} overflows this platform"
                )
            }
            Self::TruncatedLengthDelimited {
                declared,
                remaining,
            } => write!(
                f,
                "length-delimited field declares {declared} bytes with only {remaining} remaining"
            ),
            Self::TruncatedFixed { width, remaining } => write!(
                f,
                "fixed-width field needs {width} bytes with only {remaining} remaining"
            ),
            Self::TooManyEntries { max } => {
                write!(f, "geodata contains more than {max} entries")
            }
            Self::MissingCodeField => f.write_str("entry has no string field 1 code"),
            Self::DuplicateCodeField => f.write_str("entry repeats string field 1 code"),
            Self::EmptyCode => f.write_str("entry code is empty"),
            Self::CodeTooLong {
                byte_len,
                max_byte_len,
            } => write!(
                f,
                "entry code is {byte_len} bytes; the safety limit is {max_byte_len} bytes"
            ),
            Self::InvalidCodeUtf8 => f.write_str("entry code is not valid UTF-8"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_varint(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_key(output: &mut Vec<u8>, field_number: u64, wire_type: u8) {
        push_varint(output, (field_number << 3) | u64::from(wire_type));
    }

    fn push_bytes_field(output: &mut Vec<u8>, field_number: u64, value: &[u8]) {
        push_key(output, field_number, 2);
        push_varint(output, value.len() as u64);
        output.extend_from_slice(value);
    }

    fn entry(code: &str) -> Vec<u8> {
        let mut output = Vec::new();
        push_bytes_field(&mut output, 1, code.as_bytes());
        output
    }

    fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut output = Vec::new();
        for encoded_entry in entries {
            push_bytes_field(&mut output, 1, encoded_entry);
        }
        output
    }

    #[test]
    fn scans_hand_encoded_entry_envelopes() {
        let encoded = list(&[entry("CN"), entry("private")]);

        assert_eq!(scan_codes(&encoded).unwrap(), ["CN", "private"]);
    }

    #[test]
    fn skips_unknown_standard_wire_fields() {
        let mut encoded_entry = Vec::new();
        push_key(&mut encoded_entry, 7, 0);
        push_varint(&mut encoded_entry, 300);
        push_key(&mut encoded_entry, 8, 1);
        encoded_entry.extend_from_slice(&[0xaa; 8]);
        push_bytes_field(&mut encoded_entry, 1, b"TEST");
        push_bytes_field(&mut encoded_entry, 9, &[0xff, 0x00, 0x80]);
        push_key(&mut encoded_entry, 10, 5);
        encoded_entry.extend_from_slice(&[0xbb; 4]);

        let mut encoded = Vec::new();
        push_key(&mut encoded, 2, 0);
        push_varint(&mut encoded, 1);
        push_key(&mut encoded, 3, 1);
        encoded.extend_from_slice(&[0xcc; 8]);
        push_bytes_field(&mut encoded, 1, &encoded_entry);
        push_bytes_field(&mut encoded, 4, &[0x08, 0xff]);
        push_key(&mut encoded, 5, 5);
        encoded.extend_from_slice(&[0xdd; 4]);

        assert_eq!(scan_codes(&encoded).unwrap(), ["TEST"]);
    }

    #[test]
    fn sorts_and_deduplicates_codes_case_insensitively() {
        let encoded = list(&[
            entry("zulu"),
            entry("cn"),
            entry("Alpha"),
            entry("CN"),
            entry("beta"),
        ]);

        assert_eq!(
            scan_codes(&encoded).unwrap(),
            ["Alpha", "beta", "cn", "zulu"]
        );
    }

    #[test]
    fn rejects_truncated_length_delimited_fields() {
        // The outer entry is complete, but its code claims two bytes and has one.
        let encoded = [0x0a, 0x03, 0x0a, 0x02, b'C'];

        let error = scan_codes(&encoded).unwrap_err();
        assert!(matches!(
            error.kind,
            ScanErrorKind::TruncatedLengthDelimited {
                declared: 2,
                remaining: 1
            }
        ));
    }

    #[test]
    fn rejects_groups_and_overflowing_varints() {
        let group_error = scan_codes(&[0x13]).unwrap_err();
        assert_eq!(group_error.kind, ScanErrorKind::UnsupportedGroupWireType(3));

        let overflow_error = scan_codes(&[0x80; 10]).unwrap_err();
        assert_eq!(overflow_error.kind, ScanErrorKind::VarintOverflow);
    }

    #[test]
    fn rejects_wrong_wire_type_for_entry_and_code() {
        let entry_error = scan_codes(&[0x08, 0x01]).unwrap_err();
        assert!(matches!(
            entry_error.kind,
            ScanErrorKind::UnexpectedWireType {
                field_number: 1,
                expected: 2,
                actual: 0
            }
        ));

        let code_as_varint = [0x0a, 0x02, 0x08, 0x01];
        let code_error = scan_codes(&code_as_varint).unwrap_err();
        assert!(matches!(
            code_error.kind,
            ScanErrorKind::UnexpectedWireType {
                field_number: 1,
                expected: 2,
                actual: 0
            }
        ));
    }

    #[test]
    fn loads_a_catalog_pair_from_a_directory_without_touching_the_environment() {
        // A fixture directory parses through the path-taking entry point: no
        // `%APPDATA%` redirect, no ambient root resolution.
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let geosite_bytes = list(&[entry("CN"), entry("private")]);
        let geoip_bytes = list(&[entry("LAN"), entry("private")]);
        std::fs::write(directory.path().join("geosite.dat"), &geosite_bytes)
            .expect("write geosite fixture");
        std::fs::write(directory.path().join("geoip.dat"), &geoip_bytes)
            .expect("write geoip fixture");

        let snapshot = GeodataSnapshot::load_managed_at(directory.path());

        let geosite = snapshot.geosite.expect("geosite fixture parses");
        assert_eq!(geosite.codes, ["CN", "private"]);
        assert_eq!(
            geosite.metadata.path,
            directory.path().join("geosite.dat"),
            "the catalog must report the file it parsed"
        );
        assert_eq!(
            geosite.metadata.byte_len,
            geosite_bytes.len() as u64,
            "the catalog must report the parsed file's length"
        );
        let geoip = snapshot.geoip.expect("geoip fixture parses");
        assert_eq!(geoip.codes, ["LAN", "private"]);
    }

    #[test]
    fn a_missing_catalog_file_reports_only_that_side() {
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        std::fs::write(directory.path().join("geosite.dat"), list(&[entry("CN")]))
            .expect("write geosite fixture");

        let snapshot = GeodataSnapshot::load_managed_at(directory.path());

        assert_eq!(
            snapshot.geosite.expect("geosite fixture parses").codes,
            ["CN"],
            "the present side must parse despite the missing twin"
        );
        let error = snapshot
            .geoip
            .expect_err("a missing geoip fixture must fail that side");
        assert!(
            matches!(
                error,
                GeodataError::Io {
                    operation: GeodataOperation::Open,
                    ..
                }
            ),
            "a missing file must report the open failure: {error}"
        );
        assert!(
            error.to_string().contains("geoip.dat"),
            "the failure must name the missing file: {error}"
        );
    }

    #[test]
    fn error_text_renders_each_variant_with_its_keyed_message() {
        let io_error = GeodataError::Io {
            operation: GeodataOperation::Read,
            path: PathBuf::from("geosite.dat"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "access is denied"),
        };
        assert_eq!(
            io_error.text(Language::En),
            t_fmt(
                Language::En,
                Key::GeodataErrorIo,
                &[
                    &t(Language::En, Key::GeodataOperationRead),
                    &"geosite.dat",
                    &"access is denied",
                ]
            )
        );

        let too_large = GeodataError::TooLarge {
            path: PathBuf::from("geoip.dat"),
            byte_len: 134_217_729,
            max_byte_len: 134_217_728,
        };
        assert_eq!(
            too_large.text(Language::En),
            t_fmt(
                Language::En,
                Key::GeodataErrorTooLarge,
                &[&"geoip.dat", &134_217_729u64, &134_217_728u64]
            )
        );

        let malformed = GeodataError::Malformed {
            path: PathBuf::from("geosite.dat"),
            offset: 7,
            reason: "entry code is empty".to_owned(),
        };
        assert_eq!(
            malformed.text(Language::En),
            t_fmt(
                Language::En,
                Key::GeodataErrorMalformed,
                &[&"geosite.dat", &7usize, &"entry code is empty"]
            )
        );
    }
}

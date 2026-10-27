//! Minimal readers for the managed Xray geosite and geoip protobuf files.
//!
//! The payloads can be large, so this module only decodes the outer entry
//! envelopes and each entry's code. Domain and CIDR fields are skipped in the
//! byte stream — read past into a sink, never buffered, allocated, or decoded
//! — so loading a DAT costs one buffered pass and one small allocation per
//! entry code, never a whole-file buffer.

use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
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
    // The scan never buffers the file, so the number of bytes it may consume
    // is established once, up front: the file's real length, capped at the
    // probe byte that proves a file grown past the limit after the metadata
    // check (the same cap the old whole-file read applied). That bound is the
    // scan's end of stream, so a length-delimited field claiming more still
    // reports the truncation the in-memory scanner reported.
    let stream_len = file
        .seek(SeekFrom::End(0))
        .map_err(|source| GeodataError::Io {
            operation: GeodataOperation::Read,
            path: path.clone(),
            source,
        })?;
    let byte_len = stream_len.min(MAX_FILE_SIZE_BYTES + 1);
    if byte_len > MAX_FILE_SIZE_BYTES {
        return Err(GeodataError::TooLarge {
            path,
            byte_len,
            max_byte_len: MAX_FILE_SIZE_BYTES,
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| GeodataError::Io {
            operation: GeodataOperation::Read,
            path: path.clone(),
            source,
        })?;

    // One buffered pass over the file: entry envelopes are walked in place,
    // and the domain/CIDR payloads — the bulk of a DAT — are discarded
    // through a sink instead of being materialised, so no whole-file (or
    // whole-entry) buffer is ever allocated.
    let codes = scan_codes_stream(BufReader::new(file), byte_len).map_err(|error| match error {
        CatalogScanError::Malformed(error) => GeodataError::Malformed {
            path: path.clone(),
            offset: error.offset,
            reason: error.kind.to_string(),
        },
        CatalogScanError::Io(source) => GeodataError::Io {
            operation: GeodataOperation::Read,
            path: path.clone(),
            source,
        },
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

/// A failed incremental scan: either a malformed byte stream — reported with
/// the same offset and reason the whole-buffer scanner produced — or an I/O
/// failure that reading the file piecewise can now surface.
enum CatalogScanError {
    Malformed(ScanError),
    Io(io::Error),
}

impl From<ScanError> for CatalogScanError {
    fn from(error: ScanError) -> Self {
        Self::Malformed(error)
    }
}

/// A bounded incremental reader over one geodata byte stream.
///
/// `position` is the absolute offset of the next byte, so every error names
/// the same `offset` a scan over the whole file buffer would have named. The
/// `Take` bound is what ends a (sub)stream: the file cap for the outer scan,
/// the entry's declared length for an entry envelope. Payloads are
/// bounds-checked against `remaining` and then discarded through a sink, so
/// nothing but a single entry's code is ever buffered.
struct ScanStream<R> {
    reader: io::Take<R>,
    position: u64,
}

impl<R: Read> ScanStream<R> {
    fn new(reader: R, length: u64, start: u64) -> Self {
        Self {
            reader: reader.take(length),
            position: start,
        }
    }

    /// The offset every error at this point must report.
    ///
    /// The stream is length-capped at `MAX_FILE_SIZE_BYTES + 1`, which fits a
    /// `usize` on every supported target, so the cast never truncates.
    fn offset(&self) -> usize {
        self.position as usize
    }

    fn remaining(&self) -> u64 {
        self.reader.limit()
    }

    /// Read as much of `out` as the stream still allows, retrying interrupted
    /// reads; a short result means the stream ended early.
    fn read_up_to(&mut self, out: &mut [u8]) -> Result<usize, CatalogScanError> {
        let mut filled = 0;
        while filled < out.len() {
            match self.reader.read(&mut out[filled..]) {
                Ok(0) => break,
                Ok(read) => {
                    filled += read;
                    self.position += read as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(CatalogScanError::Io(error)),
            }
        }
        Ok(filled)
    }

    fn read_byte(&mut self) -> Result<Option<u8>, CatalogScanError> {
        let mut byte = [0_u8; 1];
        Ok((self.read_up_to(&mut byte)? == 1).then_some(byte[0]))
    }

    /// Read one base-128 varint. A truncated stream and a value wider than 64
    /// bits keep their historical error offsets.
    fn read_varint(&mut self) -> Result<u64, CatalogScanError> {
        let start = self.offset();
        let mut value = 0_u64;

        for index in 0..10 {
            let Some(byte) = self.read_byte()? else {
                return Err(ScanError::new(start, ScanErrorKind::TruncatedVarint).into());
            };

            if index == 9 && byte > 1 {
                return Err(ScanError::new(start, ScanErrorKind::VarintOverflow).into());
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }

        Err(ScanError::new(start, ScanErrorKind::VarintOverflow).into())
    }

    /// Read a length-delimited field's byte count and reject one that runs
    /// past the end of this (sub)stream. The payload starts at the current
    /// offset once this returns.
    fn read_length(&mut self) -> Result<u64, CatalogScanError> {
        let length_offset = self.offset();
        let encoded_len = self.read_varint()?;
        // Platform overflow keeps its historical error: a length this
        // platform cannot even address (or an offset that would wrap) is not
        // the same fact as a length that runs past the stream.
        let overflow = || ScanError::new(length_offset, ScanErrorKind::LengthOverflow(encoded_len));
        let len = usize::try_from(encoded_len).map_err(|_| overflow())?;
        length_offset.checked_add(len).ok_or_else(overflow)?;
        let remaining = self.remaining();
        if encoded_len > remaining {
            return Err(ScanError::new(
                length_offset,
                ScanErrorKind::TruncatedLengthDelimited {
                    declared: encoded_len,
                    remaining: remaining as usize,
                },
            )
            .into());
        }
        Ok(encoded_len)
    }

    /// Read and discard `len` bytes, returning how many the stream actually
    /// held. `io::copy` into `sink` keeps the source buffered and the memory
    /// use flat.
    fn discard(&mut self, len: u64) -> Result<u64, CatalogScanError> {
        let mut limited = self.reader.by_ref().take(len);
        let copied = io::copy(&mut limited, &mut io::sink()).map_err(CatalogScanError::Io)?;
        self.position += copied;
        Ok(copied)
    }

    /// Skip a length-delimited payload `read_length` already bounds-checked.
    fn skip_payload(&mut self, len: u64, length_offset: usize) -> Result<(), CatalogScanError> {
        let copied = self.discard(len)?;
        if copied < len {
            return Err(ScanError::new(
                length_offset,
                ScanErrorKind::TruncatedLengthDelimited {
                    declared: len,
                    remaining: copied as usize,
                },
            )
            .into());
        }
        Ok(())
    }

    /// Skip a fixed-width field of `width` bytes.
    fn skip_fixed(&mut self, width: usize) -> Result<(), CatalogScanError> {
        let start = self.offset();
        let remaining = self.remaining();
        if width as u64 > remaining {
            return Err(ScanError::new(
                start,
                ScanErrorKind::TruncatedFixed {
                    width,
                    remaining: remaining as usize,
                },
            )
            .into());
        }
        let copied = self.discard(width as u64)?;
        if copied < width as u64 {
            return Err(ScanError::new(
                start,
                ScanErrorKind::TruncatedFixed {
                    width,
                    remaining: copied as usize,
                },
            )
            .into());
        }
        Ok(())
    }
}

/// Scan a `GeoSiteList` or `GeoIPList` stream. Both use repeated field 1 for
/// entries, and both embedded entry messages use string field 1 for their
/// code.
fn scan_codes_stream<R: Read>(reader: R, length: u64) -> Result<Vec<String>, CatalogScanError> {
    let mut stream = ScanStream::new(reader, length, 0);
    let mut codes = Vec::new();

    while stream.remaining() > 0 {
        let key_offset = stream.offset();
        let key = stream.read_varint()?;
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
                )
                .into());
            }
            if codes.len() >= MAX_CODES {
                return Err(ScanError::new(
                    key_offset,
                    ScanErrorKind::TooManyEntries { max: MAX_CODES },
                )
                .into());
            }
            let entry_len = stream.read_length()?;
            let entry_offset = stream.position;
            // The entry envelope is its own bounded stream: nothing inside it
            // can read past its declared length, and its code field is the
            // only bytes this scan copies out.
            let code = {
                let mut entry = ScanStream::new(&mut stream.reader, entry_len, entry_offset);
                scan_entry_code(&mut entry)?
            };
            // The envelope was consumed in full; keep the outer offset in
            // step without re-reading anything.
            stream.position = entry_offset + entry_len;
            codes.push(code);
        } else {
            skip_field(&mut stream, wire_type)?;
        }
    }

    // Xray codes are ASCII identifiers. Stable sorting retains the first
    // official spelling when a file repeats a code using different casing.
    codes.sort_by(|left, right| compare_ascii_case_insensitive(left, right));
    codes.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(codes)
}

/// Whole-buffer entry point for the scanner's unit tests: a byte slice is a
/// complete stream, and an in-memory read cannot fail with I/O.
#[cfg(test)]
fn scan_codes(bytes: &[u8]) -> Result<Vec<String>, ScanError> {
    scan_codes_stream(bytes, bytes.len() as u64).map_err(|error| match error {
        CatalogScanError::Malformed(error) => error,
        CatalogScanError::Io(error) => {
            panic!("in-memory geodata scan cannot fail with I/O: {error}")
        }
    })
}

/// Scan one entry envelope for its string field 1 code.
///
/// The envelope's other fields are the domain/CIDR lists that make a DAT
/// large, so they are discarded through the stream and never buffered; only
/// the bounded code string is copied out.
fn scan_entry_code<R: Read>(entry: &mut ScanStream<R>) -> Result<String, CatalogScanError> {
    let base_offset = entry.offset();
    let mut code = None;

    while entry.remaining() > 0 {
        let key_offset = entry.offset();
        let key = entry.read_varint()?;
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
                )
                .into());
            }
            if code.is_some() {
                return Err(ScanError::new(key_offset, ScanErrorKind::DuplicateCodeField).into());
            }
            let length_offset = entry.offset();
            let code_len = entry.read_length()?;
            let code_offset = entry.offset();
            if code_len > MAX_CODE_BYTES as u64 {
                return Err(ScanError::new(
                    code_offset,
                    ScanErrorKind::CodeTooLong {
                        byte_len: code_len as usize,
                        max_byte_len: MAX_CODE_BYTES,
                    },
                )
                .into());
            }
            let mut code_bytes = vec![0_u8; code_len as usize];
            let copied = entry.read_up_to(&mut code_bytes)?;
            if copied < code_bytes.len() {
                return Err(ScanError::new(
                    length_offset,
                    ScanErrorKind::TruncatedLengthDelimited {
                        declared: code_len,
                        remaining: copied,
                    },
                )
                .into());
            }
            let parsed = String::from_utf8(code_bytes).map_err(|error| {
                ScanError::new(
                    code_offset + error.utf8_error().valid_up_to(),
                    ScanErrorKind::InvalidCodeUtf8,
                )
            })?;
            if parsed.is_empty() {
                return Err(ScanError::new(code_offset, ScanErrorKind::EmptyCode).into());
            }
            code = Some(parsed);
        } else {
            skip_field(entry, wire_type)?;
        }
    }

    code.ok_or_else(|| ScanError::new(base_offset, ScanErrorKind::MissingCodeField).into())
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

/// Skip one field of the enclosing (sub)stream, whatever its wire type.
fn skip_field<R: Read>(stream: &mut ScanStream<R>, wire_type: u8) -> Result<(), CatalogScanError> {
    match wire_type {
        0 => {
            stream.read_varint()?;
            Ok(())
        }
        1 => stream.skip_fixed(8),
        2 => {
            let length_offset = stream.offset();
            let len = stream.read_length()?;
            stream.skip_payload(len, length_offset)
        }
        5 => stream.skip_fixed(4),
        3 | 4 => Err(ScanError::new(
            stream.offset(),
            ScanErrorKind::UnsupportedGroupWireType(wire_type),
        )
        .into()),
        _ => Err(ScanError::new(stream.offset(), ScanErrorKind::InvalidWireType(wire_type)).into()),
    }
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
    fn skips_an_entry_payload_larger_than_the_read_buffer() {
        // A real entry's domain list is far larger than any read buffer; the
        // scan must discard it in place and still find a code field after it.
        // The code comes second so this also proves the scan continues inside
        // the entry after a skipped payload.
        let mut encoded_entry = Vec::new();
        push_bytes_field(&mut encoded_entry, 2, &vec![b'x'; 300 * 1024]);
        push_bytes_field(&mut encoded_entry, 1, b"LARGE");

        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let geosite = list(&[encoded_entry]);
        std::fs::write(directory.path().join("geosite.dat"), &geosite)
            .expect("write geosite fixture");
        std::fs::write(directory.path().join("geoip.dat"), list(&[entry("LAN")]))
            .expect("write geoip fixture");

        let catalog = GeodataSnapshot::load_managed_at(directory.path())
            .geosite
            .expect("a large entry payload must parse");
        assert_eq!(catalog.codes, ["LARGE"]);
        assert_eq!(
            catalog.metadata.byte_len,
            geosite.len() as u64,
            "the streamed catalog must report the file's full length"
        );
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

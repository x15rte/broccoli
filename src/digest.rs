//! Lowercase-hex rendering of digests and byte strings.
//!
//! One owner for the spelling every hash site renders: the pinned payload
//! checks, the staged-config stamps, the TLS pin transcript, and the
//! generated credentials all display or compare through these two functions.
//! `sha2` 0.11 no longer formats its output through `LowerHex`, so the
//! rendering lives here instead of in every caller.

use std::io;

use sha2::{Digest as _, Sha256};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Lowercase hex SHA-256 of everything `reader` yields, streamed through a
/// heap buffer so a large or hostile source cannot grow the stack or the
/// heap beyond that buffer.
pub fn sha256_reader(reader: &mut impl io::Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{hex, sha256_hex, sha256_reader};

    /// Known-answer vectors: SHA-256 of the empty string and of `abc` are
    /// published test vectors, not recomputed the way the code does.
    #[test]
    fn sha256_hex_matches_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0x0f, 0xa0, 0xff]), "0fa0ff");
    }

    /// The streaming form hashes the same bytes as the in-memory one, across
    /// chunk boundaries (a reader that yields one byte at a time).
    #[test]
    fn sha256_reader_matches_the_in_memory_digest() {
        let payload = b"abc";
        let expected = sha256_hex(payload);
        assert_eq!(
            sha256_reader(&mut std::io::Cursor::new(payload)).expect("hash the stream"),
            expected
        );
        struct Trickle<'a>(&'a [u8]);
        impl std::io::Read for Trickle<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let Some((first, rest)) = self.0.split_first() else {
                    return Ok(0);
                };
                if let Some(slot) = out.first_mut() {
                    *slot = *first;
                }
                self.0 = rest;
                Ok(1)
            }
        }
        assert_eq!(
            sha256_reader(&mut Trickle(payload)).expect("hash the trickled stream"),
            expected
        );
    }
}

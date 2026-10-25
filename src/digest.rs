//! Lowercase-hex rendering of digests and byte strings.
//!
//! One owner for the spelling every hash site renders: the pinned payload
//! checks, the staged-config stamps, the TLS pin transcript, and the
//! generated credentials all display or compare through these two functions.
//! `sha2` 0.11 no longer formats its output through `LowerHex`, so the
//! rendering lives here instead of in every caller.

use sha2::{Digest as _, Sha256};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{hex, sha256_hex};

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
}

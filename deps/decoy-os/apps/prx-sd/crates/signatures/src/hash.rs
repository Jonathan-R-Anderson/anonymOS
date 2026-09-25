//! Hash computation utilities for signature matching.
//!
//! Provides SHA-256 and MD5 hash functions for both in-memory data
//! and file-based hashing with chunked async I/O.

use std::path::Path;

use anyhow::Result;
use md5::Md5;
use sha2::Sha256;
use tracing::instrument;

/// Compute a SHA-256 hash of the given data, returning raw bytes.
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute an MD5 hash of the given data, returning raw bytes.
pub fn md5_hash(data: &[u8]) -> Vec<u8> {
    use md5::Digest;
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute a SHA-256 hash and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_hash(data))
}

/// Compute an MD5 hash and return it as a lowercase hex string.
pub fn md5_hex(data: &[u8]) -> String {
    hex_encode(&md5_hash(data))
}

/// Asynchronously compute the SHA-256 hash of a file, reading in 8KB chunks.
///
/// This avoids loading the entire file into memory at once.
#[instrument(skip_all, fields(path = %path.display()))]
pub async fn sha256_file(path: &Path) -> Result<Vec<u8>> {
    use sha2::Digest;
    use tokio::io::AsyncReadExt;

    const BUF_SIZE: usize = 8192;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        // n is always <= buf.len() per the AsyncRead contract,
        // but we use .get() to satisfy clippy::indexing_slicing.
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
    }

    Ok(hasher.finalize().to_vec())
}

/// Encode raw bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // write! to a String never fails, but we handle it for safety.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string
        let hash = sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_md5_known_vector() {
        // MD5 of empty string
        let hash = md5_hex(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256_hex(b"abc");
        assert_eq!(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_md5_abc() {
        let hash = md5_hex(b"abc");
        assert_eq!(hash, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_raw_bytes_length() {
        assert_eq!(sha256_hash(b"test").len(), 32);
        assert_eq!(md5_hash(b"test").len(), 16);
    }

    #[tokio::test]
    async fn test_sha256_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        std::fs::write(&file_path, b"hello world").unwrap();

        let hash = sha256_file(&file_path).await.unwrap();
        let expected = sha256_hash(b"hello world");
        assert_eq!(hash, expected);
    }
}

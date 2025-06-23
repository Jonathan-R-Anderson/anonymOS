//! Cryptographic engine derived from the UPSS project.
//!
//! Functions here would encrypt/decrypt file blocks, sign metadata and
//! maintain a revision log to enable redaction or rollback.

/// Encrypt a blob of data.
pub fn encrypt_blob(data: &[u8]) -> Vec<u8> {
    // Very small XOR-based transformation used for the examples
    data.iter().map(|b| b ^ 0xAA).collect()
}

/// Decrypt a blob of data.
pub fn decrypt_blob(data: &[u8]) -> Vec<u8> {
    // Same operation as encrypt since XOR is symmetric
    encrypt_blob(data)
}

/// Sign metadata and return a signature.
pub fn sign_metadata(meta: &[u8]) -> Vec<u8> {
    let mut sum: u32 = 0;
    for b in meta { sum = sum.wrapping_add(*b as u32); }
    sum.to_le_bytes().to_vec()
}

/// Verify metadata signature.
pub fn verify_metadata(meta: &[u8], sig: &[u8]) -> bool {
    sign_metadata(meta) == sig
}

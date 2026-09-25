//! Ed25519 signature verification and signing for update payloads.
//!
//! Payload wire format: `[64 bytes Ed25519 signature][data]`.
//! The signature covers exactly the `data` portion that follows it.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Size of an Ed25519 signature in bytes.
const SIGNATURE_LEN: usize = 64;

/// Verify a signed payload and return the data portion.
///
/// The `payload` is expected to be `[64-byte Ed25519 signature][data]`.
/// Returns the `data` slice (copied into a `Vec`) if the signature is valid
/// over that data. Returns an error if the payload is too short or the
/// signature does not verify.
pub fn verify_payload(key: &VerifyingKey, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() > SIGNATURE_LEN,
        "payload too short: expected at least {} bytes, got {}",
        SIGNATURE_LEN + 1,
        payload.len()
    );

    let (sig_bytes, data) = payload.split_at(SIGNATURE_LEN);

    let sig = Signature::from_slice(sig_bytes).context("invalid Ed25519 signature bytes")?;

    key.verify(data, &sig)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;

    Ok(data.to_vec())
}

/// Sign data and return a payload with the signature prepended.
///
/// Returns `[64-byte Ed25519 signature][data]`.
pub fn sign_payload(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let sig = key.sign(data);
    let sig_bytes = sig.to_bytes();

    let mut payload = Vec::with_capacity(SIGNATURE_LEN + data.len());
    payload.extend_from_slice(&sig_bytes);
    payload.extend_from_slice(data);
    payload
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let data = b"hello antivirus update world";

        let payload = sign_payload(&sk, data);
        assert_eq!(payload.len(), 64 + data.len());

        let recovered = verify_payload(&vk, &payload).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_verify_rejects_tampered_data() {
        let (sk, vk) = generate_keypair();
        let data = b"original data";

        let mut payload = sign_payload(&sk, data);
        // Tamper with the data portion.
        if let Some(last) = payload.last_mut() {
            *last ^= 0xff;
        }

        let result = verify_payload(&vk, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let data = b"signed by someone else";

        let payload = sign_payload(&sk, data);
        let result = verify_payload(&wrong_vk, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_too_short() {
        let (_, vk) = generate_keypair();
        // Exactly 64 bytes (no data) should fail.
        let result = verify_payload(&vk, &[0u8; 64]);
        assert!(result.is_err());

        // Less than 64 bytes should also fail.
        let result = verify_payload(&vk, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let (sk, vk) = generate_keypair();
        let data = b"x"; // minimum 1 byte of data
        let payload = sign_payload(&sk, data);
        let recovered = verify_payload(&vk, &payload).unwrap();
        assert_eq!(recovered, data);
    }

    /// A payload whose first 64 bytes are all zero (an invalid Ed25519
    /// signature) must be rejected even when the trailing data is non-empty.
    #[test]
    fn verify_rejects_all_zero_signature() {
        let (_, vk) = generate_keypair();

        // Build a payload with a zeroed-out signature prefix.
        let data = b"some valid looking data after the signature";
        let mut payload = vec![0u8; 64];
        payload.extend_from_slice(data);

        let result = verify_payload(&vk, &payload);
        assert!(result.is_err(), "all-zero Ed25519 signature must be rejected");
    }

    /// Signing a 1 MiB payload and verifying it must succeed, and the
    /// recovered data must match the original byte-for-byte.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn sign_verify_large_payload() {
        let (sk, vk) = generate_keypair();

        // 1 MiB of deterministic pseudo-random bytes (simple LCG).
        let data: Vec<u8> = (0u64..(1024 * 1024))
            .map(|i| {
                i.wrapping_mul(6_364_136_223_846_793_005_u64)
                    .wrapping_add(1_442_695_040_888_963_407_u64)
                    .wrapping_shr(56) as u8
            })
            .collect();

        let payload = sign_payload(&sk, &data);
        assert_eq!(
            payload.len(),
            64 + data.len(),
            "signed payload must be exactly 64 + data bytes long"
        );

        let recovered =
            verify_payload(&vk, &payload).expect("verify_payload must succeed for a legitimately signed large payload");
        assert_eq!(
            recovered, data,
            "recovered data must be identical to the original 1 MiB payload"
        );
    }

    /// A payload that is exactly 64 bytes long contains only a signature and
    /// zero data bytes; this must be rejected because the wire format requires
    /// at least one data byte following the 64-byte signature.
    #[test]
    fn verify_exact_signature_length_no_data() {
        let (_, vk) = generate_keypair();

        // Payload is exactly SIGNATURE_LEN bytes — no data portion at all.
        let payload = [0u8; 64];
        let result = verify_payload(&vk, &payload);

        assert!(
            result.is_err(),
            "a payload of exactly 64 bytes (no data) must be rejected"
        );
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("payload too short"),
            "error must mention 'payload too short', got: {err_msg}"
        );
    }
}

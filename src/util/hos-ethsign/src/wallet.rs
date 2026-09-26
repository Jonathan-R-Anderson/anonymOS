//! Key material: derive the signing key + Ethereum address from a BIP-39 mnemonic (the seed the
//! user backs up via scripts/attest-deploy.sh) or from a raw private key. Uses audited RustCrypto
//! (`k256`) and `bip32`; no hand-rolled EC math.

use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Ethereum's default account derivation path, matching Foundry/MetaMask: m/44'/60'/0'/0/index.
fn eth_path(index: u32) -> Result<DerivationPath, String> {
    format!("m/44'/60'/0'/0/{index}")
        .parse()
        .map_err(|e| format!("derivation path: {e}"))
}

/// BIP-39 phrase (+ optional passphrase) -> the index-th secp256k1 signing key. Accepts any valid
/// mnemonic length (12/15/18/21/24 words) via the `bip39` crate; `bip32` does the HD derivation.
pub fn key_from_mnemonic(phrase: &str, passphrase: &str, index: u32) -> Result<SigningKey, String> {
    let mnemonic = Mnemonic::parse_normalized(phrase.trim())
        .map_err(|e| format!("invalid BIP-39 mnemonic: {e}"))?;
    let seed = mnemonic.to_seed(passphrase); // [u8; 64]
    let xprv = XPrv::derive_from_path(seed, &eth_path(index)?)
        .map_err(|e| format!("HD derive: {e}"))?;
    Ok(xprv.private_key().clone())
}

/// Raw 32-byte private key (hex, optional 0x) -> signing key.
pub fn key_from_hex(s: &str) -> Result<SigningKey, String> {
    let s = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(|e| format!("private key hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("private key must be 32 bytes, got {}", bytes.len()));
    }
    SigningKey::from_slice(&bytes).map_err(|e| format!("private key: {e}"))
}

/// The 20-byte Ethereum address for a signing key: keccak256(uncompressed pubkey X||Y)[12..].
pub fn address_of(sk: &SigningKey) -> [u8; 20] {
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let hash = keccak256(&point.as_bytes()[1..]); // drop the 0x04 tag
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 checksummed "0x…" address string.
pub fn address_checksummed(addr: &[u8; 20]) -> String {
    let hexed = hex::encode(addr); // lowercase, 40 chars
    let hash = keccak256(hexed.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hexed.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            // uppercase the hex letter if the corresponding hash nibble >= 8
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical 24-word BIP-39 vector (23x "abandon" + "art"). Ground truth from Foundry on this
    // machine: `cast wallet address/private-key --mnemonic <file> --mnemonic-index 0` (matches
    // scripts/attest-deploy.sh's default 24-word wallet). Confirms parse + HD path + address.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon art";
    const ADDR0: &str = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb";
    const KEY0: &str = "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f";

    #[test]
    fn mnemonic_account0_matches_cast() {
        let sk = key_from_mnemonic(PHRASE, "", 0).unwrap();
        assert_eq!(hex::encode(sk.to_bytes()), KEY0, "derived private key");
        assert_eq!(address_checksummed(&address_of(&sk)), ADDR0, "derived address (EIP-55)");
    }

    // Well-known test key (all EIP-155 examples use it): privkey ...4646 -> 0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F
    #[test]
    fn known_privkey_address() {
        let sk = key_from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
            .unwrap();
        let addr = address_of(&sk);
        assert_eq!(
            address_checksummed(&addr),
            "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
        );
    }
}

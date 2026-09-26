//! Ethereum transaction construction + signing: EIP-1559 (type 2) and legacy EIP-155.
//! secp256k1 signing is RFC-6979 deterministic with low-S normalization (via `k256`), so the
//! output matches Foundry/ethers byte-for-byte (the tests cross-check the canonical EIP-155
//! spec vector, and build-verify.sh cross-checks EIP-1559 against `cast mktx`).

use crate::rlp;
use crate::wallet::keccak256;
use k256::ecdsa::SigningKey;

pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
}

pub struct Legacy {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
}

fn encode_to(out: &mut Vec<u8>, to: &Option<[u8; 20]>) {
    match to {
        Some(a) => rlp::encode_bytes(out, a),
        None => rlp::encode_bytes(out, &[]), // empty = contract creation
    }
}

fn sig_rs(sk: &SigningKey, hash: &[u8; 32]) -> (u8, [u8; 32], [u8; 32]) {
    let (sig, recid) = sk
        .sign_prehash_recoverable(hash)
        .expect("prehash signing cannot fail for a valid key");
    let b = sig.to_bytes(); // r || s, 32 bytes each, big-endian, low-S normalized
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&b[..32]);
    s.copy_from_slice(&b[32..]);
    (recid.to_byte(), r, s)
}

impl Eip1559 {
    /// The 8 unsigned fields + empty access list, RLP-encoded and concatenated (not list-wrapped).
    fn inner(&self) -> Vec<u8> {
        let mut p = Vec::new();
        rlp::encode_u64(&mut p, self.chain_id);
        rlp::encode_u64(&mut p, self.nonce);
        rlp::encode_u128(&mut p, self.max_priority_fee);
        rlp::encode_u128(&mut p, self.max_fee);
        rlp::encode_u64(&mut p, self.gas_limit);
        encode_to(&mut p, &self.to);
        rlp::encode_u128(&mut p, self.value);
        rlp::encode_bytes(&mut p, &self.data);
        rlp::encode_list(&mut p, &[]); // empty access list
        p
    }

    /// -> (raw signed tx bytes `0x02 || rlp(...)`, tx hash).
    pub fn sign(&self, sk: &SigningKey) -> (Vec<u8>, [u8; 32]) {
        let inner = self.inner();
        let mut signing = vec![0x02u8];
        rlp::encode_list(&mut signing, &inner);
        let hash = keccak256(&signing);
        let (y_parity, r, s) = sig_rs(sk, &hash);

        let mut signed_inner = inner;
        rlp::encode_u64(&mut signed_inner, y_parity as u64);
        rlp::encode_uint_be(&mut signed_inner, &r);
        rlp::encode_uint_be(&mut signed_inner, &s);
        let mut raw = vec![0x02u8];
        rlp::encode_list(&mut raw, &signed_inner);
        let txhash = keccak256(&raw);
        (raw, txhash)
    }
}

impl Legacy {
    fn six(&self, out: &mut Vec<u8>) {
        rlp::encode_u64(out, self.nonce);
        rlp::encode_u128(out, self.gas_price);
        rlp::encode_u64(out, self.gas_limit);
        encode_to(out, &self.to);
        rlp::encode_u128(out, self.value);
        rlp::encode_bytes(out, &self.data);
    }

    pub fn sign(&self, sk: &SigningKey) -> (Vec<u8>, [u8; 32]) {
        // EIP-155 signing payload: rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])
        let mut inner = Vec::new();
        self.six(&mut inner);
        rlp::encode_u64(&mut inner, self.chain_id);
        rlp::encode_u64(&mut inner, 0);
        rlp::encode_u64(&mut inner, 0);
        let mut signing = Vec::new();
        rlp::encode_list(&mut signing, &inner);
        let hash = keccak256(&signing);
        let (recid, r, s) = sig_rs(sk, &hash);
        let v = recid as u64 + 35 + 2 * self.chain_id; // EIP-155 v

        let mut signed_inner = Vec::new();
        self.six(&mut signed_inner);
        rlp::encode_u64(&mut signed_inner, v);
        rlp::encode_uint_be(&mut signed_inner, &r);
        rlp::encode_uint_be(&mut signed_inner, &s);
        let mut raw = Vec::new();
        rlp::encode_list(&mut raw, &signed_inner);
        let txhash = keccak256(&raw);
        (raw, txhash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::key_from_hex;

    // The canonical example from the EIP-155 specification itself:
    //   nonce 9, gasPrice 20 gwei, gas 21000, to 0x3535..35, value 1 ETH, data "", chainId 1,
    //   privkey 0x4646..46 -> a fixed, spec-published signed transaction.
    #[test]
    fn eip155_spec_vector() {
        let sk = key_from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
            .unwrap();
        let mut to = [0u8; 20];
        to.copy_from_slice(&hex::decode("3535353535353535353535353535353535353535").unwrap());
        let tx = Legacy {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some(to),
            value: 1_000_000_000_000_000_000,
            data: vec![],
        };
        let (raw, _hash) = tx.sign(&sk);
        assert_eq!(
            hex::encode(&raw),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000\
8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb70330\
4b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    // Contract-creation shape: `to` is empty. Just check it signs + round-trips structurally.
    #[test]
    fn eip1559_create_is_type2_and_stable() {
        let sk = key_from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
            .unwrap();
        let tx = Eip1559 {
            chain_id: 84532,
            nonce: 0,
            max_priority_fee: 1_000_000,
            max_fee: 1_000_000_000,
            gas_limit: 500_000,
            to: None,
            value: 0,
            data: hex::decode("6080604052").unwrap(),
        };
        let (raw, _h) = tx.sign(&sk);
        assert_eq!(raw[0], 0x02, "EIP-1559 envelope byte");
        // deterministic (RFC-6979): signing twice yields identical bytes
        let (raw2, _) = tx.sign(&sk);
        assert_eq!(raw, raw2);
    }
}

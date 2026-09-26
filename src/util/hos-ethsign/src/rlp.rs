//! Minimal RLP encoding — only what Ethereum transaction encoding needs (byte strings, lists,
//! and big-endian unsigned integers with leading zeros stripped). Kept tiny and covered by the
//! transaction test vectors in `tx.rs`, which cross-check the whole encoding against `cast`.

/// Encode a byte string per RLP rules.
pub fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]); // single low byte is its own encoding
    } else {
        encode_len(out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
}

/// Wrap an already-encoded payload as an RLP list.
pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    encode_len(out, payload.len(), 0xc0);
    out.extend_from_slice(payload);
}

/// Encode an unsigned integer given as a big-endian slice: strip leading zero bytes, then encode
/// as a byte string (so 0 becomes the empty string 0x80, per Ethereum convention).
pub fn encode_uint_be(out: &mut Vec<u8>, be: &[u8]) {
    let start = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    encode_bytes(out, &be[start..]);
}

pub fn encode_u128(out: &mut Vec<u8>, v: u128) {
    encode_uint_be(out, &v.to_be_bytes());
}

pub fn encode_u64(out: &mut Vec<u8>, v: u64) {
    encode_uint_be(out, &v.to_be_bytes());
}

fn encode_len(out: &mut Vec<u8>, len: usize, offset: u8) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&x| x != 0).unwrap();
        let len_bytes = &be[start..];
        out.push(offset + 55 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_bytes_and_zero() {
        let mut o = Vec::new();
        encode_u64(&mut o, 0);
        assert_eq!(o, vec![0x80]); // zero -> empty string
        o.clear();
        encode_u64(&mut o, 15);
        assert_eq!(o, vec![0x0f]); // low single byte is itself
        o.clear();
        encode_u64(&mut o, 1024);
        assert_eq!(o, vec![0x82, 0x04, 0x00]); // 0x0400
    }

    #[test]
    fn short_and_long_strings() {
        let mut o = Vec::new();
        encode_bytes(&mut o, b"dog");
        assert_eq!(o, vec![0x83, b'd', b'o', b'g']);
        // 56-byte string crosses into the long-form length prefix
        o.clear();
        let big = vec![0xaau8; 56];
        encode_bytes(&mut o, &big);
        assert_eq!(o[0], 0xb8);
        assert_eq!(o[1], 56);
        assert_eq!(o.len(), 58);
    }

    #[test]
    fn empty_list() {
        let mut o = Vec::new();
        encode_list(&mut o, &[]);
        assert_eq!(o, vec![0xc0]);
    }
}

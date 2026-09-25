//! Entropy calculation utilities for heuristic analysis.
//!
//! Shannon entropy measures the randomness (information density) of data.
//! Packed, encrypted, or compressed sections typically exhibit entropy above 7.0,
//! which is a strong indicator of obfuscation or encryption.

/// Compute the Shannon entropy of a byte slice.
///
/// Returns a value in `[0.0, 8.0]`:
/// - 0.0 means every byte is identical (zero information).
/// - 8.0 means the data is maximally random (each byte value equally likely).
///
/// An empty slice returns 0.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        // SAFETY: `byte` is `u8` so `byte as usize` is always in 0..=255,
        // which is within bounds of the 256-element array.
        #[allow(clippy::indexing_slicing)]
        {
            freq[byte as usize] += 1;
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Compute Shannon entropy for each non-overlapping block of `block_size` bytes.
///
/// The last block may be smaller than `block_size` if `data.len()` is not evenly
/// divisible. Each entry in the returned vector corresponds to one block.
///
/// # Panics
///
/// Panics if `block_size` is zero.
pub fn block_entropy(data: &[u8], block_size: usize) -> Vec<f64> {
    assert!(block_size > 0, "block_size must be greater than zero");

    if data.is_empty() {
        return Vec::new();
    }

    data.chunks(block_size).map(shannon_entropy).collect()
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_data_has_zero_entropy() {
        let data = vec![0xAA; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn two_equally_likely_bytes() {
        // 50/50 split of two distinct byte values → entropy = 1.0
        let mut data = vec![0u8; 1000];
        for item in data.iter_mut().take(500) {
            *item = 0xFF;
        }
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
    }

    #[test]
    fn high_entropy_random_like() {
        // All 256 byte values equally represented → entropy ≈ 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.99, "expected ~8.0, got {e}");
    }

    #[test]
    fn block_entropy_splits_correctly() {
        let data = vec![0u8; 100];
        let blocks = block_entropy(&data, 30);
        // 100 / 30 = 3 full blocks + 1 partial (10 bytes)
        assert_eq!(blocks.len(), 4);
        for &e in &blocks {
            assert_eq!(e, 0.0);
        }
    }

    #[test]
    fn block_entropy_empty() {
        assert!(block_entropy(&[], 16).is_empty());
    }

    #[test]
    #[should_panic(expected = "block_size must be greater than zero")]
    fn block_entropy_zero_block_size_panics() {
        block_entropy(&[1, 2, 3], 0);
    }

    #[test]
    fn block_entropy_exact_division() {
        let data = vec![0u8; 64];
        let blocks = block_entropy(&data, 32);
        assert_eq!(blocks.len(), 2);
    }
}

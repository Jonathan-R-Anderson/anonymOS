//! Parser for `ClamAV` `.ndb` hex signature files.
//!
//! NDB signatures define body-based (hex pattern) detection rules. Each line
//! has the format:
//!
//! ```text
//! MalwareName:TargetType:Offset:HexSignature
//! ```
//!
//! - **`TargetType`**: 0 = any, 1 = PE, 2 = OLE2, etc.
//! - **Offset**: `*` (any), absolute number, `EP+n`/`EP-n`, `EOF-n`, `SE<section>`.
//! - **`HexSignature`**: hex-encoded byte pattern.

use anyhow::{Context, Result, bail};

/// A parsed NDB hex signature.
#[derive(Debug, Clone)]
pub struct NdbSignature {
    /// Malware family/variant name.
    pub name: String,
    /// Target file type (0 = any, 1 = PE, 2 = OLE2, etc.).
    pub target_type: u32,
    /// Where in the file to search for the pattern.
    pub offset: NdbOffset,
    /// The raw hex pattern string (may contain wildcards like `??`).
    pub hex_pattern: String,
}

/// Offset specification for an NDB signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdbOffset {
    /// Match anywhere in the file (`*`).
    Any,
    /// Match at an absolute file offset.
    Absolute(u64),
    /// Match relative to the entry point (`EP+n` or `EP-n`).
    EntryPoint(i64),
    /// Match relative to the end of file (`EOF-n`).
    EndOfFile(i64),
    /// Match at the start of a given PE section number.
    SectionStart(u32),
}

/// Parse the content of an `.ndb` file into a list of signatures.
///
/// Blank lines and lines starting with `#` (comments) are skipped.
pub fn parse_ndb(content: &str) -> Result<Vec<NdbSignature>> {
    let mut signatures = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 4 {
            bail!(
                "NDB line {}: expected 4 colon-separated fields, got {}",
                line_num + 1,
                parts.len()
            );
        }

        let name = parts.first().context("NDB: missing name field")?.to_string();

        let target_str = *parts.get(1).context("NDB: missing target type field")?;
        let target_type = target_str
            .parse::<u32>()
            .with_context(|| format!("NDB line {}: invalid target type '{target_str}'", line_num + 1,))?;

        let offset_str = *parts.get(2).context("NDB: missing offset field")?;
        let offset = parse_offset(offset_str)
            .with_context(|| format!("NDB line {}: invalid offset '{offset_str}'", line_num + 1))?;

        let hex_pattern = parts.get(3).context("NDB: missing hex pattern field")?.to_string();

        signatures.push(NdbSignature {
            name,
            target_type,
            offset,
            hex_pattern,
        });
    }

    Ok(signatures)
}

/// Parse an NDB offset specification string.
fn parse_offset(s: &str) -> Result<NdbOffset> {
    let s = s.trim();

    if s == "*" {
        return Ok(NdbOffset::Any);
    }

    // Entry point relative: EP+N or EP-N
    if let Some(rest) = s.strip_prefix("EP") {
        if let Some(num_str) = rest.strip_prefix('+') {
            let n = num_str.parse::<i64>().context("invalid EP+ offset")?;
            return Ok(NdbOffset::EntryPoint(n));
        }
        if let Some(num_str) = rest.strip_prefix('-') {
            let n = num_str.parse::<i64>().context("invalid EP- offset")?;
            return Ok(NdbOffset::EntryPoint(-n));
        }
        // EP with no +/- means EP+0
        if rest.is_empty() {
            return Ok(NdbOffset::EntryPoint(0));
        }
        bail!("invalid EP offset: '{s}'");
    }

    // End of file relative: EOF-N
    if let Some(rest) = s.strip_prefix("EOF-") {
        let n = rest.parse::<i64>().context("invalid EOF- offset")?;
        return Ok(NdbOffset::EndOfFile(-n));
    }

    // Section start: SE<N> or SectionStart<N>
    if let Some(rest) = s.strip_prefix("SE") {
        let n = rest.parse::<u32>().context("invalid SE section number")?;
        return Ok(NdbOffset::SectionStart(n));
    }

    // Absolute offset (plain number)
    let n = s.parse::<u64>().with_context(|| format!("invalid offset: '{s}'"))?;
    Ok(NdbOffset::Absolute(n))
}

/// Convert a hex pattern string to raw bytes.
///
/// The hex string must have an even number of characters. Wildcard nibbles
/// (`?`) are not supported in this conversion and will cause an error; use
/// this function only for fully specified patterns.
pub fn parse_hex_pattern(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();

    if !hex.len().is_multiple_of(2) {
        bail!("hex pattern has odd length: {}", hex.len());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in (0..hex.len()).step_by(2) {
        let pair = hex.get(i..i + 2).context("hex pattern slice out of bounds")?;
        if pair == "??" {
            // Wildcard byte - represent as 0x00 placeholder.
            // Callers performing matching should handle wildcards separately.
            bytes.push(0x00);
            continue;
        }
        let byte =
            u8::from_str_radix(pair, 16).with_context(|| format!("invalid hex byte at position {i}: '{pair}'"))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ndb_basic() {
        let content = "\
Win.Trojan.Test-1:1:*:4d5a90000300
Win.Trojan.Test-2:0:EP+0:cafebabe
";
        let sigs = parse_ndb(content).unwrap();
        assert_eq!(sigs.len(), 2);

        assert_eq!(sigs[0].name, "Win.Trojan.Test-1");
        assert_eq!(sigs[0].target_type, 1);
        assert_eq!(sigs[0].offset, NdbOffset::Any);
        assert_eq!(sigs[0].hex_pattern, "4d5a90000300");

        assert_eq!(sigs[1].name, "Win.Trojan.Test-2");
        assert_eq!(sigs[1].target_type, 0);
        assert_eq!(sigs[1].offset, NdbOffset::EntryPoint(0));
    }

    #[test]
    fn test_parse_offsets() {
        assert_eq!(parse_offset("*").unwrap(), NdbOffset::Any);
        assert_eq!(parse_offset("1024").unwrap(), NdbOffset::Absolute(1024));
        assert_eq!(parse_offset("EP+100").unwrap(), NdbOffset::EntryPoint(100));
        assert_eq!(parse_offset("EP-50").unwrap(), NdbOffset::EntryPoint(-50));
        assert_eq!(parse_offset("EP").unwrap(), NdbOffset::EntryPoint(0));
        assert_eq!(parse_offset("EOF-512").unwrap(), NdbOffset::EndOfFile(-512));
        assert_eq!(parse_offset("SE0").unwrap(), NdbOffset::SectionStart(0));
        assert_eq!(parse_offset("SE3").unwrap(), NdbOffset::SectionStart(3));
    }

    #[test]
    fn test_skip_comments_and_blanks() {
        let content = "\
# This is a comment

Win.Test-1:0:*:aabb

# Another comment
Win.Test-2:1:100:ccdd
";
        let sigs = parse_ndb(content).unwrap();
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_parse_hex_pattern() {
        let bytes = parse_hex_pattern("4d5a9000").unwrap();
        assert_eq!(bytes, vec![0x4d, 0x5a, 0x90, 0x00]);
    }

    #[test]
    fn test_parse_hex_pattern_with_wildcards() {
        let bytes = parse_hex_pattern("4d??9000").unwrap();
        assert_eq!(bytes, vec![0x4d, 0x00, 0x90, 0x00]);
    }

    #[test]
    fn test_parse_hex_pattern_odd_length() {
        assert!(parse_hex_pattern("4d5").is_err());
    }

    #[test]
    fn test_parse_hex_pattern_invalid_chars() {
        assert!(parse_hex_pattern("zzzz").is_err());
    }

    #[test]
    fn test_too_few_fields() {
        let content = "MalwareName:1:*\n";
        assert!(parse_ndb(content).is_err());
    }
}

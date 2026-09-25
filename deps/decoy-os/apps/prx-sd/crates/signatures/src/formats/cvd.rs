//! Parser for `ClamAV` `.cvd` (`ClamAV` Virus Database) files.
//!
//! A CVD file has a 512-byte ASCII header followed by a tar.gz archive
//! containing the actual signature data. The header fields are colon-separated:
//!
//! ```text
//! ClamAV-VDB:build_time:version:num_sigs:func_level:md5:builder:stime:...
//! ```

use anyhow::{Context, Result, bail};

/// The fixed size of a CVD file header in bytes.
const CVD_HEADER_SIZE: usize = 512;

/// Parsed CVD file header.
#[derive(Debug, Clone)]
pub struct CvdHeader {
    /// Database name (e.g., "`ClamAV`-VDB").
    pub name: String,
    /// Build time as a human-readable string.
    pub build_time: String,
    /// Database version number.
    pub version: u32,
    /// Total number of signatures in this database.
    pub num_signatures: u32,
    /// MD5 checksum of the tar.gz payload.
    pub md5: String,
}

/// A parsed CVD file: header plus the raw signature data (tar.gz payload).
#[derive(Debug)]
pub struct CvdFile {
    /// The parsed header.
    pub header: CvdHeader,
    /// The raw tar.gz payload bytes following the 512-byte header.
    pub data: Vec<u8>,
}

/// Parse a `ClamAV` `.cvd` file from raw bytes.
///
/// The first 512 bytes are a colon-separated ASCII header. Everything after
/// that is a tar.gz archive containing the signature files.
pub fn parse_cvd(data: &[u8]) -> Result<CvdFile> {
    if data.len() < CVD_HEADER_SIZE {
        bail!(
            "CVD data too short: {} bytes (expected at least {CVD_HEADER_SIZE})",
            data.len(),
        );
    }

    // Safe: length checked above ensures data has at least CVD_HEADER_SIZE bytes.
    let header_bytes = data.get(..CVD_HEADER_SIZE).context("CVD header slice out of bounds")?;
    let header_str = std::str::from_utf8(header_bytes)
        .context("CVD header is not valid UTF-8")?
        .trim_end_matches('\0')
        .trim();

    let fields: Vec<&str> = header_str.split(':').collect();

    // Minimum fields: name, build_time, version, num_sigs, func_level, md5
    if fields.len() < 6 {
        bail!(
            "CVD header has too few fields: got {}, expected at least 6",
            fields.len()
        );
    }

    // Safe: we verified fields.len() >= 6 above.
    let name = fields.first().context("missing CVD name field")?.to_string();
    let build_time = fields.get(1).context("missing CVD build_time field")?.to_string();

    let version_str = fields.get(2).context("missing CVD version field")?;
    let version = version_str
        .parse::<u32>()
        .with_context(|| format!("invalid CVD version field: '{version_str}'"))?;

    let sigs_str = fields.get(3).context("missing CVD num_signatures field")?;
    let num_signatures = sigs_str
        .parse::<u32>()
        .with_context(|| format!("invalid CVD num_signatures field: '{sigs_str}'"))?;

    // fields[4] is func_level, which we skip.
    let md5 = fields.get(5).context("missing CVD md5 field")?.to_string();

    let header = CvdHeader {
        name,
        build_time,
        version,
        num_signatures,
        md5,
    };

    let payload = data
        .get(CVD_HEADER_SIZE..)
        .context("CVD payload slice out of bounds")?
        .to_vec();

    Ok(CvdFile { header, data: payload })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unreadable_literal)]
mod tests {
    use super::*;

    fn make_cvd_header(fields: &str) -> Vec<u8> {
        let mut header = vec![0u8; CVD_HEADER_SIZE];
        let bytes = fields.as_bytes();
        header[..bytes.len()].copy_from_slice(bytes);
        header
    }

    #[test]
    fn test_parse_valid_cvd() {
        let header_str = "ClamAV-VDB:09 Mar 2024:27200:4500000:90:abc123def456:builder:1709942400";
        let mut data = make_cvd_header(header_str);
        // Append some fake payload.
        data.extend_from_slice(b"fake tar.gz payload data");

        let cvd = parse_cvd(&data).unwrap();
        assert_eq!(cvd.header.name, "ClamAV-VDB");
        assert_eq!(cvd.header.build_time, "09 Mar 2024");
        assert_eq!(cvd.header.version, 27200);
        assert_eq!(cvd.header.num_signatures, 4500000);
        assert_eq!(cvd.header.md5, "abc123def456");
        assert_eq!(cvd.data, b"fake tar.gz payload data");
    }

    #[test]
    fn test_parse_too_short() {
        let data = b"too short";
        assert!(parse_cvd(data).is_err());
    }

    #[test]
    fn test_parse_too_few_fields() {
        let header_str = "ClamAV-VDB:timestamp:123";
        let data = make_cvd_header(header_str);
        assert!(parse_cvd(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_version() {
        let header_str = "ClamAV-VDB:ts:notanumber:100:90:md5hash";
        let data = make_cvd_header(header_str);
        assert!(parse_cvd(&data).is_err());
    }

    #[test]
    fn test_parse_no_payload() {
        let header_str = "ClamAV-VDB:ts:100:5000:90:md5val:builder:12345";
        let data = make_cvd_header(header_str);
        let cvd = parse_cvd(&data).unwrap();
        assert!(cvd.data.is_empty());
    }
}

use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Supported archive formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Zip,
    Gzip,
    Tar,
    TarGz,
    SevenZip,
}

/// High-level information about an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub format: ArchiveFormat,
    pub entries: Vec<ArchiveEntry>,
    pub total_uncompressed_size: u64,
}

/// A single entry within an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub size: u64,
    pub is_encrypted: bool,
}

/// Maximum total bytes we will buffer during recursive extraction to prevent
/// zip-bomb style resource exhaustion.
const MAX_EXTRACTION_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Inspect an archive and return metadata about its entries without fully
/// extracting the contents.
pub fn inspect_archive(data: &[u8], format: ArchiveFormat) -> Result<ArchiveInfo> {
    match format {
        ArchiveFormat::Zip => inspect_zip(data),
        ArchiveFormat::Tar => inspect_tar(data),
        ArchiveFormat::TarGz => inspect_targz(data),
        ArchiveFormat::Gzip => inspect_gzip(data),
        ArchiveFormat::SevenZip => inspect_7z(data),
    }
}

/// Recursively extract files from an archive up to `max_depth` levels of
/// nesting. Returns a list of `(path, contents)` pairs.
pub fn extract_archive(data: &[u8], format: ArchiveFormat, max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    if max_depth == 0 {
        debug!("max recursion depth reached, skipping nested extraction");
        return Ok(Vec::new());
    }

    match format {
        ArchiveFormat::Zip => extract_zip(data, max_depth),
        ArchiveFormat::Tar => extract_tar(data, max_depth),
        ArchiveFormat::TarGz => extract_targz(data, max_depth),
        ArchiveFormat::Gzip => extract_gzip(data, max_depth),
        ArchiveFormat::SevenZip => {
            bail!("7z extraction is not yet implemented")
        }
    }
}

/// Detect the archive format of `data` by inspecting magic bytes.
pub fn detect_archive_format(data: &[u8]) -> Option<ArchiveFormat> {
    if data.len() < 4 {
        return None;
    }
    // ZIP: PK\x03\x04
    if data.starts_with(b"PK\x03\x04") {
        return Some(ArchiveFormat::Zip);
    }
    // Gzip: \x1f\x8b
    if data.starts_with(&[0x1f, 0x8b]) {
        // Could be standalone gzip or tar.gz. We optimistically call it TarGz
        // and let the caller fall back to Gzip if tar parsing fails.
        return Some(ArchiveFormat::TarGz);
    }
    // Tar: "ustar" at offset 257
    if data.get(257..262).is_some_and(|slice| slice == b"ustar") {
        return Some(ArchiveFormat::Tar);
    }
    // 7z: 7z\xBC\xAF\x27\x1C
    if data.get(..6).is_some_and(|slice| slice == b"7z\xBC\xAF\x27\x1C") {
        return Some(ArchiveFormat::SevenZip);
    }
    None
}

// ── ZIP ──────────────────────────────────────────────────────────────

fn inspect_zip(data: &[u8]) -> Result<ArchiveInfo> {
    let reader = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).context("failed to open zip archive")?;
    let mut entries = Vec::with_capacity(archive.len());
    let mut total_uncompressed_size: u64 = 0;

    for i in 0..archive.len() {
        let file = archive.by_index_raw(i).context("failed to read zip entry")?;
        let is_encrypted = file.encrypted();
        let size = file.size();
        total_uncompressed_size = total_uncompressed_size.saturating_add(size);
        entries.push(ArchiveEntry {
            path: file.name().to_string(),
            size,
            is_encrypted,
        });
    }

    Ok(ArchiveInfo {
        format: ArchiveFormat::Zip,
        entries,
        total_uncompressed_size,
    })
}

fn extract_zip(data: &[u8], max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    let reader = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).context("failed to open zip archive")?;
    let mut results = Vec::new();
    let mut total_bytes: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("failed to read zip entry")?;

        if file.is_dir() {
            continue;
        }
        if file.encrypted() {
            warn!(name = file.name(), "skipping encrypted zip entry");
            continue;
        }

        let name = file.name().to_string();
        let size = file.size();

        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_EXTRACTION_BYTES {
            warn!("extraction size limit reached, stopping");
            break;
        }

        #[allow(clippy::cast_possible_truncation)]
        let mut buf = Vec::with_capacity(size as usize);
        file.read_to_end(&mut buf)
            .with_context(|| format!("failed to decompress zip entry: {name}"))?;

        // Attempt recursive extraction of nested archives
        if let Some(nested_fmt) = detect_archive_format(&buf) {
            debug!(%name, ?nested_fmt, "recursively extracting nested archive");
            match extract_archive(&buf, nested_fmt, max_depth - 1) {
                Ok(nested) => {
                    for (nested_path, nested_data) in nested {
                        results.push((format!("{name}/{nested_path}"), nested_data));
                    }
                    continue;
                }
                Err(e) => {
                    debug!(%name, %e, "nested extraction failed, treating as plain file");
                }
            }
        }

        results.push((name, buf));
    }

    Ok(results)
}

// ── TAR ──────────────────────────────────────────────────────────────

fn inspect_tar(data: &[u8]) -> Result<ArchiveInfo> {
    let reader = Cursor::new(data);
    let mut archive = tar::Archive::new(reader);
    let mut entries = Vec::new();
    let mut total_uncompressed_size: u64 = 0;

    for entry in archive.entries().context("failed to read tar entries")? {
        let entry = entry.context("failed to read tar entry")?;
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = entry.size();
        total_uncompressed_size = total_uncompressed_size.saturating_add(size);
        entries.push(ArchiveEntry {
            path,
            size,
            is_encrypted: false,
        });
    }

    Ok(ArchiveInfo {
        format: ArchiveFormat::Tar,
        entries,
        total_uncompressed_size,
    })
}

fn extract_tar(data: &[u8], max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    extract_tar_from_reader(Cursor::new(data), max_depth)
}

fn extract_tar_from_reader<R: Read>(reader: R, max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = tar::Archive::new(reader);
    let mut results = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("failed to read tar entry")?;
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if entry.header().entry_type().is_dir() {
            continue;
        }

        let size = entry.size();
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_EXTRACTION_BYTES {
            warn!("extraction size limit reached, stopping");
            break;
        }

        #[allow(clippy::cast_possible_truncation)]
        let mut buf = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("failed to read tar entry: {path}"))?;

        if let Some(nested_fmt) = detect_archive_format(&buf) {
            debug!(%path, ?nested_fmt, "recursively extracting nested archive");
            match extract_archive(&buf, nested_fmt, max_depth - 1) {
                Ok(nested) => {
                    for (nested_path, nested_data) in nested {
                        results.push((format!("{path}/{nested_path}"), nested_data));
                    }
                    continue;
                }
                Err(e) => {
                    debug!(%path, %e, "nested extraction failed, treating as plain file");
                }
            }
        }

        results.push((path, buf));
    }

    Ok(results)
}

// ── TAR.GZ ───────────────────────────────────────────────────────────

fn inspect_targz(data: &[u8]) -> Result<ArchiveInfo> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(data));
    let mut archive = tar::Archive::new(gz);
    let mut entries = Vec::new();
    let mut total_uncompressed_size: u64 = 0;

    for entry in archive.entries().context("failed to read tar.gz entries")? {
        let entry = entry.context("failed to read tar.gz entry")?;
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = entry.size();
        total_uncompressed_size = total_uncompressed_size.saturating_add(size);
        entries.push(ArchiveEntry {
            path,
            size,
            is_encrypted: false,
        });
    }

    Ok(ArchiveInfo {
        format: ArchiveFormat::TarGz,
        entries,
        total_uncompressed_size,
    })
}

fn extract_targz(data: &[u8], max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(data));
    extract_tar_from_reader(gz, max_depth)
}

// ── GZIP (standalone, not tar) ───────────────────────────────────────

fn inspect_gzip(data: &[u8]) -> Result<ArchiveInfo> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(data));
    let mut limited = gz.take(MAX_EXTRACTION_BYTES);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .context("failed to decompress gzip")?;

    Ok(ArchiveInfo {
        format: ArchiveFormat::Gzip,
        entries: vec![ArchiveEntry {
            path: String::from("decompressed"),
            size: decompressed.len() as u64,
            is_encrypted: false,
        }],
        total_uncompressed_size: decompressed.len() as u64,
    })
}

fn extract_gzip(data: &[u8], max_depth: u32) -> Result<Vec<(String, Vec<u8>)>> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(data));
    let mut limited = gz.take(MAX_EXTRACTION_BYTES);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .context("failed to decompress gzip")?;

    // Check if the decompressed content is itself an archive
    if let Some(nested_fmt) = detect_archive_format(&decompressed) {
        debug!(?nested_fmt, "gzip content is a nested archive");
        match extract_archive(&decompressed, nested_fmt, max_depth - 1) {
            Ok(nested) => return Ok(nested),
            Err(e) => {
                debug!(%e, "nested extraction of gzip content failed");
            }
        }
    }

    Ok(vec![("decompressed".to_string(), decompressed)])
}

// ── 7Z (stub) ────────────────────────────────────────────────────────

fn inspect_7z(data: &[u8]) -> Result<ArchiveInfo> {
    // We cannot parse 7z without a dedicated crate. Return minimal info.
    warn!("7z inspection is a stub; only magic-byte validation is performed");

    if data.get(..6).is_none_or(|slice| slice != b"7z\xBC\xAF\x27\x1C") {
        bail!("data does not have a valid 7z signature");
    }

    Ok(ArchiveInfo {
        format: ArchiveFormat::SevenZip,
        entries: Vec::new(),
        total_uncompressed_size: 0,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a minimal valid ZIP file containing one file entry.
    fn make_minimal_zip() -> Vec<u8> {
        use std::io::Write;
        let buf = Vec::new();
        let cursor = Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file("hello.txt", options).expect("start file");
        writer.write_all(b"Hello, world!").expect("write data");
        let cursor = writer.finish().expect("finish zip");
        cursor.into_inner()
    }

    /// Build a minimal gzip-compressed payload.
    fn make_minimal_gzip(content: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).expect("write gzip");
        encoder.finish().expect("finish gzip")
    }

    // ── detect_archive_format tests ──

    #[test]
    fn detect_zip_magic() {
        let data = make_minimal_zip();
        let fmt = detect_archive_format(&data);
        assert_eq!(fmt, Some(ArchiveFormat::Zip));
    }

    #[test]
    fn detect_gzip_magic() {
        let data = make_minimal_gzip(b"test data");
        let fmt = detect_archive_format(&data);
        // Gzip is detected as TarGz (optimistic, per code comment)
        assert_eq!(fmt, Some(ArchiveFormat::TarGz));
    }

    #[test]
    fn detect_tar_magic() {
        let mut data = vec![0u8; 512];
        // "ustar" at offset 257
        data[257..262].copy_from_slice(b"ustar");
        let fmt = detect_archive_format(&data);
        assert_eq!(fmt, Some(ArchiveFormat::Tar));
    }

    #[test]
    fn detect_7z_magic() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        let fmt = detect_archive_format(&data);
        assert_eq!(fmt, Some(ArchiveFormat::SevenZip));
    }

    #[test]
    fn detect_unknown_format() {
        let data = b"This is just random text, not an archive.";
        let fmt = detect_archive_format(data);
        assert_eq!(fmt, None);
    }

    #[test]
    fn detect_empty_input() {
        let fmt = detect_archive_format(&[]);
        assert_eq!(fmt, None);
    }

    #[test]
    fn detect_too_short() {
        let fmt = detect_archive_format(&[0x50, 0x4B]); // PK but only 2 bytes
        assert_eq!(fmt, None);
    }

    // ── inspect_archive tests ──

    #[test]
    fn inspect_zip_entries() {
        let data = make_minimal_zip();
        let info = inspect_archive(&data, ArchiveFormat::Zip).expect("should inspect zip");
        assert_eq!(info.format, ArchiveFormat::Zip);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].path, "hello.txt");
        assert_eq!(info.entries[0].size, 13); // "Hello, world!" = 13 bytes
        assert!(!info.entries[0].is_encrypted);
        assert_eq!(info.total_uncompressed_size, 13);
    }

    #[test]
    fn inspect_gzip_standalone() {
        let content = b"Some decompressed content here.";
        let data = make_minimal_gzip(content);
        let info = inspect_archive(&data, ArchiveFormat::Gzip).expect("should inspect gzip");
        assert_eq!(info.format, ArchiveFormat::Gzip);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].path, "decompressed");
        assert_eq!(info.total_uncompressed_size, content.len() as u64);
    }

    #[test]
    fn inspect_7z_valid_signature() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        let info = inspect_archive(&data, ArchiveFormat::SevenZip).expect("should inspect 7z stub");
        assert_eq!(info.format, ArchiveFormat::SevenZip);
        assert!(info.entries.is_empty());
    }

    #[test]
    fn inspect_7z_invalid_signature() {
        let data = b"not a 7z file at all";
        let result = inspect_archive(data, ArchiveFormat::SevenZip);
        assert!(result.is_err(), "invalid 7z signature should error");
    }

    // ── extract_archive tests ──

    #[test]
    fn extract_zip_contents() {
        let data = make_minimal_zip();
        let files = extract_archive(&data, ArchiveFormat::Zip, 3).expect("should extract zip");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "hello.txt");
        assert_eq!(files[0].1, b"Hello, world!");
    }

    #[test]
    fn extract_gzip_contents() {
        let content = b"gzip payload";
        let data = make_minimal_gzip(content);
        let files = extract_archive(&data, ArchiveFormat::Gzip, 3).expect("should extract gzip");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1, content);
    }

    #[test]
    fn extract_at_zero_depth_returns_empty() {
        let data = make_minimal_zip();
        let files = extract_archive(&data, ArchiveFormat::Zip, 0).expect("should return empty at depth 0");
        assert!(files.is_empty());
    }

    #[test]
    fn extract_7z_returns_error() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        let result = extract_archive(&data, ArchiveFormat::SevenZip, 3);
        assert!(result.is_err(), "7z extraction should fail (not implemented)");
    }

    #[test]
    fn inspect_zip_invalid_data() {
        let data = b"PK\x03\x04garbage that is not actually a zip";
        let result = inspect_archive(data, ArchiveFormat::Zip);
        assert!(result.is_err(), "invalid zip data should return error");
    }
}

//! Criterion benchmarks for the prx-sd-core scanning pipeline.
//!
//! Benchmarks cover hash lookups, in-memory scanning at various payload sizes,
//! Shannon entropy computation, and magic-byte file-type detection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal,
    clippy::redundant_closure_for_method_calls,
    clippy::format_collect,
    clippy::int_plus_one,
    clippy::needless_collect,
    clippy::if_not_else,
    clippy::redundant_clone,
    clippy::uninlined_format_args,
    clippy::similar_names,
    clippy::used_underscore_binding,
    clippy::unnecessary_wraps,
    clippy::bool_assert_comparison,
    clippy::vec_init_then_push,
    clippy::print_stderr,
    clippy::write_with_newline,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::manual_let_else,
    clippy::return_self_not_must_use,
    clippy::must_use_candidate,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use prx_sd_core::{ScanConfig, ScanEngine, detect_magic};
use prx_sd_heuristic::entropy::shannon_entropy;
use prx_sd_signatures::SignatureDatabase;

/// Build a `ScanEngine` backed by a temp directory with `n_hashes` random
/// SHA-256 entries pre-loaded.
fn engine_with_hashes(tmp: &tempfile::TempDir, n_hashes: usize) -> ScanEngine {
    let sigs_dir = tmp.path().join("sigs");
    let yara_dir = tmp.path().join("yara");
    let qdir = tmp.path().join("quarantine");

    std::fs::create_dir_all(&sigs_dir).unwrap();
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::create_dir_all(&qdir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).unwrap();

    // Generate `n_hashes` unique entries.
    let entries: Vec<(Vec<u8>, String)> = (0..n_hashes)
        .map(|i| {
            let fake_data = format!("__malware_sample_{i:08}__");
            let hash = prx_sd_signatures::hash::sha256_hash(fake_data.as_bytes());
            (hash, format!("Bench.Malware.{i}"))
        })
        .collect();

    db.import_hashes(&entries).unwrap();

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&qdir)
        .with_scan_threads(1);

    ScanEngine::new(config).unwrap()
}

// ---------------------------------------------------------------------------
// Benchmark: hash lookup with a populated database (worst case - no match)
// ---------------------------------------------------------------------------

fn bench_hash_lookup(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let engine = engine_with_hashes(&tmp, 1_000);

    // Data that will NOT match any imported hash -- forces a full lookup.
    let miss_data = b"this data does not match any known signature";

    c.bench_function("hash_lookup_miss_1k_db", |b| {
        b.iter(|| {
            let _ = engine.signatures.hash_lookup(miss_data);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: scan_bytes at various payload sizes
// ---------------------------------------------------------------------------

fn bench_scan_bytes(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let engine = engine_with_hashes(&tmp, 100);

    let sizes: &[(usize, &str)] = &[(1_024, "1KB"), (10_240, "10KB"), (102_400, "100KB"), (1_048_576, "1MB")];

    let mut group = c.benchmark_group("scan_bytes");

    for &(size, label) in sizes {
        // Fill with non-random, non-zero data to avoid triggering high-entropy
        // heuristics.  Repeat a simple pattern.
        let data: Vec<u8> = (0..size).map(|i| (i % 97) as u8 + 0x20).collect();

        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| {
                let _ = engine.scan_bytes(data, "bench-source");
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: Shannon entropy on 1 MB of pseudo-random data
// ---------------------------------------------------------------------------

fn bench_entropy(c: &mut Criterion) {
    // Build data with all 256 byte values roughly equally represented.
    let mut data = Vec::with_capacity(1_048_576);
    for i in 0..1_048_576u32 {
        data.push((i % 256) as u8);
    }

    c.bench_function("shannon_entropy_1MB", |b| {
        b.iter(|| {
            let _ = shannon_entropy(&data);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: magic-byte file-type detection
// ---------------------------------------------------------------------------

fn bench_magic_detection(c: &mut Criterion) {
    let headers: &[(&str, &[u8])] = &[
        ("PE", b"MZ\x90\x00\x03\x00\x00\x00"),
        ("ELF", b"\x7fELF\x02\x01\x01\x00"),
        ("PDF", b"%PDF-1.7 trailer"),
        ("ZIP", b"PK\x03\x04\x14\x00\x00\x00"),
        ("gzip", &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]),
        ("Unknown", &[0x00, 0x00, 0x00, 0x00, 0x00]),
    ];

    let mut group = c.benchmark_group("detect_magic");

    for &(label, header) in headers {
        group.bench_with_input(BenchmarkId::from_parameter(label), header, |b, data| {
            b.iter(|| {
                let _ = detect_magic(data);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_lookup,
    bench_scan_bytes,
    bench_entropy,
    bench_magic_detection,
);
criterion_main!(benches);

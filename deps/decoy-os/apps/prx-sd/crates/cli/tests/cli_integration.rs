//! Integration tests for the `sd` CLI binary.
//!
//! These tests spawn the actual binary and verify command-line behavior.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;

/// Helper: create a temp data directory with the minimal structure
/// the engine requires (signatures LMDB + empty yara dir).
fn setup_data_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let sig_dir = dir.path().join("signatures");
    let yara_dir = dir.path().join("yara");
    let quarantine_dir = dir.path().join("quarantine");
    fs::create_dir_all(&sig_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Open the LMDB env so the directories are properly initialised.
    let _db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).unwrap();

    // Write a trivial YARA rule so the yara dir is non-empty and
    // first_run_setup is skipped.
    fs::write(yara_dir.join("stub.yar"), r"rule Stub { condition: false }").unwrap();

    // Write a minimal config.json so first-run setup is skipped.
    let config = serde_json::json!({});
    fs::write(
        dir.path().join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();

    dir
}

fn sd_cmd() -> Command {
    Command::cargo_bin("sd").unwrap()
}

/// Compute the SHA-256 hex digest of the given data.
fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let hash = Sha256::digest(data);
    hash.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn scan_clean_file_exits_success() {
    let data_dir = setup_data_dir();
    let file = data_dir.path().join("clean.txt");
    fs::write(&file, "This is a clean file.").unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Clean"));
}

#[test]
fn scan_nonexistent_file_fails() {
    let data_dir = setup_data_dir();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "/tmp/__sd_test_nonexistent_file_xyz__",
        ])
        .assert()
        .failure();
}

#[test]
fn scan_directory_exits_success() {
    let data_dir = setup_data_dir();
    let scan_dir = data_dir.path().join("target_dir");
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("a.txt"), "alpha").unwrap();
    fs::write(scan_dir.join("b.txt"), "bravo").unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            scan_dir.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn scan_json_output_is_valid_json() {
    let data_dir = setup_data_dir();
    let file = data_dir.path().join("test.txt");
    fs::write(&file, "test content").unwrap();

    let output = sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "--json",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["threat_level"], "Clean");
}

#[test]
fn info_command_exits_success() {
    let data_dir = setup_data_dir();

    sd_cmd()
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "info"])
        .assert()
        .success();
}

#[test]
fn import_valid_blocklist() {
    let data_dir = setup_data_dir();

    // Create a blocklist file with one valid entry.
    let blocklist = data_dir.path().join("blocklist.txt");
    // SHA-256 of "malware_test" (64 hex chars).
    let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    fs::write(&blocklist, format!("{hash_hex} Test.Malware.Import\n")).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import",
            blocklist.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported"));
}

#[test]
fn import_nonexistent_file_fails() {
    let data_dir = setup_data_dir();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import",
            "/tmp/__sd_test_no_such_blocklist__",
        ])
        .assert()
        .failure();
}

#[test]
fn quarantine_list_exits_success() {
    let data_dir = setup_data_dir();

    sd_cmd()
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "quarantine", "list"])
        .assert()
        .success();
}

// ──────────────────────────────────────────────────────────────────────
// End-to-end business flow tests
// ──────────────────────────────────────────────────────────────────────

/// 1. Import a hash, create a file with that content, scan it, verify MALICIOUS.
#[test]
fn scan_detects_malicious_file_by_hash() {
    let data_dir = setup_data_dir();

    // Compute a SHA-256 of known content and import it as malicious.
    let malware_content = b"this_is_definitely_malware_content_unique_12345";
    let hash = sha256_hex(malware_content);
    let blocklist = data_dir.path().join("mal.txt");
    fs::write(&blocklist, format!("{hash} Test.Trojan.E2E\n")).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import",
            blocklist.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported"));

    // Write the "malware" file and scan it.
    let malfile = data_dir.path().join("malware.bin");
    fs::write(&malfile, malware_content).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            malfile.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("MALICIOUS"))
        .stdout(predicate::str::contains("Test.Trojan.E2E"));
}

/// 2. Import hash, create malware, scan with --auto-quarantine, verify quarantine list.
#[test]
fn scan_with_auto_quarantine() {
    let data_dir = setup_data_dir();

    let malware_content = b"auto_quarantine_test_payload_e2e_unique";
    let hash = sha256_hex(malware_content);
    let blocklist = data_dir.path().join("aq_mal.txt");
    fs::write(&blocklist, format!("{hash} Test.Quarantine.AQ\n")).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import",
            blocklist.to_str().unwrap(),
        ])
        .assert()
        .success();

    let malfile = data_dir.path().join("aq_malware.bin");
    fs::write(&malfile, malware_content).unwrap();

    // Scan with auto-quarantine.
    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "--auto-quarantine",
            malfile.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Quarantined"));

    // The quarantine list should now show the entry.
    sd_cmd()
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "quarantine", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test.Quarantine.AQ"));
}

/// 3. Import hash, scan with --json, verify JSON has `threat_level` "Malicious".
#[test]
fn scan_with_json_output_contains_threat() {
    let data_dir = setup_data_dir();

    let malware_content = b"json_output_malware_test_payload_unique_xyz";
    let hash = sha256_hex(malware_content);
    let blocklist = data_dir.path().join("json_mal.txt");
    fs::write(&blocklist, format!("{hash} Test.JSON.Mal\n")).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import",
            blocklist.to_str().unwrap(),
        ])
        .assert()
        .success();

    let malfile = data_dir.path().join("json_malware.bin");
    fs::write(&malfile, malware_content).unwrap();

    let output = sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "--json",
            malfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["threat_level"], "Malicious");
    assert_eq!(arr[0]["threat_name"], "Test.JSON.Mal");
}

/// 4. Scan a directory and generate an HTML report via --report.
#[test]
fn scan_with_report_generates_html() {
    let data_dir = setup_data_dir();
    let scan_dir = data_dir.path().join("report_target");
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("file1.txt"), "alpha content").unwrap();
    fs::write(scan_dir.join("file2.txt"), "bravo content").unwrap();

    let report_path = data_dir.path().join("report.html");

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "--report",
            report_path.to_str().unwrap(),
            scan_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Report saved to"));

    // Verify the report file exists and contains expected HTML.
    assert!(report_path.exists(), "HTML report file must exist");
    let html = fs::read_to_string(&report_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"), "report must be HTML");
    assert!(html.contains("PRX-SD Scan Report"), "report must have title");
    assert!(html.contains("Total Files"), "report must show summary stats");
}

/// 5. Policy show → set → show (verify change) → reset.
#[test]
fn policy_show_set_reset_flow() {
    let data_dir = setup_data_dir();
    let dd = data_dir.path().to_str().unwrap();

    // Show default policy.
    sd_cmd()
        .args(["--data-dir", dd, "policy", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("on_malicious"));

    // Set on_malicious to "kill,quarantine".
    sd_cmd()
        .args(["--data-dir", dd, "policy", "set", "on_malicious", "kill,quarantine"])
        .assert()
        .success()
        .stdout(predicate::str::contains("policy updated"));

    // Show again — verify new value is persisted.
    sd_cmd()
        .args(["--data-dir", dd, "policy", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("KillProcess"))
        .stdout(predicate::str::contains("Quarantine"));

    // Reset to defaults.
    sd_cmd()
        .args(["--data-dir", dd, "policy", "reset"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reset to defaults"));
}

/// 6. Config set and show.
#[test]
fn config_set_and_show() {
    let data_dir = setup_data_dir();
    let dd = data_dir.path().to_str().unwrap();

    // Set a config key.
    sd_cmd()
        .args(["--data-dir", dd, "config", "set", "vt_api_key", "test123"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Set"));

    // Show — verify value appears.
    sd_cmd()
        .args(["--data-dir", dd, "config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test123"));
}

/// 7. Import `ClamAV` .hdb file with synthetic MD5 entries.
#[test]
fn import_clamav_with_synthetic_hdb() {
    let data_dir = setup_data_dir();

    // Create a .hdb file (ClamAV MD5 hash signature format):
    //   md5_hex:filesize:name
    let hdb_content = "\
aabbccddaabbccddaabbccddaabbccdd:1024:Test.ClamAV.HDB-1\n\
11223344112233441122334411223344:*:Test.ClamAV.HDB-2\n";

    let hdb_path = data_dir.path().join("test.hdb");
    fs::write(&hdb_path, hdb_content).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import-clamav",
            hdb_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ClamAV import complete"))
        .stdout(predicate::str::contains("MD5"));
}

/// 8. Quarantine full lifecycle: import → scan --auto-quarantine → list → restore → list empty.
#[test]
fn quarantine_full_lifecycle() {
    let data_dir = setup_data_dir();
    let dd = data_dir.path().to_str().unwrap();

    // Import a malicious hash.
    let malware_content = b"quarantine_lifecycle_test_content_unique_abcdef";
    let hash = sha256_hex(malware_content);
    let blocklist = data_dir.path().join("ql_mal.txt");
    fs::write(&blocklist, format!("{hash} Test.QLF.Trojan\n")).unwrap();

    sd_cmd()
        .args(["--data-dir", dd, "import", blocklist.to_str().unwrap()])
        .assert()
        .success();

    // Write malware file and scan with auto-quarantine.
    let malfile = data_dir.path().join("ql_malware.bin");
    fs::write(&malfile, malware_content).unwrap();

    sd_cmd()
        .args(["--data-dir", dd, "scan", "--auto-quarantine", malfile.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Quarantined"));

    // Quarantine list should show the entry.
    let list_output = sd_cmd()
        .args(["--data-dir", dd, "quarantine", "list"])
        .output()
        .unwrap();
    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        list_stdout.contains("Test.QLF.Trojan"),
        "quarantine list must show the threat name"
    );

    // Extract the quarantine ID (first 8 chars of UUID shown in the table).
    let id = list_stdout
        .lines()
        .find(|line| line.contains("Test.QLF.Trojan"))
        .expect("must find entry line")
        .split_whitespace()
        .next()
        .expect("must have ID column")
        .to_string();

    // Restore the file to a safe temp location.
    let restore_target = data_dir.path().join("restored_malware.bin");
    sd_cmd()
        .args([
            "--data-dir",
            dd,
            "quarantine",
            "restore",
            &id,
            "--to",
            restore_target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Restored"));

    // Verify the restored file has the original content.
    let restored = fs::read(&restore_target).unwrap();
    assert_eq!(restored, malware_content);

    // Quarantine list should now be empty (restore deletes the entry).
    sd_cmd()
        .args(["--data-dir", dd, "quarantine", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No quarantined files"));
}

/// 9. YARA rule detection: write a custom rule, create matching file, scan.
#[test]
fn scan_yara_rule_detection() {
    let data_dir = setup_data_dir();
    let yara_dir = data_dir.path().join("yara");

    // Write a YARA rule that matches a specific string.
    let rule = r#"
rule E2E_Test_Malware {
    meta:
        description = "E2E test rule"
        threat_name = "Test.YARA.E2E"
    strings:
        $magic = "YARA_E2E_DETECTION_MARKER_XYZ_42"
    condition:
        $magic
}
"#;
    fs::write(yara_dir.join("e2e_test.yar"), rule).unwrap();

    // Create a file containing the matching string.
    let target = data_dir.path().join("yara_target.bin");
    fs::write(&target, b"some preamble YARA_E2E_DETECTION_MARKER_XYZ_42 some epilogue").unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("E2E_Test_Malware"));
}

/// 10. Webhook add → list → remove → list (empty).
#[test]
fn webhook_add_list_remove() {
    let data_dir = setup_data_dir();
    let dd = data_dir.path().to_str().unwrap();

    // Add a webhook.
    sd_cmd()
        .args([
            "--data-dir",
            dd,
            "webhook",
            "add",
            "test-hook",
            "https://example.com/hook",
            "--format",
            "generic",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added webhook"));

    // List webhooks — should show test-hook.
    sd_cmd()
        .args(["--data-dir", dd, "webhook", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-hook"))
        .stdout(predicate::str::contains("https://example.com/hook"));

    // Remove the webhook.
    sd_cmd()
        .args(["--data-dir", dd, "webhook", "remove", "test-hook"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed webhook"));

    // List again — should be empty.
    sd_cmd()
        .args(["--data-dir", dd, "webhook", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No webhook endpoints configured"));
}

/// 11. Scan with --exclude pattern: .log files should be skipped.
#[test]
fn scan_excludes_pattern() {
    let data_dir = setup_data_dir();
    let scan_dir = data_dir.path().join("exclude_target");
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("normal.txt"), "normal content").unwrap();
    fs::write(scan_dir.join("debug.log"), "log content").unwrap();

    let output = sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "scan",
            "--json",
            "--exclude",
            "*.log",
            scan_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();

    // The .log file should not appear in results.
    let paths: Vec<String> = arr
        .iter()
        .map(|v| v["path"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        !paths.iter().any(|p| std::path::Path::new(p)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))),
        "excluded .log file should not appear in scan results: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("normal.txt")),
        "non-excluded file must appear in results: {paths:?}"
    );
}

/// 12. Info command shows database stats after importing hashes.
#[test]
fn info_command_shows_database_stats() {
    let data_dir = setup_data_dir();
    let dd = data_dir.path().to_str().unwrap();

    // Import a few hashes.
    let blocklist = data_dir.path().join("info_test.txt");
    let content = format!(
        "{} Info.Test.One\n{} Info.Test.Two\n{} Info.Test.Three\n",
        sha256_hex(b"info_test_one"),
        sha256_hex(b"info_test_two"),
        sha256_hex(b"info_test_three"),
    );
    fs::write(&blocklist, content).unwrap();

    sd_cmd()
        .args(["--data-dir", dd, "import", blocklist.to_str().unwrap()])
        .assert()
        .success();

    // Info should show the hash count.
    sd_cmd()
        .args(["--data-dir", dd, "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SHA-256 hash count"))
        .stdout(predicate::str::contains("3"));
}

/// 13. Import `ClamAV` synthetic CVD file (512-byte header + tar.gz with .hdb).
#[test]
fn import_clamav_with_synthetic_cvd() {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let data_dir = setup_data_dir();

    // Build the .hdb content (ClamAV MD5 format: md5:size:name).
    let hdb_content = "\
aabbccddaabbccddaabbccddaabbccdd:1024:CVD.Test.Malware-1\n\
11223344112233441122334411223344:*:CVD.Test.Malware-2\n\
deadbeefdeadbeefdeadbeefdeadbeef:512:CVD.Test.Malware-3\n";

    // Build a tar.gz containing the .hdb file.
    let mut tar_buf = Vec::new();
    {
        let gz = GzEncoder::new(&mut tar_buf, Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        let data = hdb_content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("test.hdb").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, data).unwrap();
        tar_builder.finish().unwrap();
    }

    // Build a CVD: 512-byte header + tar.gz payload.
    let header_str = "ClamAV-VDB:01 Jan 2025:999:3:90:abc123hash:testbuilder:0";
    let mut cvd_data = vec![0u8; 512];
    cvd_data[..header_str.len()].copy_from_slice(header_str.as_bytes());
    cvd_data.extend_from_slice(&tar_buf);

    let cvd_path = data_dir.path().join("test.cvd");
    fs::write(&cvd_path, &cvd_data).unwrap();

    sd_cmd()
        .args([
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "import-clamav",
            cvd_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ClamAV import complete"))
        .stdout(predicate::str::contains("MD5"));
}

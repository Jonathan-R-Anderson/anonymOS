use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

/// GitHub repository that hosts the signature database.
const SIGNATURES_REPO: &str = "openprx/prx-sd-signatures";

/// GitHub API endpoint for the latest commit on main.
const GITHUB_API_COMMITS: &str = "https://api.github.com/repos/openprx/prx-sd-signatures/commits?per_page=1&sha=main";

/// Tarball download URL for the main branch.
const TARBALL_URL: &str = "https://github.com/openprx/prx-sd-signatures/archive/refs/heads/main.tar.gz";

/// User-Agent header required by GitHub API.
const USER_AGENT: &str = "prx-sd-updater";

/// GitHub API commit response (minimal fields).
#[derive(Debug, Deserialize)]
struct GitHubCommit {
    sha: String,
    commit: GitHubCommitInner,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitInner {
    committer: GitHubCommitter,
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitter {
    date: String,
}

/// Read the local commit SHA that was last synced.
fn read_local_commit(data_dir: &Path) -> Option<String> {
    let version_file = data_dir.join("signatures").join("commit_sha");
    std::fs::read_to_string(version_file).ok().map(|s| s.trim().to_string())
}

/// Write the commit SHA after a successful update.
fn write_local_commit(data_dir: &Path, sha: &str) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;
    std::fs::write(sig_dir.join("commit_sha"), sha)?;
    Ok(())
}

/// Load config to get a potentially user-overridden server URL.
/// If a custom `update_server_url` is configured, return it; otherwise `None`
/// to use the default GitHub-based mechanism.
fn load_custom_server_url(data_dir: &Path) -> Option<String> {
    let config_path = data_dir.join("config.json");
    let data = std::fs::read_to_string(config_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&data).ok()?;
    val.get("update_server_url")
        .and_then(|v| v.as_str())
        .map(std::string::ToString::to_string)
}

/// Build an HTTP client with GitHub-compatible headers.
fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(USER_AGENT)
        .build()
        .context("failed to build HTTP client")
}

pub async fn run(check_only: bool, force: bool, server_url: Option<String>, data_dir: &Path) -> Result<()> {
    // If a custom server URL is provided (CLI flag or config), use the legacy
    // update-server protocol. Otherwise, use GitHub-based updates.
    let custom_url = server_url.or_else(|| load_custom_server_url(data_dir));
    if let Some(url) = custom_url {
        return run_legacy_server(check_only, force, &url, data_dir).await;
    }

    run_github_update(check_only, force, data_dir).await
}

/// Update signatures from the GitHub `prx-sd-signatures` repository.
async fn run_github_update(check_only: bool, force: bool, data_dir: &Path) -> Result<()> {
    let local_sha = read_local_commit(data_dir);

    println!("{} Checking for signature updates...", ">>>".cyan().bold());
    println!("  Source: github.com/{SIGNATURES_REPO}");
    if let Some(ref sha) = local_sha {
        println!("  Local:  {}", &sha[..sha.len().min(12)]);
    } else {
        println!("  Local:  (not yet synced)");
    }

    let client = build_client()?;

    // 1. Fetch latest commit from GitHub API.
    let commits: Vec<GitHubCommit> = client
        .get(GITHUB_API_COMMITS)
        .send()
        .await
        .context("failed to reach GitHub API")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("failed to parse GitHub API response")?;

    let latest = commits.first().context("no commits found in signatures repository")?;

    let remote_sha = &latest.sha;
    let remote_date = &latest.commit.committer.date;
    let commit_msg = latest.commit.message.lines().next().unwrap_or("(no message)");

    println!(
        "  Remote: {} ({})",
        &remote_sha[..remote_sha.len().min(12)],
        remote_date
    );
    println!("  Commit: {commit_msg}");

    let up_to_date = local_sha.as_deref() == Some(remote_sha.as_str());

    if up_to_date && !force {
        println!("\n{} Signatures are up to date.", "OK".green().bold(),);
        return Ok(());
    }

    if check_only {
        if up_to_date {
            println!("\n{} Already up to date.", "OK".green().bold());
        } else {
            println!(
                "\n{} Update available: {} -> {}",
                "UPDATE".yellow().bold(),
                local_sha.as_deref().map_or("(none)", |s| &s[..s.len().min(12)]),
                &remote_sha[..remote_sha.len().min(12)],
            );
        }
        return Ok(());
    }

    // 2. Download the tarball.
    println!("\n{} Downloading signatures...", ">>>".cyan().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}").unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message("downloading tarball...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let response = client
        .get(TARBALL_URL)
        .send()
        .await
        .context("failed to download signatures tarball")?
        .error_for_status()
        .context("tarball download failed")?;

    let bytes = response.bytes().await.context("failed to read tarball")?;
    pb.set_message(format!("downloaded {} bytes", bytes.len()));

    // 3. Extract tarball to temporary directory.
    pb.set_message("extracting...");
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);

    let tmp_dir = tempfile::tempdir().context("failed to create temporary directory")?;
    archive
        .unpack(tmp_dir.path())
        .context("failed to extract signatures tarball")?;

    // GitHub tarballs extract to a directory like `prx-sd-signatures-main/`
    let extracted_root = find_extracted_root(tmp_dir.path())?;

    // 4. Copy YARA rules.
    let yara_src = extracted_root.join("yara");
    let yara_dst = data_dir.join("yara");
    if yara_src.exists() {
        copy_dir_recursive(&yara_src, &yara_dst)?;
        let rule_count = count_files_with_ext(&yara_dst, "yar") + count_files_with_ext(&yara_dst, "yara");
        println!("  {} {rule_count} YARA rules synced", "OK".green());
    }

    // 5. Import IOC blocklists.
    let ioc_src = extracted_root.join("ioc");
    let ioc_dst = data_dir.join("ioc");
    if ioc_src.exists() {
        std::fs::create_dir_all(&ioc_dst)?;
        copy_dir_recursive(&ioc_src, &ioc_dst)?;
        let ioc_count = count_files(&ioc_dst);
        println!("  {} {ioc_count} IOC blocklists synced", "OK".green());
    }

    // 6. Import hash blocklists into LMDB.
    let hashes_src = extracted_root.join("hashes");
    if hashes_src.exists() {
        import_hash_directory(&hashes_src, data_dir)?;
    }

    // 7. Record commit SHA.
    write_local_commit(data_dir, remote_sha)?;

    pb.finish_and_clear();
    println!(
        "\n{} Signatures updated to {} ({}).",
        "OK".green().bold(),
        &remote_sha[..remote_sha.len().min(12)],
        remote_date,
    );

    Ok(())
}

/// Find the single top-level directory inside the extracted tarball.
fn find_extracted_root(tmp_dir: &Path) -> Result<std::path::PathBuf> {
    let mut entries = std::fs::read_dir(tmp_dir)?;
    let first = entries
        .next()
        .context("extracted tarball is empty")?
        .context("failed to read extracted directory")?;
    Ok(first.path())
}

/// Recursively copy a directory, overwriting existing files.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in walkdir::WalkDir::new(src).min_depth(1) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src).context("path strip_prefix failed")?;
        let target = dst.join(rel);

        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Count files in a directory tree with a given extension.
fn count_files_with_ext(dir: &Path, ext: &str) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case(ext)))
        .count()
}

/// Count all files in a directory tree.
fn count_files(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .count()
}

/// Import all hash files from the downloaded hashes directory into LMDB.
fn import_hash_directory(hashes_dir: &Path, data_dir: &Path) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;

    let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).context("failed to open signature database")?;

    let mut total_imported: usize = 0;

    for entry in walkdir::WalkDir::new(hashes_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext != "txt" && ext != "csv" {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        let mut entries: Vec<(Vec<u8>, String)> = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Support formats: "hex_hash name" or bare "hex_hash"
            let (hex_hash, name) = line
                .split_once([' ', '\t', ','])
                .map_or((line, "malware"), |(h, n)| (h.trim(), n.trim()));

            let name = if name.is_empty() { "malware" } else { name };

            if let Ok(hash_bytes) = decode_hex(hex_hash) {
                entries.push((hash_bytes, name.to_string()));
            }
        }

        if !entries.is_empty() {
            let count = db.import_hashes(&entries).unwrap_or(0);
            total_imported += count;
        }
    }

    if total_imported > 0 {
        println!("  {} {total_imported} hash entries imported", "OK".green());
    }

    Ok(())
}

/// Decode a hex string to bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("odd length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let pair = s.get(i..i + 2).context("index out of bounds")?;
            u8::from_str_radix(pair, 16).context("invalid hex digit")
        })
        .collect()
}

// ── Legacy update-server protocol ──────────────────────────────────────────

/// Manifest returned by the legacy update server's `/manifest.json` endpoint.
#[derive(Debug, Deserialize)]
struct UpdateManifest {
    version: u64,
    released_at: String,
    sha256: String,
    size: u64,
    payload_url: String,
}

/// Legacy: update from a self-hosted update server.
async fn run_legacy_server(check_only: bool, force: bool, base_url: &str, data_dir: &Path) -> Result<()> {
    use std::fmt::Write;

    let local_version = read_local_version(data_dir);

    println!("{} Checking for signature updates...", ">>>".cyan().bold());
    println!("  Server:        {base_url}");
    println!("  Local version: {local_version}");

    let manifest_url = format!("{}/manifest.json", base_url.trim_end_matches('/'));
    let client = build_client()?;

    let manifest: UpdateManifest = client
        .get(&manifest_url)
        .send()
        .await
        .context("failed to reach update server")?
        .error_for_status()
        .context("update server returned an error")?
        .json()
        .await
        .context("failed to parse update manifest")?;

    println!("  Remote version: {}", manifest.version);
    println!("  Released:       {}", manifest.released_at);

    let up_to_date = manifest.version <= local_version;

    if up_to_date && !force {
        println!(
            "\n{} Signatures are up to date (v{}).",
            "OK".green().bold(),
            local_version
        );
        return Ok(());
    }

    if check_only {
        if up_to_date {
            println!("\n{} Already up to date.", "OK".green().bold());
        } else {
            println!(
                "\n{} Update available: v{} -> v{} ({})",
                "UPDATE".yellow().bold(),
                local_version,
                manifest.version,
                crate::output::format_bytes(manifest.size),
            );
        }
        return Ok(());
    }

    let payload_url = if manifest.payload_url.starts_with("http") {
        manifest.payload_url.clone()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            manifest.payload_url.trim_start_matches('/')
        )
    };

    println!(
        "\n{} Downloading update ({})...",
        ">>>".cyan().bold(),
        crate::output::format_bytes(manifest.size),
    );

    let pb = ProgressBar::new(manifest.size);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec})",
        )
        .map_or_else(|_| ProgressStyle::default_bar(), |style| style.progress_chars("#>-")),
    );

    let response = client
        .get(&payload_url)
        .send()
        .await
        .context("failed to download update payload")?
        .error_for_status()
        .context("update download failed")?;

    let bytes = response.bytes().await.context("failed to read update payload body")?;
    pb.set_position(bytes.len() as u64);
    pb.finish_and_clear();

    // Verify SHA-256 digest.
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_bytes = hasher.finalize();
        let digest = hash_bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        if digest != manifest.sha256 {
            anyhow::bail!("SHA-256 mismatch: expected {}, got {}", manifest.sha256, digest);
        }
        println!("  {} SHA-256 verified", "OK".green());
    }

    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;
    std::fs::write(sig_dir.join("update.bin"), &bytes)?;
    write_local_version(data_dir, manifest.version)?;

    println!("\n{} Signatures updated to v{}.", "OK".green().bold(), manifest.version);
    Ok(())
}

/// Read legacy version number.
fn read_local_version(data_dir: &Path) -> u64 {
    let version_file = data_dir.join("signatures").join("version");
    std::fs::read_to_string(version_file)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Write legacy version number.
fn write_local_version(data_dir: &Path, version: u64) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;
    std::fs::write(sig_dir.join("version"), version.to_string())?;
    Ok(())
}

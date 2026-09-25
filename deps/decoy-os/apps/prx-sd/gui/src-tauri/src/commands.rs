use serde::{Deserialize, Serialize};
// NOTE: std::sync::Mutex is used here intentionally for Tauri State compatibility.
// Tauri's State<T> requires T: Send + Sync, and std::sync::Mutex provides Sync.
// parking_lot::Mutex would also work, but std::sync::Mutex is sufficient and avoids
// an extra dependency in the GUI crate.
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

use prx_sd_core::{ScanConfig, ScanEngine};
use prx_sd_quarantine::Quarantine;
use prx_sd_signatures::SignatureDatabase;

// ---------------------------------------------------------------------------
// DTO types (Serialize for Tauri IPC, separate from internal engine types)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultDto {
    pub path: String,
    pub threat_level: String,
    pub detection_type: Option<String>,
    pub threat_name: Option<String>,
    pub details: Vec<String>,
    pub scan_time_ms: u64,
}

impl From<prx_sd_core::ScanResult> for ScanResultDto {
    fn from(r: prx_sd_core::ScanResult) -> Self {
        Self {
            path: r.path.display().to_string(),
            threat_level: r.threat_level.to_string(),
            detection_type: r.detection_type.map(|d| d.to_string()),
            threat_name: r.threat_name,
            details: r.details,
            scan_time_ms: r.scan_time_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntryDto {
    pub id: String,
    pub original_path: String,
    pub threat_name: String,
    pub quarantine_time: String,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigDto {
    pub max_file_size: u64,
    pub scan_threads: u32,
    pub heuristic_threshold: u32,
    pub scan_archives: bool,
    pub max_archive_depth: u32,
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineInfoDto {
    pub version: String,
    pub signature_version: u64,
    pub hash_count: u64,
    pub yara_rule_count: u64,
    pub quarantine_count: u64,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub data_dir: PathBuf,
    // NOTE: Mutex is required by Tauri State<> which needs Send + Sync.
    // ScanEngine is Clone (Arc internals), so the Mutex overhead is minimal.
    pub engine: Mutex<Option<ScanEngine>>,
    pub quarantine: Mutex<Option<Quarantine>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            engine: Mutex::new(None),
            quarantine: Mutex::new(None),
        }
    }

    fn get_or_init_engine(&self) -> Result<ScanEngine, String> {
        let mut guard = self.engine.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let config = ScanConfig::default()
                .with_signatures_dir(self.data_dir.join("signatures"))
                .with_yara_rules_dir(self.data_dir.join("yara"))
                .with_quarantine_dir(self.data_dir.join("quarantine"));
            let engine = ScanEngine::new(config).map_err(|e| e.to_string())?;
            *guard = Some(engine);
        }
        // ScanEngine is Clone (Arc internals), so cloning is cheap.
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "engine not initialized".to_string())
    }

    fn get_or_init_quarantine(&self) -> Result<Quarantine, String> {
        let mut guard = self.quarantine.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let quarantine_dir = self.data_dir.join("quarantine");
            let q = Quarantine::new(quarantine_dir).map_err(|e| e.to_string())?;
            *guard = Some(q);
        }
        // Quarantine is not Clone, so we need to re-create it each time or
        // keep it behind the lock. We re-create to avoid holding the lock.
        drop(guard);
        let quarantine_dir = self.data_dir.join("quarantine");
        Quarantine::new(quarantine_dir).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn scan_path(
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<ScanResultDto>, String> {
    let engine = state.get_or_init_engine()?;
    let path = std::path::Path::new(&path);

    if path.is_dir() {
        let results = engine.scan_directory(path);
        Ok(results.into_iter().map(ScanResultDto::from).collect())
    } else {
        let result = engine.scan_file(path).await.map_err(|e| e.to_string())?;
        Ok(vec![ScanResultDto::from(result)])
    }
}

#[tauri::command]
pub async fn scan_directory(
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<ScanResultDto>, String> {
    let engine = state.get_or_init_engine()?;
    let dir = std::path::Path::new(&path);

    if !dir.is_dir() {
        return Err(format!("not a directory: {}", path));
    }

    let results = engine.scan_directory(dir);
    Ok(results.into_iter().map(ScanResultDto::from).collect())
}

#[tauri::command]
pub async fn start_monitor(
    paths: Vec<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Validate that paths exist.
    for p in &paths {
        let path = std::path::Path::new(p);
        if !path.exists() {
            return Err(format!("path does not exist: {}", p));
        }
    }
    // Verify the engine can be initialized (validates signatures/yara dirs).
    let _engine = state.get_or_init_engine()?;
    // Real-time monitoring in the GUI is handled by the daemon process.
    // This command validates readiness; actual monitoring is started via the
    // daemon binary (`sd daemon`).
    Ok(())
}

#[tauri::command]
pub async fn stop_monitor() -> Result<(), String> {
    // Monitoring is managed by the daemon process. Stopping is done via
    // signaling the daemon (SIGTERM on the PID from prx-sd.pid).
    Ok(())
}

#[tauri::command]
pub async fn get_quarantine_list(
    state: State<'_, AppState>,
) -> Result<Vec<QuarantineEntryDto>, String> {
    let q = state.get_or_init_quarantine()?;
    let entries = q.list().map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|(id, meta)| QuarantineEntryDto {
            id: id.to_string(),
            original_path: meta.original_path.display().to_string(),
            threat_name: meta.threat_name,
            quarantine_time: meta.quarantine_time.to_rfc3339(),
            file_size: meta.file_size,
        })
        .collect())
}

#[tauri::command]
pub async fn restore_quarantine(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let q = state.get_or_init_quarantine()?;
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;

    // Find the original path from metadata.
    let entries = q.list().map_err(|e| e.to_string())?;
    let (_, meta) = entries
        .iter()
        .find(|(eid, _)| *eid == uuid)
        .ok_or_else(|| format!("quarantine entry not found: {}", id))?;

    q.restore(uuid, &meta.original_path)
        .map_err(|e| e.to_string())?;

    // Remove the quarantine entry after successful restore.
    q.delete(uuid).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn delete_quarantine(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let q = state.get_or_init_quarantine()?;
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    q.delete(uuid).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_engine_info(
    state: State<'_, AppState>,
) -> Result<EngineInfoDto, String> {
    let data_dir = &state.data_dir;
    let sig_dir = data_dir.join("signatures");

    let (signature_version, hash_count) = if sig_dir.exists() {
        match SignatureDatabase::open(&sig_dir) {
            Ok(db) => match db.get_stats() {
                Ok(stats) => (stats.version, stats.hash_count),
                Err(_) => (0, 0),
            },
            Err(_) => (0, 0),
        }
    } else {
        (0, 0)
    };

    let yara_dir = data_dir.join("yara");
    let yara_rule_count = if yara_dir.exists() {
        walkdir::WalkDir::new(&yara_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().is_file()
                    && e.path()
                        .extension()
                        .is_some_and(|ext| ext == "yar" || ext == "yara")
            })
            .count() as u64
    } else {
        0
    };

    let quarantine_dir = data_dir.join("quarantine");
    let quarantine_count = if quarantine_dir.exists() {
        match Quarantine::new(quarantine_dir) {
            Ok(q) => q.stats().map(|s| s.count as u64).unwrap_or(0),
            Err(_) => 0,
        }
    } else {
        0
    };

    Ok(EngineInfoDto {
        version: env!("CARGO_PKG_VERSION").to_string(),
        signature_version,
        hash_count,
        yara_rule_count,
        quarantine_count,
    })
}

#[tauri::command]
pub async fn get_config(
    state: State<'_, AppState>,
) -> Result<ScanConfigDto, String> {
    let config_path = state.data_dir.join("config.json");

    if config_path.exists() {
        let data = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        let config: ScanConfig =
            serde_json::from_str(&data).map_err(|e| e.to_string())?;
        Ok(ScanConfigDto {
            max_file_size: config.max_file_size,
            scan_threads: config.scan_threads as u32,
            heuristic_threshold: config.heuristic_threshold,
            scan_archives: config.scan_archives,
            max_archive_depth: config.max_archive_depth,
            exclude_paths: config.exclude_paths,
        })
    } else {
        // Return defaults.
        let config = ScanConfig::default();
        Ok(ScanConfigDto {
            max_file_size: config.max_file_size,
            scan_threads: config.scan_threads as u32,
            heuristic_threshold: config.heuristic_threshold,
            scan_archives: config.scan_archives,
            max_archive_depth: config.max_archive_depth,
            exclude_paths: config.exclude_paths,
        })
    }
}

#[tauri::command]
pub async fn save_config(
    config: ScanConfigDto,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let data_dir = &state.data_dir;

    // Build a full ScanConfig from the DTO, preserving directory paths.
    let full_config = ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"))
        .with_max_file_size(config.max_file_size)
        .with_scan_threads(config.scan_threads as usize)
        .with_heuristic_threshold(config.heuristic_threshold);

    let mut full = full_config;
    full.scan_archives = config.scan_archives;
    full.max_archive_depth = config.max_archive_depth;
    full.exclude_paths = config.exclude_paths;

    let json = serde_json::to_string_pretty(&full).map_err(|e| e.to_string())?;

    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    std::fs::write(data_dir.join("config.json"), json).map_err(|e| e.to_string())?;

    // Invalidate the cached engine so the next scan picks up the new config.
    if let Ok(mut guard) = state.engine.lock() {
        *guard = None;
    }

    Ok(())
}

#[tauri::command]
pub async fn update_signatures(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let data_dir = &state.data_dir;
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir).map_err(|e| e.to_string())?;

    // Read server URL from config.
    let server_url = {
        let config_path = data_dir.join("config.json");
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
            .and_then(|val| {
                val.get("update_server_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| "No update server URL configured. Run 'sd update' from CLI or set update_server_url in config.".to_string())?
    };

    let manifest_url = format!("{}/manifest.json", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    #[derive(Deserialize)]
    struct UpdateManifest {
        version: u64,
        sha256: String,
        payload_url: String,
    }

    let manifest: UpdateManifest = client
        .get(&manifest_url)
        .send()
        .await
        .map_err(|e| format!("failed to reach update server: {}", e))?
        .error_for_status()
        .map_err(|e| format!("update server error: {}", e))?
        .json()
        .await
        .map_err(|e| format!("failed to parse manifest: {}", e))?;

    let payload_url = if manifest.payload_url.starts_with("http") {
        manifest.payload_url.clone()
    } else {
        format!(
            "{}/{}",
            server_url.trim_end_matches('/'),
            manifest.payload_url.trim_start_matches('/')
        )
    };

    let response = client
        .get(&payload_url)
        .send()
        .await
        .map_err(|e| format!("download failed: {}", e))?
        .error_for_status()
        .map_err(|e| format!("download error: {}", e))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("failed to read payload: {}", e))?;

    // Verify SHA-256.
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if digest != manifest.sha256 {
            return Err(format!(
                "SHA-256 mismatch: expected {}, got {}",
                manifest.sha256, digest
            ));
        }
    }

    std::fs::write(sig_dir.join("update.bin"), &bytes).map_err(|e| e.to_string())?;
    std::fs::write(sig_dir.join("version"), manifest.version.to_string())
        .map_err(|e| e.to_string())?;

    // Invalidate cached engine to force reload with new signatures.
    if let Ok(mut guard) = state.engine.lock() {
        *guard = None;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Alert history (Task 4.2.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEntryDto {
    pub timestamp: String,
    pub file: String,
    pub threat: String,
    pub level: String,
    pub action: String,
}

#[tauri::command]
pub async fn get_alert_history(
    state: State<'_, AppState>,
) -> Result<Vec<AlertEntryDto>, String> {
    let audit_dir = state.data_dir.join("audit");
    if !audit_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<AlertEntryDto> = Vec::new();

    let dir_entries = std::fs::read_dir(&audit_dir).map_err(|e| e.to_string())?;
    for dir_entry in dir_entries {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = dir_entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "jsonl" && ext != "json" {
            continue;
        }

        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AlertEntryDto>(trimmed) {
                entries.push(entry);
            } else if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                // Best-effort field extraction from arbitrary JSONL.
                entries.push(AlertEntryDto {
                    timestamp: val
                        .get("timestamp")
                        .or_else(|| val.get("time"))
                        .or_else(|| val.get("ts"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    file: val
                        .get("file")
                        .or_else(|| val.get("path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    threat: val
                        .get("threat")
                        .or_else(|| val.get("threat_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    level: val
                        .get("level")
                        .or_else(|| val.get("threat_level"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    action: val
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or("detected")
                        .to_string(),
                });
            }
        }
    }

    // Sort by timestamp descending (newest first).
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Dashboard stats (Task 4.4.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub date: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentThreatDto {
    pub path: String,
    pub threat_name: String,
    pub level: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStatsDto {
    pub total_scans: u64,
    pub threats_found: u64,
    pub files_quarantined: u64,
    pub last_scan_time: String,
    pub monitoring_active: bool,
    pub scan_history: Vec<ScanHistoryEntry>,
    pub recent_threats: Vec<RecentThreatDto>,
}

#[tauri::command]
pub async fn get_dashboard_stats(
    state: State<'_, AppState>,
) -> Result<DashboardStatsDto, String> {
    let data_dir = &state.data_dir;

    // Count quarantined files.
    let quarantine_dir = data_dir.join("quarantine");
    let files_quarantined = if quarantine_dir.exists() {
        match Quarantine::new(quarantine_dir) {
            Ok(q) => q.stats().map(|s| s.count as u64).unwrap_or(0),
            Err(_) => 0,
        }
    } else {
        0
    };

    // Check if monitoring daemon is running via PID file.
    let pid_file = data_dir.join("prx-sd.pid");
    let monitoring_active = pid_file.exists();

    // Parse audit logs to gather scan history and recent threats.
    let audit_dir = data_dir.join("audit");
    let mut total_scans: u64 = 0;
    let mut threats_found: u64 = 0;
    let mut last_scan_time = String::new();
    let mut recent_threats: Vec<RecentThreatDto> = Vec::new();
    let mut daily_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();

    if audit_dir.exists() {
        if let Ok(dir_entries) = std::fs::read_dir(&audit_dir) {
            for dir_entry in dir_entries.flatten() {
                let path = dir_entry.path();
                if !path.is_file() {
                    continue;
                }
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "jsonl" && ext != "json" {
                    continue;
                }

                let file = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let reader = std::io::BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let val: serde_json::Value = match serde_json::from_str(trimmed) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    total_scans += 1;

                    let ts = val
                        .get("timestamp")
                        .or_else(|| val.get("time"))
                        .or_else(|| val.get("ts"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if ts > last_scan_time {
                        last_scan_time = ts.clone();
                    }

                    // Extract date portion for daily counts (first 10 chars: YYYY-MM-DD).
                    let date_key = if ts.len() >= 10 {
                        ts[..10].to_string()
                    } else {
                        "unknown".to_string()
                    };
                    *daily_counts.entry(date_key).or_insert(0) += 1;

                    let level = val
                        .get("level")
                        .or_else(|| val.get("threat_level"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Clean");

                    if level != "Clean" {
                        threats_found += 1;
                        if recent_threats.len() < 10 {
                            recent_threats.push(RecentThreatDto {
                                path: val
                                    .get("file")
                                    .or_else(|| val.get("path"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                threat_name: val
                                    .get("threat")
                                    .or_else(|| val.get("threat_name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string(),
                                level: level.to_string(),
                                timestamp: ts,
                            });
                        }
                    }
                }
            }
        }
    }

    // Build scan history from daily counts (last 7 days max).
    let scan_history: Vec<ScanHistoryEntry> = daily_counts
        .into_iter()
        .rev()
        .take(7)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|(date, count)| ScanHistoryEntry { date, count })
        .collect();

    // Sort recent threats by timestamp descending.
    recent_threats.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(DashboardStatsDto {
        total_scans,
        threats_found,
        files_quarantined,
        last_scan_time,
        monitoring_active,
        scan_history,
        recent_threats,
    })
}

// ---------------------------------------------------------------------------
// Adblock commands
// ---------------------------------------------------------------------------

fn adblock_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("adblock")
}

#[tauri::command]
pub async fn get_adblock_stats(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let data_dir = &state.data_dir;
    let ab_dir = adblock_dir(data_dir);
    let enabled = ab_dir.join("enabled").exists();

    let (list_count, total_rules, last_sync, lists) =
        match prx_sd_realtime::adblock_filter::AdblockFilterManager::init(&ab_dir) {
            Ok(mgr) => {
                let stats = mgr.stats();
                let config = mgr.config();
                let lists: Vec<serde_json::Value> = config
                    .sources
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "url": s.url,
                            "category": format!("{:?}", s.category),
                            "enabled": s.enabled,
                        })
                    })
                    .collect();
                (stats.list_count, stats.total_rules, stats.last_sync, lists)
            }
            Err(_) => (0, 0, None, Vec::new()),
        };

    Ok(serde_json::json!({
        "enabled": enabled,
        "list_count": list_count,
        "total_rules": total_rules,
        "last_sync": last_sync.unwrap_or_default(),
        "lists": lists,
    }))
}

#[tauri::command]
pub async fn adblock_enable(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let data_dir = &state.data_dir;
    let ab_dir = adblock_dir(data_dir);
    std::fs::create_dir_all(&ab_dir).map_err(|e| e.to_string())?;

    // Init filter manager (downloads default lists if needed)
    let mgr = prx_sd_realtime::adblock_filter::AdblockFilterManager::init(&ab_dir)
        .map_err(|e| e.to_string())?;

    // Build DNS filter from cached lists
    let mut dns = prx_sd_realtime::DnsFilter::new();
    let lists_dir = ab_dir.join("lists");
    if lists_dir.is_dir() {
        let entries = std::fs::read_dir(&lists_dir).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty()
                    || line.starts_with('!')
                    || line.starts_with('#')
                    || line.starts_with('[')
                {
                    continue;
                }
                if let Some(rest) = line.strip_prefix("||") {
                    if let Some(domain) = rest.strip_suffix('^') {
                        dns.add_domain(domain);
                    }
                }
                if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                    if let Some(domain) = line.split_whitespace().nth(1) {
                        dns.add_domain(domain);
                    }
                }
            }
        }
    }
    let _ = mgr; // used above for init side effects

    dns.install_hosts_blocking().map_err(|e| e.to_string())?;

    let flag = ab_dir.join("enabled");
    std::fs::write(&flag, "true").map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn adblock_disable(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let data_dir = &state.data_dir;
    let ab_dir = adblock_dir(data_dir);

    let mut dns = prx_sd_realtime::DnsFilter::new();
    dns.remove_hosts_blocking().map_err(|e| e.to_string())?;

    let flag = ab_dir.join("enabled");
    if flag.exists() {
        std::fs::remove_file(&flag).ok();
    }

    Ok(())
}

#[tauri::command]
pub async fn adblock_sync(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let data_dir = &state.data_dir;
    let ab_dir = adblock_dir(data_dir);
    std::fs::create_dir_all(&ab_dir).map_err(|e| e.to_string())?;

    let mut mgr = prx_sd_realtime::adblock_filter::AdblockFilterManager::init(&ab_dir)
        .map_err(|e| e.to_string())?;
    mgr.sync().map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn adblock_check(
    domain: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let data_dir = &state.data_dir;
    let ab_dir = adblock_dir(data_dir);

    let mgr = prx_sd_realtime::adblock_filter::AdblockFilterManager::init(&ab_dir)
        .map_err(|e| e.to_string())?;

    let full_url = if domain.contains("://") {
        domain.clone()
    } else {
        format!("https://{domain}/")
    };

    let result = mgr.check_url(&full_url, &full_url, "document");

    Ok(serde_json::json!({
        "blocked": result.blocked,
        "category": format!("{:?}", result.category),
    }))
}

#[tauri::command]
pub async fn get_adblock_log(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let data_dir = &state.data_dir;
    let log_path = adblock_dir(data_dir).join("blocked_log.jsonl");

    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let start = if total > 50 { total - 50 } else { 0 };

    let mut entries: Vec<serde_json::Value> = Vec::new();
    for line in &lines[start..] {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            entries.push(val);
        }
    }

    // Reverse so newest first
    entries.reverse();

    Ok(entries)
}

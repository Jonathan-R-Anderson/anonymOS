export interface ScanResult {
  path: string;
  threat_level: 'Clean' | 'Suspicious' | 'Malicious';
  detection_type: string | null;
  threat_name: string | null;
  details: string[];
  scan_time_ms: number;
}

export interface QuarantineEntry {
  id: string;
  original_path: string;
  threat_name: string;
  quarantine_time: string;
  file_size: number;
}

export interface MonitorEvent {
  event_type: string;
  path: string;
  timestamp: string;
  threat_level?: string;
}

export interface ScanConfig {
  max_file_size: number;
  scan_threads: number;
  heuristic_threshold: number;
  scan_archives: boolean;
  max_archive_depth: number;
  exclude_paths: string[];
}

export interface EngineInfo {
  version: string;
  signature_version: number;
  hash_count: number;
  yara_rule_count: number;
  quarantine_count: number;
}

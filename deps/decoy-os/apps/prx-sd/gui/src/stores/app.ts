import { reactive } from 'vue';
import type { ScanResult, MonitorEvent, QuarantineEntry, ScanConfig, EngineInfo } from '../types';

export interface ScanProgress {
  total: number;
  scanned: number;
  threats: number;
  current: string;
}

export interface AppState {
  currentPage: string;
  scanResults: ScanResult[];
  isScanning: boolean;
  scanProgress: ScanProgress;
  monitorEvents: MonitorEvent[];
  isMonitoring: boolean;
  monitoredPaths: string[];
  quarantineEntries: QuarantineEntry[];
  config: ScanConfig;
  engineInfo: EngineInfo;
}

export const state = reactive<AppState>({
  currentPage: 'dashboard',
  scanResults: [],
  isScanning: false,
  scanProgress: { total: 0, scanned: 0, threats: 0, current: '' },
  monitorEvents: [],
  isMonitoring: false,
  monitoredPaths: [],
  quarantineEntries: [],
  config: {
    max_file_size: 104857600,
    scan_threads: 4,
    heuristic_threshold: 60,
    scan_archives: true,
    max_archive_depth: 3,
    exclude_paths: [],
  },
  engineInfo: {
    version: '0.1.0',
    signature_version: 0,
    hash_count: 0,
    yara_rule_count: 0,
    quarantine_count: 0,
  },
});

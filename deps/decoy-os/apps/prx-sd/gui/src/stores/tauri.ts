import { invoke } from '@tauri-apps/api/core';
import type { ScanResult, QuarantineEntry, ScanConfig, EngineInfo } from '../types';

async function safeInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    console.error(`Tauri invoke "${cmd}" failed:`, err);
    throw err;
  }
}

export async function scanPath(path: string): Promise<ScanResult[]> {
  return safeInvoke<ScanResult[]>('scan_path', { path });
}

export async function scanDirectory(path: string): Promise<ScanResult[]> {
  return safeInvoke<ScanResult[]>('scan_directory', { path });
}

export async function getQuarantineList(): Promise<QuarantineEntry[]> {
  return safeInvoke<QuarantineEntry[]>('get_quarantine_list');
}

export async function quarantineFile(path: string, threatName: string): Promise<string> {
  return safeInvoke<string>('quarantine_file', { path, threatName });
}

export async function restoreFile(id: string): Promise<void> {
  return safeInvoke<void>('restore_file', { id });
}

export async function deleteQuarantined(id: string): Promise<void> {
  return safeInvoke<void>('delete_quarantined', { id });
}

export async function startMonitor(paths: string[]): Promise<void> {
  return safeInvoke<void>('start_monitor', { paths });
}

export async function stopMonitor(): Promise<void> {
  return safeInvoke<void>('stop_monitor');
}

export async function getConfig(): Promise<ScanConfig> {
  return safeInvoke<ScanConfig>('get_config');
}

export async function updateConfig(config: ScanConfig): Promise<void> {
  return safeInvoke<void>('update_config', { config });
}

export async function getEngineInfo(): Promise<EngineInfo> {
  return safeInvoke<EngineInfo>('get_engine_info');
}

export async function updateSignatures(): Promise<void> {
  return safeInvoke<void>('update_signatures');
}

export interface AlertEntry {
  timestamp: string;
  file: string;
  threat: string;
  level: string;
  action: string;
}

export async function getAlertHistory(): Promise<AlertEntry[]> {
  return safeInvoke<AlertEntry[]>('get_alert_history');
}

export interface DashboardStats {
  total_scans: number;
  threats_found: number;
  files_quarantined: number;
  last_scan_time: string;
  monitoring_active: boolean;
  scan_history: { date: string; count: number }[];
  recent_threats: {
    path: string;
    threat_name: string;
    level: string;
    timestamp: string;
  }[];
}

export async function getDashboardStats(): Promise<DashboardStats> {
  return safeInvoke<DashboardStats>('get_dashboard_stats');
}

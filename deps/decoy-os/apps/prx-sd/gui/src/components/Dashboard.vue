<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { state } from '../stores/app';
import { getEngineInfo, getQuarantineList } from '../stores/tauri';
import { t } from '../i18n';
import Badge from './Badge.vue';

interface DashboardStats {
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

const stats = ref<DashboardStats>({
  total_scans: 0,
  threats_found: 0,
  files_quarantined: 0,
  last_scan_time: '',
  monitoring_active: false,
  scan_history: [],
  recent_threats: [],
});
const isLoading = ref(true);

const maxHistoryCount = computed(() => {
  if (stats.value.scan_history.length === 0) return 1;
  return Math.max(...stats.value.scan_history.map(h => h.count), 1);
});

function barHeight(count: number): number {
  return Math.max(Math.round((count / maxHistoryCount.value) * 100), 2);
}

function truncatePath(path: string, maxLen = 45): string {
  if (path.length <= maxLen) return path;
  return '...' + path.slice(path.length - maxLen + 3);
}

function formatTimestamp(ts: string): string {
  if (!ts) return '-';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

async function loadDashboard() {
  isLoading.value = true;
  try {
    const data = await invoke<DashboardStats>('get_dashboard_stats');
    stats.value = data;
  } catch {
    // Fallback: build stats from local state
    const quarantine = await getQuarantineList().catch(() => []);
    const info = await getEngineInfo().catch(() => state.engineInfo);
    state.engineInfo = info;
    state.quarantineEntries = quarantine;

    stats.value = {
      total_scans: state.scanResults.length,
      threats_found: state.scanResults.filter(r => r.threat_level !== 'Clean').length,
      files_quarantined: quarantine.length,
      last_scan_time: '',
      monitoring_active: state.isMonitoring,
      scan_history: [],
      recent_threats: state.scanResults
        .filter(r => r.threat_level !== 'Clean')
        .slice(0, 10)
        .map(r => ({
          path: r.path,
          threat_name: r.threat_name || 'Unknown',
          level: r.threat_level,
          timestamp: '',
        })),
    };
  } finally {
    isLoading.value = false;
  }
}

onMounted(() => {
  loadDashboard();
});
</script>

<template>
  <div class="dashboard">
    <div class="header-row">
      <h1 class="page-title">{{ t('dashboard.title') }}</h1>
      <button class="btn btn-secondary" :disabled="isLoading" @click="loadDashboard">
        {{ t('alerts.refresh') }}
      </button>
    </div>

    <!-- Summary cards -->
    <div class="summary-cards">
      <div class="card">
        <div class="card-icon card-icon-scan">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="10" cy="10" r="7" stroke="currentColor" stroke-width="2" fill="none"/>
            <path d="M15 15l5 5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="card-value">{{ stats.total_scans }}</div>
        <div class="card-label">{{ t('dashboard.total_scans') }}</div>
      </div>
      <div class="card">
        <div class="card-icon card-icon-threat">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L2 22h20L12 2z" stroke="currentColor" stroke-width="2" fill="none"/>
            <path d="M12 10v4M12 17v1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="card-value card-value-threat">{{ stats.threats_found }}</div>
        <div class="card-label">{{ t('dashboard.threats_found') }}</div>
      </div>
      <div class="card">
        <div class="card-icon card-icon-quarantine">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="3" y="11" width="18" height="11" rx="2" stroke="currentColor" stroke-width="2" fill="none"/>
            <path d="M7 11V7a5 5 0 0110 0v4" stroke="currentColor" stroke-width="2" fill="none"/>
          </svg>
        </div>
        <div class="card-value">{{ stats.files_quarantined }}</div>
        <div class="card-label">{{ t('dashboard.quarantined') }}</div>
      </div>
      <div class="card">
        <div class="card-icon" :class="stats.monitoring_active ? 'card-icon-active' : 'card-icon-inactive'">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" stroke-width="2" fill="none"/>
            <path v-if="stats.monitoring_active" d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path v-else d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="card-value" :class="stats.monitoring_active ? 'card-value-active' : 'card-value-inactive'">
          {{ stats.monitoring_active ? t('dashboard.protected') : t('dashboard.unprotected') }}
        </div>
        <div class="card-label">{{ t('dashboard.status') }}</div>
      </div>
    </div>

    <div class="panels">
      <!-- Scan history chart -->
      <div class="panel">
        <h2 class="panel-title">{{ t('dashboard.scan_history') }}</h2>
        <div v-if="stats.scan_history.length > 0" class="chart">
          <div class="chart-bars">
            <div
              v-for="(entry, idx) in stats.scan_history"
              :key="idx"
              class="chart-bar-group"
            >
              <div class="chart-bar-value">{{ entry.count }}</div>
              <div class="chart-bar" :style="{ height: `${barHeight(entry.count)}%` }"></div>
              <div class="chart-bar-label">{{ entry.date }}</div>
            </div>
          </div>
        </div>
        <div v-else class="panel-empty">
          {{ t('dashboard.no_history') }}
        </div>
      </div>

      <!-- Recent threats -->
      <div class="panel">
        <h2 class="panel-title">{{ t('dashboard.recent_threats') }}</h2>
        <div v-if="stats.recent_threats.length > 0" class="threat-list">
          <div
            v-for="(threat, idx) in stats.recent_threats"
            :key="idx"
            class="threat-item"
          >
            <div class="threat-info">
              <div class="threat-path" :title="threat.path">{{ truncatePath(threat.path) }}</div>
              <div class="threat-name">{{ threat.threat_name }}</div>
            </div>
            <Badge :level="threat.level" />
          </div>
        </div>
        <div v-else class="panel-empty">
          {{ t('dashboard.no_threats') }}
        </div>
      </div>
    </div>

    <!-- System status -->
    <div class="system-status">
      <h2 class="panel-title">{{ t('dashboard.system_status') }}</h2>
      <div class="status-grid">
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.engine_version') }}</span>
          <span class="status-value">v{{ state.engineInfo.version }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.sig_version') }}</span>
          <span class="status-value">{{ state.engineInfo.signature_version || '-' }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.hash_count') }}</span>
          <span class="status-value">{{ state.engineInfo.hash_count.toLocaleString() }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.yara_rules') }}</span>
          <span class="status-value">{{ state.engineInfo.yara_rule_count }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.monitoring') }}</span>
          <span class="status-value" :class="state.isMonitoring ? 'status-on' : 'status-off'">
            {{ state.isMonitoring ? t('dashboard.active') : t('dashboard.inactive') }}
          </span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('dashboard.last_scan') }}</span>
          <span class="status-value">{{ stats.last_scan_time ? formatTimestamp(stats.last_scan_time) : '-' }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dashboard {
  max-width: 1000px;
  box-sizing: border-box;
}

.header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}

.page-title {
  font-size: 24px;
  font-weight: 700;
  color: #e2e8f0;
  margin: 0;
}

.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
  font-family: system-ui, -apple-system, sans-serif;
  cursor: pointer;
  transition: all 0.2s;
  box-sizing: border-box;
  white-space: nowrap;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: rgba(99, 102, 241, 0.15);
  color: #6366f1;
  border: 1px solid #6366f1;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(99, 102, 241, 0.3);
}

/* Summary cards */
.summary-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}

.card {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.card-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.card-icon-scan { background: rgba(99, 102, 241, 0.15); color: #6366f1; }
.card-icon-threat { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
.card-icon-quarantine { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
.card-icon-active { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
.card-icon-inactive { background: rgba(153, 153, 153, 0.15); color: #999; }

.card-value {
  font-size: 28px;
  font-weight: 700;
  color: #e2e8f0;
}

.card-value-threat { color: #ef4444; }
.card-value-active { font-size: 16px; color: #22c55e; }
.card-value-inactive { font-size: 16px; color: #999; }

.card-label {
  font-size: 12px;
  color: #94a3b8;
}

/* Panels */
.panels {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 24px;
}

.panel {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 12px;
  padding: 20px;
}

.panel-title {
  font-size: 16px;
  font-weight: 600;
  color: #e2e8f0;
  margin: 0 0 16px;
}

.panel-empty {
  text-align: center;
  padding: 32px 16px;
  color: #666;
  font-size: 14px;
}

/* Chart */
.chart {
  height: 200px;
}

.chart-bars {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  height: 100%;
  padding-bottom: 24px;
  position: relative;
}

.chart-bar-group {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
  justify-content: flex-end;
}

.chart-bar-value {
  font-size: 11px;
  color: #94a3b8;
  margin-bottom: 4px;
}

.chart-bar {
  width: 100%;
  max-width: 40px;
  background: linear-gradient(180deg, #6366f1, #4f46e5);
  border-radius: 4px 4px 0 0;
  min-height: 2px;
  transition: height 0.3s ease;
}

.chart-bar-label {
  font-size: 10px;
  color: #666;
  margin-top: 6px;
  white-space: nowrap;
}

/* Threat list */
.threat-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 220px;
  overflow-y: auto;
}

.threat-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 6px;
  background: rgba(30, 30, 58, 0.3);
}

.threat-info {
  flex: 1;
  min-width: 0;
}

.threat-path {
  font-family: monospace;
  font-size: 12px;
  color: #ccc;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.threat-name {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 2px;
}

/* System status */
.system-status {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 12px;
  padding: 20px;
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.status-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.status-label {
  font-size: 12px;
  color: #94a3b8;
}

.status-value {
  font-size: 14px;
  font-weight: 600;
  color: #e2e8f0;
}

.status-on { color: #22c55e; }
.status-off { color: #999; }
</style>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { state } from '../stores/app';
import { scanPath, quarantineFile } from '../stores/tauri';
import { t } from '../i18n';
import Badge from '../components/Badge.vue';

const scanTarget = ref('/home');

const summaryCards = computed(() => {
  const results = state.scanResults;
  const clean = results.filter(r => r.threat_level === 'Clean').length;
  const suspicious = results.filter(r => r.threat_level === 'Suspicious').length;
  const malicious = results.filter(r => r.threat_level === 'Malicious').length;
  return { total: results.length, clean, suspicious, malicious };
});

const hasThreats = computed(() =>
  state.scanResults.some(r => r.threat_level !== 'Clean')
);

const progressPercent = computed(() => {
  if (state.scanProgress.total === 0) return 0;
  return Math.round((state.scanProgress.scanned / state.scanProgress.total) * 100);
});

async function startScan() {
  if (!scanTarget.value.trim()) return;
  state.isScanning = true;
  state.scanResults = [];
  state.scanProgress = { total: 0, scanned: 0, threats: 0, current: '' };

  try {
    const results = await scanPath(scanTarget.value.trim());
    state.scanResults = results;
    state.scanProgress.scanned = results.length;
    state.scanProgress.total = results.length;
    state.scanProgress.threats = results.filter(r => r.threat_level !== 'Clean').length;
  } catch (err) {
    console.error('Scan failed:', err);
  } finally {
    state.isScanning = false;
  }
}

async function quarantineAll() {
  const threats = state.scanResults.filter(r => r.threat_level !== 'Clean');
  for (const threat of threats) {
    try {
      await quarantineFile(threat.path, threat.threat_name || 'Unknown');
    } catch (err) {
      console.error('Quarantine failed for', threat.path, err);
    }
  }
}

function truncatePath(path: string, maxLen = 60): string {
  if (path.length <= maxLen) return path;
  return '...' + path.slice(path.length - maxLen + 3);
}
</script>

<template>
  <div class="scan-page">
    <h1 class="page-title">{{ t('scan.title') }}</h1>

    <div class="scan-input-row">
      <input
        v-model="scanTarget"
        type="text"
        class="scan-input"
        :placeholder="t('scan.placeholder')"
        :disabled="state.isScanning"
        @keyup.enter="startScan"
      />
      <button
        class="btn btn-primary"
        :disabled="state.isScanning || !scanTarget.trim()"
        @click="startScan"
      >
        {{ state.isScanning ? t('scan.scanning') : t('scan.button') }}
      </button>
    </div>

    <div v-if="state.isScanning" class="progress-section">
      <div class="progress-info">
        <span>{{ state.scanProgress.current || t('scan.progress') }}</span>
        <span>{{ progressPercent }}%</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" :style="{ width: progressPercent + '%' }"></div>
      </div>
      <div class="progress-stats">
        {{ t('scan.scanned') }}: {{ state.scanProgress.scanned }} / {{ state.scanProgress.total }}
        &nbsp;&bull;&nbsp;
        {{ t('scan.threats') }}: {{ state.scanProgress.threats }}
      </div>
    </div>

    <div v-if="state.scanResults.length > 0" class="summary-cards">
      <div class="card card-total">
        <div class="card-value">{{ summaryCards.total }}</div>
        <div class="card-label">{{ t('scan.summary.total') }}</div>
      </div>
      <div class="card card-clean">
        <div class="card-value">{{ summaryCards.clean }}</div>
        <div class="card-label">{{ t('scan.summary.clean') }}</div>
      </div>
      <div class="card card-suspicious">
        <div class="card-value">{{ summaryCards.suspicious }}</div>
        <div class="card-label">{{ t('scan.summary.suspicious') }}</div>
      </div>
      <div class="card card-malicious">
        <div class="card-value">{{ summaryCards.malicious }}</div>
        <div class="card-label">{{ t('scan.summary.malicious') }}</div>
      </div>
    </div>

    <div v-if="hasThreats" class="actions-row">
      <button class="btn btn-danger" @click="quarantineAll">
        🔒 {{ t('scan.quarantine_all') }}
      </button>
    </div>

    <div v-if="state.scanResults.length > 0" class="results-table-wrap">
      <table class="results-table">
        <thead>
          <tr>
            <th>{{ t('scan.path_col') }}</th>
            <th>{{ t('scan.level_col') }}</th>
            <th>{{ t('scan.type_col') }}</th>
            <th>{{ t('scan.threat_col') }}</th>
            <th>{{ t('scan.time_col') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(result, idx) in state.scanResults"
            :key="idx"
            :class="{ 'row-threat': result.threat_level !== 'Clean' }"
          >
            <td class="cell-path" :title="result.path">{{ truncatePath(result.path) }}</td>
            <td><Badge :level="result.threat_level" /></td>
            <td>{{ result.detection_type || '-' }}</td>
            <td>{{ result.threat_name || '-' }}</td>
            <td class="cell-time">{{ result.scan_time_ms }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="!state.isScanning && state.scanResults.length === 0" class="empty-state">
      <div class="empty-icon">🔍</div>
      <div class="empty-text">{{ t('scan.empty_hint') }}</div>
    </div>
  </div>
</template>

<style scoped>
.scan-page {
  max-width: 1000px;
  box-sizing: border-box;
}

.page-title {
  font-size: 24px;
  font-weight: 700;
  color: #e2e8f0;
  margin: 0 0 20px;
}

.scan-input-row {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
}

.scan-input {
  flex: 1;
  padding: 12px 16px;
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  color: #e2e8f0;
  font-size: 14px;
  font-family: system-ui, -apple-system, sans-serif;
  box-sizing: border-box;
  outline: none;
  transition: border-color 0.2s;
}

.scan-input:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.scan-input:disabled {
  opacity: 0.5;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 4px;
  font-size: 14px;
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

.btn-primary {
  background: #6366f1;
  color: #fff;
}

.btn-primary:hover:not(:disabled) {
  background: #4f46e5;
}

.btn-danger {
  background: rgba(99, 102, 241, 0.15);
  color: #6366f1;
  border: 1px solid #6366f1;
}

.btn-danger:hover:not(:disabled) {
  background: rgba(99, 102, 241, 0.3);
}

.progress-section {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
}

.progress-info {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
  color: #999;
  margin-bottom: 8px;
}

.progress-bar {
  height: 8px;
  background: #1e1e3a;
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #6366f1, #818cf8);
  border-radius: 4px;
  transition: width 0.3s ease;
}

.progress-stats {
  font-size: 12px;
  color: #666;
  margin-top: 8px;
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.card {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.card-value {
  font-size: 28px;
  font-weight: 700;
}

.card-label {
  font-size: 12px;
  color: #999;
  margin-top: 4px;
}

.card-total .card-value { color: #e2e8f0; }
.card-clean .card-value { color: #22c55e; }
.card-suspicious .card-value { color: #f59e0b; }
.card-malicious .card-value { color: #ef4444; }

.actions-row {
  margin-bottom: 16px;
}

.results-table-wrap {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  overflow: hidden;
}

.results-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.results-table th {
  text-align: left;
  padding: 12px 14px;
  background: #1e1e3a;
  color: #999;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.results-table td {
  padding: 10px 14px;
  border-top: 1px solid rgba(15, 52, 96, 0.5);
  color: #ccc;
}

.results-table tr:hover td {
  background: rgba(15, 52, 96, 0.3);
}

.row-threat td {
  background: rgba(99, 102, 241, 0.05);
}

.cell-path {
  font-family: monospace;
  font-size: 12px;
  max-width: 350px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-time {
  text-align: right;
  font-family: monospace;
  color: #666;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.empty-text {
  font-size: 15px;
}
</style>

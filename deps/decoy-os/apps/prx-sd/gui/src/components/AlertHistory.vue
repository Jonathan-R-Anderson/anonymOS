<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { t } from '../i18n';
import Badge from './Badge.vue';

interface AlertEntry {
  timestamp: string;
  file: string;
  threat: string;
  level: string;
  action: string;
}

const alerts = ref<AlertEntry[]>([]);
const searchQuery = ref('');
const isLoading = ref(false);
const sortAsc = ref(false);

async function loadAlerts() {
  isLoading.value = true;
  try {
    const entries = await invoke<AlertEntry[]>('get_alert_history');
    alerts.value = entries;
  } catch (err) {
    console.error('Failed to load alert history:', err);
    alerts.value = [];
  } finally {
    isLoading.value = false;
  }
}

const filteredAlerts = computed(() => {
  const q = searchQuery.value.toLowerCase().trim();
  let result = alerts.value;

  if (q) {
    result = result.filter(a =>
      a.timestamp.toLowerCase().includes(q) ||
      a.file.toLowerCase().includes(q) ||
      a.threat.toLowerCase().includes(q) ||
      a.level.toLowerCase().includes(q) ||
      a.action.toLowerCase().includes(q)
    );
  }

  result = [...result].sort((a, b) => {
    const cmp = a.timestamp.localeCompare(b.timestamp);
    return sortAsc.value ? cmp : -cmp;
  });

  return result;
});

function toggleSort() {
  sortAsc.value = !sortAsc.value;
}

function truncatePath(path: string, maxLen = 50): string {
  if (path.length <= maxLen) return path;
  return '...' + path.slice(path.length - maxLen + 3);
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString();
  } catch {
    return ts;
  }
}

onMounted(() => {
  loadAlerts();
});
</script>

<template>
  <div class="alert-history">
    <div class="header-row">
      <h1 class="page-title">{{ t('alerts.title') }}</h1>
      <button class="btn btn-secondary" :disabled="isLoading" @click="loadAlerts">
        {{ t('alerts.refresh') }}
      </button>
    </div>

    <div class="search-row">
      <input
        v-model="searchQuery"
        type="text"
        class="search-input"
        :placeholder="t('alerts.search')"
      />
      <div class="result-count">{{ filteredAlerts.length }} {{ t('alerts.entries') }}</div>
    </div>

    <div v-if="isLoading" class="loading-state">
      <div class="spinner"></div>
      <span>{{ t('common.loading') }}</span>
    </div>

    <div v-else-if="filteredAlerts.length === 0" class="empty-state">
      <div class="empty-icon">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="24" cy="24" r="20" stroke="#333" stroke-width="2" fill="none"/>
          <path d="M24 14v12M24 30v2" stroke="#666" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="empty-text">{{ t('alerts.empty') }}</div>
    </div>

    <div v-else class="table-wrap">
      <table class="alert-table">
        <thead>
          <tr>
            <th class="col-time" @click="toggleSort">
              {{ t('alerts.col_time') }}
              <span class="sort-icon">{{ sortAsc ? '&#9650;' : '&#9660;' }}</span>
            </th>
            <th>{{ t('alerts.col_file') }}</th>
            <th>{{ t('alerts.col_threat') }}</th>
            <th>{{ t('alerts.col_level') }}</th>
            <th>{{ t('alerts.col_action') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(alert, idx) in filteredAlerts" :key="idx">
            <td class="cell-time">{{ formatTimestamp(alert.timestamp) }}</td>
            <td class="cell-path" :title="alert.file">{{ truncatePath(alert.file) }}</td>
            <td>{{ alert.threat || '-' }}</td>
            <td><Badge :level="alert.level" /></td>
            <td class="cell-action">{{ alert.action }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.alert-history {
  max-width: 1000px;
  box-sizing: border-box;
}

.header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
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

.search-row {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
}

.search-input {
  flex: 1;
  padding: 10px 16px;
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

.search-input:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.result-count {
  font-size: 13px;
  color: #94a3b8;
  white-space: nowrap;
}

.loading-state {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 40px 0;
  justify-content: center;
  color: #94a3b8;
  font-size: 14px;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #1e1e3a;
  border-top-color: #6366f1;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}

.empty-icon {
  margin-bottom: 16px;
}

.empty-text {
  font-size: 15px;
}

.table-wrap {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  overflow: hidden;
}

.alert-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.alert-table th {
  text-align: left;
  padding: 12px 14px;
  background: #1e1e3a;
  color: #999;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  user-select: none;
}

.col-time {
  cursor: pointer;
}

.col-time:hover {
  color: #e2e8f0;
}

.sort-icon {
  font-size: 10px;
  margin-left: 4px;
  color: #6366f1;
}

.alert-table td {
  padding: 10px 14px;
  border-top: 1px solid rgba(30, 30, 58, 0.5);
  color: #ccc;
}

.alert-table tr:hover td {
  background: rgba(15, 52, 96, 0.3);
}

.cell-time {
  font-family: monospace;
  font-size: 12px;
  white-space: nowrap;
  color: #94a3b8;
}

.cell-path {
  font-family: monospace;
  font-size: 12px;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-action {
  font-size: 12px;
  color: #94a3b8;
}
</style>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { state } from '../stores/app';
import { getQuarantineList, restoreFile, deleteQuarantined } from '../stores/tauri';
import { t } from '../i18n';

const selectedIds = ref<Set<string>>(new Set());
const loading = ref(false);

const totalSize = computed(() =>
  state.quarantineEntries.reduce((sum, e) => sum + e.file_size, 0)
);

const allSelected = computed(() =>
  state.quarantineEntries.length > 0 &&
  state.quarantineEntries.every(e => selectedIds.value.has(e.id))
);

function toggleSelectAll() {
  if (allSelected.value) {
    selectedIds.value.clear();
  } else {
    state.quarantineEntries.forEach(e => selectedIds.value.add(e.id));
  }
}

function toggleSelect(id: string) {
  if (selectedIds.value.has(id)) {
    selectedIds.value.delete(id);
  } else {
    selectedIds.value.add(id);
  }
}

async function refresh() {
  loading.value = true;
  try {
    state.quarantineEntries = await getQuarantineList();
  } catch (err) {
    console.error('Failed to load quarantine:', err);
  } finally {
    loading.value = false;
  }
}

async function restore(id: string) {
  try {
    await restoreFile(id);
    await refresh();
    selectedIds.value.delete(id);
  } catch (err) {
    console.error('Restore failed:', err);
  }
}

async function remove(id: string) {
  try {
    await deleteQuarantined(id);
    await refresh();
    selectedIds.value.delete(id);
  } catch (err) {
    console.error('Delete failed:', err);
  }
}

async function bulkRestore() {
  for (const id of selectedIds.value) {
    try { await restoreFile(id); } catch { /* skip */ }
  }
  selectedIds.value.clear();
  await refresh();
}

async function bulkDelete() {
  for (const id of selectedIds.value) {
    try { await deleteQuarantined(id); } catch { /* skip */ }
  }
  selectedIds.value.clear();
  await refresh();
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(1) + ' GB';
}

function formatDate(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function truncateId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) + '...' : id;
}

onMounted(refresh);
</script>

<template>
  <div class="quarantine-page">
    <h1 class="page-title">{{ t('quarantine.title') }}</h1>

    <div class="stats-bar">
      <div class="stat-item">
        <span class="stat-label">{{ t('quarantine.files') }}:</span>
        <span class="stat-value">{{ state.quarantineEntries.length }}</span>
      </div>
      <div class="stat-item">
        <span class="stat-label">{{ t('quarantine.total_size') }}:</span>
        <span class="stat-value">{{ formatSize(totalSize) }}</span>
      </div>
      <button class="btn btn-refresh" @click="refresh" :disabled="loading">
        {{ loading ? t('quarantine.loading') : t('quarantine.refresh') }}
      </button>
    </div>

    <div v-if="selectedIds.size > 0" class="bulk-actions">
      <span class="bulk-info">{{ selectedIds.size }} {{ t('quarantine.selected') }}</span>
      <button class="btn btn-outline" @click="bulkRestore">{{ t('quarantine.restore_selected') }}</button>
      <button class="btn btn-danger" @click="bulkDelete">{{ t('quarantine.delete_selected') }}</button>
    </div>

    <div v-if="state.quarantineEntries.length > 0" class="table-wrap">
      <table class="q-table">
        <thead>
          <tr>
            <th class="col-check">
              <input
                type="checkbox"
                :checked="allSelected"
                @change="toggleSelectAll"
              />
            </th>
            <th>{{ t('quarantine.col_id') }}</th>
            <th>{{ t('quarantine.col_path') }}</th>
            <th>{{ t('quarantine.col_threat') }}</th>
            <th>{{ t('quarantine.col_date') }}</th>
            <th>{{ t('quarantine.col_size') }}</th>
            <th>{{ t('quarantine.col_actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in state.quarantineEntries" :key="entry.id">
            <td class="col-check">
              <input
                type="checkbox"
                :checked="selectedIds.has(entry.id)"
                @change="toggleSelect(entry.id)"
              />
            </td>
            <td class="cell-id" :title="entry.id">{{ truncateId(entry.id) }}</td>
            <td class="cell-path" :title="entry.original_path">{{ entry.original_path }}</td>
            <td class="cell-threat">{{ entry.threat_name }}</td>
            <td class="cell-date">{{ formatDate(entry.quarantine_time) }}</td>
            <td class="cell-size">{{ formatSize(entry.file_size) }}</td>
            <td class="cell-actions">
              <button class="action-btn action-restore" @click="restore(entry.id)" :title="t('quarantine.restore')">
                ↩
              </button>
              <button class="action-btn action-delete" @click="remove(entry.id)" :title="t('quarantine.delete')">
                ✕
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else class="empty-state">
      <div class="empty-icon">🔒</div>
      <div class="empty-text">{{ t('quarantine.empty') }}</div>
      <div class="empty-sub">{{ t('quarantine.empty_sub') }}</div>
    </div>
  </div>
</template>

<style scoped>
.quarantine-page {
  max-width: 1000px;
  box-sizing: border-box;
}

.page-title {
  font-size: 24px;
  font-weight: 700;
  color: #e2e8f0;
  margin: 0 0 20px;
}

.stats-bar {
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 14px 18px;
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  margin-bottom: 16px;
}

.stat-item {
  display: flex;
  gap: 6px;
  font-size: 14px;
}

.stat-label {
  color: #999;
}

.stat-value {
  color: #e2e8f0;
  font-weight: 600;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
  font-family: system-ui, -apple-system, sans-serif;
  cursor: pointer;
  transition: all 0.2s;
  box-sizing: border-box;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-refresh {
  margin-left: auto;
  background: #1e1e3a;
  color: #ccc;
}

.btn-refresh:hover:not(:disabled) {
  background: #2a2a4a;
  color: #e2e8f0;
}

.bulk-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  padding: 10px 16px;
  background: rgba(99, 102, 241, 0.1);
  border: 1px solid rgba(99, 102, 241, 0.3);
  border-radius: 8px;
}

.bulk-info {
  font-size: 13px;
  color: #6366f1;
  font-weight: 600;
  margin-right: auto;
}

.btn-outline {
  background: transparent;
  color: #ccc;
  border: 1px solid #1e1e3a;
}

.btn-outline:hover {
  border-color: #6366f1;
  color: #e2e8f0;
}

.btn-danger {
  background: #ef4444;
  color: #fff;
}

.btn-danger:hover {
  background: #dc2626;
}

.table-wrap {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  overflow: hidden;
}

.q-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.q-table th {
  text-align: left;
  padding: 12px 14px;
  background: #1e1e3a;
  color: #999;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.q-table td {
  padding: 10px 14px;
  border-top: 1px solid rgba(15, 52, 96, 0.5);
  color: #ccc;
}

.q-table tr:hover td {
  background: rgba(15, 52, 96, 0.3);
}

.col-check {
  width: 40px;
  text-align: center;
}

.col-check input[type="checkbox"] {
  accent-color: #6366f1;
  cursor: pointer;
}

.cell-id {
  font-family: monospace;
  font-size: 12px;
  color: #666;
}

.cell-path {
  font-family: monospace;
  font-size: 12px;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cell-threat {
  color: #ef4444;
  font-weight: 600;
  font-size: 12px;
}

.cell-date {
  font-size: 12px;
  color: #999;
  white-space: nowrap;
}

.cell-size {
  font-family: monospace;
  font-size: 12px;
  color: #999;
  text-align: right;
  white-space: nowrap;
}

.cell-actions {
  white-space: nowrap;
}

.action-btn {
  background: none;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  padding: 4px 10px;
  cursor: pointer;
  font-size: 14px;
  margin-right: 6px;
  transition: all 0.2s;
}

.action-restore {
  color: #6366f1;
}

.action-restore:hover {
  background: rgba(99, 102, 241, 0.15);
  border-color: #6366f1;
}

.action-delete {
  color: #ef4444;
}

.action-delete:hover {
  background: rgba(239, 68, 68, 0.15);
  border-color: #ef4444;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.empty-text {
  font-size: 17px;
  color: #999;
  margin-bottom: 6px;
}

.empty-sub {
  font-size: 13px;
  color: #555;
}
</style>

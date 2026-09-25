<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { t } from '../i18n';

interface AdblockStats {
  enabled: boolean;
  list_count: number;
  total_rules: number;
  last_sync: string;
  lists: { name: string; url: string; category: string; enabled: boolean }[];
}

interface BlockEntry {
  timestamp: string;
  domain: string;
  category: string;
  source: string;
  action: string;
}

interface DomainCheckResult {
  blocked: boolean;
  category: string;
}

const stats = ref<AdblockStats>({
  enabled: false,
  list_count: 0,
  total_rules: 0,
  last_sync: '',
  lists: [],
});
const blockLog = ref<BlockEntry[]>([]);
const isLoading = ref(true);
const isSyncing = ref(false);
const isToggling = ref(false);
const checkDomainInput = ref('');
const checkResult = ref<DomainCheckResult | null>(null);
const isChecking = ref(false);
const newListUrl = ref('');
const errorMessage = ref('');

async function getAdblockStats(): Promise<AdblockStats> {
  return await invoke('get_adblock_stats');
}

async function enableAdblock(): Promise<void> {
  await invoke('adblock_enable');
}

async function disableAdblock(): Promise<void> {
  await invoke('adblock_disable');
}

async function syncAdblock(): Promise<void> {
  await invoke('adblock_sync');
}

async function checkDomain(domain: string): Promise<DomainCheckResult> {
  return await invoke('adblock_check', { domain });
}

async function getBlockLog(): Promise<BlockEntry[]> {
  return await invoke('get_adblock_log');
}

async function loadData() {
  isLoading.value = true;
  errorMessage.value = '';
  try {
    stats.value = await getAdblockStats();
    blockLog.value = await getBlockLog();
  } catch (e) {
    errorMessage.value = String(e);
  } finally {
    isLoading.value = false;
  }
}

async function handleToggle() {
  isToggling.value = true;
  errorMessage.value = '';
  try {
    if (stats.value.enabled) {
      await disableAdblock();
    } else {
      await enableAdblock();
    }
    stats.value = await getAdblockStats();
  } catch (e) {
    errorMessage.value = String(e);
  } finally {
    isToggling.value = false;
  }
}

async function handleSync() {
  isSyncing.value = true;
  errorMessage.value = '';
  try {
    await syncAdblock();
    stats.value = await getAdblockStats();
  } catch (e) {
    errorMessage.value = String(e);
  } finally {
    isSyncing.value = false;
  }
}

async function handleCheck() {
  const domain = checkDomainInput.value.trim();
  if (!domain) return;
  isChecking.value = true;
  checkResult.value = null;
  errorMessage.value = '';
  try {
    checkResult.value = await checkDomain(domain);
  } catch (e) {
    errorMessage.value = String(e);
  } finally {
    isChecking.value = false;
  }
}

function formatTimestamp(ts: string): string {
  if (!ts) return '-';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

onMounted(() => {
  loadData();
});
</script>

<template>
  <div class="adblock-settings">
    <div class="header-row">
      <h1 class="page-title">{{ t('adblock.title') }}</h1>
      <button class="btn btn-secondary" :disabled="isLoading" @click="loadData">
        {{ t('alerts.refresh') }}
      </button>
    </div>

    <!-- Error banner -->
    <div v-if="errorMessage" class="error-banner">
      {{ errorMessage }}
    </div>

    <!-- Toggle + Status -->
    <div class="panel status-panel">
      <div class="status-row">
        <div class="status-info">
          <div class="status-label" :class="stats.enabled ? 'status-enabled' : 'status-disabled'">
            {{ stats.enabled ? t('adblock.enabled') : t('adblock.disabled') }}
          </div>
          <div class="status-meta">
            <span>{{ t('adblock.rules') }}: {{ stats.total_rules.toLocaleString() }}</span>
            <span v-if="stats.last_sync">{{ t('adblock.last_sync') }}: {{ formatTimestamp(stats.last_sync) }}</span>
          </div>
        </div>
        <div class="status-actions">
          <button
            class="btn"
            :class="stats.enabled ? 'btn-danger' : 'btn-primary'"
            :disabled="isToggling"
            @click="handleToggle"
          >
            {{ stats.enabled ? t('adblock.disable') : t('adblock.enable') }}
          </button>
          <button
            class="btn btn-secondary"
            :disabled="isSyncing"
            @click="handleSync"
          >
            {{ isSyncing ? t('common.loading') : t('adblock.sync') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Filter Lists -->
    <div class="panel">
      <h2 class="panel-title">{{ t('adblock.lists') }}</h2>
      <div v-if="stats.lists.length > 0" class="list-table">
        <div v-for="(list, idx) in stats.lists" :key="idx" class="list-row">
          <div class="list-info">
            <span class="list-name">{{ list.name }}</span>
            <span class="list-category">[{{ list.category }}]</span>
          </div>
          <span class="list-url" :title="list.url">{{ list.url }}</span>
          <span class="list-status" :class="list.enabled ? 'status-on' : 'status-off'">
            {{ list.enabled ? t('adblock.enabled') : t('adblock.disabled') }}
          </span>
        </div>
      </div>
      <div v-else class="panel-empty">
        {{ t('adblock.lists') }}: 0
      </div>
    </div>

    <!-- Domain Check -->
    <div class="panel">
      <h2 class="panel-title">{{ t('adblock.check') }}</h2>
      <div class="check-row">
        <input
          v-model="checkDomainInput"
          type="text"
          class="input"
          :placeholder="t('adblock.check_placeholder')"
          @keyup.enter="handleCheck"
        />
        <button class="btn btn-secondary" :disabled="isChecking || !checkDomainInput.trim()" @click="handleCheck">
          {{ t('adblock.check') }}
        </button>
      </div>
      <div v-if="checkResult" class="check-result" :class="checkResult.blocked ? 'check-blocked' : 'check-allowed'">
        <span class="check-icon">{{ checkResult.blocked ? 'BLOCKED' : 'ALLOWED' }}</span>
        <span v-if="checkResult.blocked" class="check-category">[{{ checkResult.category }}]</span>
      </div>
    </div>

    <!-- Block Log -->
    <div class="panel">
      <h2 class="panel-title">{{ t('adblock.log') }}</h2>
      <div v-if="blockLog.length > 0" class="log-table">
        <div class="log-header">
          <span class="log-col-time">{{ t('alerts.col_time') }}</span>
          <span class="log-col-domain">Domain</span>
          <span class="log-col-category">Category</span>
          <span class="log-col-source">Source</span>
        </div>
        <div v-for="(entry, idx) in blockLog.slice(0, 20)" :key="idx" class="log-row">
          <span class="log-col-time">{{ formatTimestamp(entry.timestamp) }}</span>
          <span class="log-col-domain">{{ entry.domain }}</span>
          <span class="log-col-category">{{ entry.category }}</span>
          <span class="log-col-source">{{ entry.source }}</span>
        </div>
      </div>
      <div v-else class="panel-empty">
        No blocked entries yet.
      </div>
    </div>
  </div>
</template>

<style scoped>
.adblock-settings {
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

.error-banner {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid #ef4444;
  color: #ef4444;
  padding: 10px 16px;
  border-radius: 8px;
  margin-bottom: 16px;
  font-size: 13px;
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

.btn-primary {
  background: #6366f1;
  color: #fff;
}

.btn-primary:hover:not(:disabled) {
  background: #4f46e5;
}

.btn-secondary {
  background: rgba(99, 102, 241, 0.15);
  color: #6366f1;
  border: 1px solid #6366f1;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(99, 102, 241, 0.3);
}

.btn-danger {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
  border: 1px solid #ef4444;
}

.btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.3);
}

.panel {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 16px;
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

/* Status panel */
.status-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.status-info {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.status-label {
  font-size: 18px;
  font-weight: 700;
}

.status-enabled { color: #22c55e; }
.status-disabled { color: #999; }

.status-meta {
  display: flex;
  gap: 20px;
  font-size: 13px;
  color: #94a3b8;
}

.status-actions {
  display: flex;
  gap: 8px;
}

/* List table */
.list-table {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.list-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 6px;
  background: rgba(30, 30, 58, 0.3);
}

.list-info {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 180px;
}

.list-name {
  font-weight: 600;
  color: #e2e8f0;
  font-size: 13px;
}

.list-category {
  font-size: 11px;
  color: #94a3b8;
}

.list-url {
  flex: 1;
  font-size: 12px;
  font-family: monospace;
  color: #666;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.list-status {
  font-size: 12px;
  font-weight: 600;
}

.status-on { color: #22c55e; }
.status-off { color: #999; }

/* Domain check */
.check-row {
  display: flex;
  gap: 8px;
}

.input {
  flex: 1;
  padding: 10px 14px;
  background: #13131f;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 13px;
  font-family: system-ui, -apple-system, sans-serif;
  outline: none;
}

.input:focus {
  border-color: #6366f1;
}

.check-result {
  margin-top: 12px;
  padding: 10px 16px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 14px;
}

.check-blocked {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.check-allowed {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.check-category {
  font-weight: 400;
  font-size: 12px;
}

/* Block log */
.log-table {
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-height: 400px;
  overflow-y: auto;
}

.log-header {
  display: flex;
  gap: 8px;
  padding: 8px 12px;
  font-size: 11px;
  font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.log-row {
  display: flex;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 4px;
  background: rgba(30, 30, 58, 0.3);
  font-size: 12px;
  color: #ccc;
}

.log-col-time { width: 180px; flex-shrink: 0; }
.log-col-domain { flex: 1; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.log-col-category { width: 100px; flex-shrink: 0; }
.log-col-source { width: 120px; flex-shrink: 0; }
</style>

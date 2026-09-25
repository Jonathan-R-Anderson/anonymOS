<script setup lang="ts">
import { ref, computed } from 'vue';
import { state } from '../stores/app';
import { startMonitor, stopMonitor } from '../stores/tauri';
import { t } from '../i18n';

const newPath = ref('');
const eventLogRef = ref<HTMLElement | null>(null);

const threatEvents = computed(() =>
  state.monitorEvents.filter(e => e.threat_level && e.threat_level !== 'Clean').length
);

async function toggleMonitor() {
  if (state.isMonitoring) {
    try {
      await stopMonitor();
      state.isMonitoring = false;
    } catch (err) {
      console.error('Failed to stop monitor:', err);
    }
  } else {
    if (state.monitoredPaths.length === 0) return;
    try {
      await startMonitor(state.monitoredPaths);
      state.isMonitoring = true;
    } catch (err) {
      console.error('Failed to start monitor:', err);
    }
  }
}

function addPath() {
  const path = newPath.value.trim();
  if (!path || state.monitoredPaths.includes(path)) return;
  state.monitoredPaths.push(path);
  newPath.value = '';
}

function removePath(idx: number) {
  state.monitoredPaths.splice(idx, 1);
}

function clearEvents() {
  state.monitorEvents = [];
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString();
  } catch {
    return ts;
  }
}

function eventTypeColor(type: string): string {
  const map: Record<string, string> = {
    created: '#22c55e',
    modified: '#f59e0b',
    deleted: '#ef4444',
    renamed: '#818cf8',
    accessed: '#94a3b8',
  };
  return map[type.toLowerCase()] || '#94a3b8';
}

function isThreatEvent(event: { threat_level?: string }): boolean {
  return !!event.threat_level && event.threat_level !== 'Clean';
}
</script>

<template>
  <div class="monitor-page">
    <h1 class="page-title">{{ t('monitor.title') }}</h1>

    <div class="monitor-header">
      <div class="status-section">
        <button
          class="toggle-btn"
          :class="{ active: state.isMonitoring }"
          @click="toggleMonitor"
        >
          <span class="status-dot" :class="{ on: state.isMonitoring }"></span>
          {{ state.isMonitoring ? t('monitor.stop') : t('monitor.start') }}
        </button>
        <span v-if="state.isMonitoring" class="status-info">
          {{ t('monitor.watching') }} {{ state.monitoredPaths.length }} {{ t('monitor.paths_suffix') }}
        </span>
      </div>
      <div class="stats-row">
        <span class="stat">{{ t('monitor.events_count') }}: {{ state.monitorEvents.length }}</span>
        <span class="stat stat-threats" v-if="threatEvents > 0">{{ t('monitor.threats_count') }}: {{ threatEvents }}</span>
      </div>
    </div>

    <div class="paths-section">
      <h3 class="section-title">{{ t('monitor.paths') }}</h3>
      <div class="path-input-row">
        <input
          v-model="newPath"
          type="text"
          class="path-input"
          :placeholder="t('monitor.add_path')"
          :disabled="state.isMonitoring"
          @keyup.enter="addPath"
        />
        <button
          class="btn btn-add"
          :disabled="state.isMonitoring || !newPath.trim()"
          @click="addPath"
        >
          {{ t('monitor.add') }}
        </button>
      </div>
      <div v-if="state.monitoredPaths.length === 0" class="empty-paths">
        {{ t('monitor.no_paths') }}
      </div>
      <ul v-else class="path-list">
        <li v-for="(p, idx) in state.monitoredPaths" :key="idx" class="path-item">
          <span class="path-text">{{ p }}</span>
          <button
            class="btn-remove"
            :disabled="state.isMonitoring"
            @click="removePath(idx)"
          >
            &times;
          </button>
        </li>
      </ul>
    </div>

    <div class="events-section">
      <div class="events-header">
        <h3 class="section-title">{{ t('monitor.events') }}</h3>
        <button
          v-if="state.monitorEvents.length > 0"
          class="btn btn-small"
          @click="clearEvents"
        >
          {{ t('monitor.clear') }}
        </button>
      </div>
      <div ref="eventLogRef" class="event-log">
        <div v-if="state.monitorEvents.length === 0" class="empty-events">
          {{ t('monitor.no_events') }}
        </div>
        <div
          v-for="(event, idx) in state.monitorEvents"
          :key="idx"
          class="event-item"
          :class="{ 'event-threat': isThreatEvent(event) }"
        >
          <span class="event-time">{{ formatTime(event.timestamp) }}</span>
          <span
            class="event-type-badge"
            :style="{ color: eventTypeColor(event.event_type), borderColor: eventTypeColor(event.event_type) }"
          >
            {{ event.event_type }}
          </span>
          <span class="event-path">{{ event.path }}</span>
          <span v-if="isThreatEvent(event)" class="event-threat-label">
            {{ event.threat_level }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.monitor-page {
  max-width: 1000px;
  box-sizing: border-box;
}

.page-title {
  font-size: 24px;
  font-weight: 700;
  color: #e2e8f0;
  margin: 0 0 20px;
}

.monitor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  flex-wrap: wrap;
  gap: 12px;
}

.status-section {
  display: flex;
  align-items: center;
  gap: 16px;
}

.toggle-btn {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 20px;
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  color: #999;
  font-size: 14px;
  font-weight: 600;
  font-family: system-ui, -apple-system, sans-serif;
  cursor: pointer;
  transition: all 0.2s;
  box-sizing: border-box;
}

.toggle-btn:hover {
  border-color: #6366f1;
}

.toggle-btn.active {
  border-color: #6366f1;
  color: #6366f1;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #ef4444;
  transition: background 0.2s;
}

.status-dot.on {
  background: #22c55e;
  box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
}

.status-info {
  font-size: 13px;
  color: #666;
}

.stats-row {
  display: flex;
  gap: 16px;
}

.stat {
  font-size: 13px;
  color: #999;
}

.stat-threats {
  color: #ef4444;
  font-weight: 600;
}

.section-title {
  font-size: 16px;
  font-weight: 600;
  color: #ccc;
  margin: 0 0 12px;
}

.paths-section {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
}

.path-input-row {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}

.path-input {
  flex: 1;
  padding: 10px 14px;
  background: #13131f;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 13px;
  font-family: system-ui, -apple-system, sans-serif;
  box-sizing: border-box;
  outline: none;
  transition: border-color 0.2s;
}

.path-input:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.path-input:disabled {
  opacity: 0.5;
}

.btn {
  padding: 10px 18px;
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

.btn-add {
  background: #1e1e3a;
  color: #e2e8f0;
}

.btn-add:hover:not(:disabled) {
  background: #2a2a4a;
}

.btn-small {
  padding: 6px 14px;
  font-size: 12px;
  background: #1e1e3a;
  color: #999;
}

.btn-small:hover {
  color: #e2e8f0;
}

.empty-paths {
  color: #555;
  font-size: 13px;
  padding: 8px 0;
}

.path-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.path-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: #13131f;
  border-radius: 4px;
  font-size: 13px;
}

.path-text {
  font-family: monospace;
  color: #ccc;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.btn-remove {
  background: none;
  border: none;
  color: #666;
  font-size: 18px;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
  transition: color 0.2s;
}

.btn-remove:hover:not(:disabled) {
  color: #ef4444;
}

.btn-remove:disabled {
  opacity: 0.3;
  cursor: not-allowed;
}

.events-section {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  padding: 16px;
}

.events-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.event-log {
  max-height: 400px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.empty-events {
  color: #555;
  font-size: 13px;
  text-align: center;
  padding: 24px;
}

.event-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  background: #13131f;
  border-radius: 4px;
  font-size: 13px;
}

.event-item.event-threat {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.event-time {
  font-family: monospace;
  font-size: 12px;
  color: #666;
  white-space: nowrap;
}

.event-type-badge {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  padding: 2px 8px;
  border: 1px solid;
  border-radius: 3px;
  white-space: nowrap;
}

.event-path {
  flex: 1;
  font-family: monospace;
  font-size: 12px;
  color: #ccc;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.event-threat-label {
  color: #ef4444;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}
</style>

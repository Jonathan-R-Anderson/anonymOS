<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { scanPath } from '../stores/tauri';
import { t } from '../i18n';
import Badge from './Badge.vue';
import type { ScanResult } from '../types';

const isDragging = ref(false);
const isScanning = ref(false);
const scanResults = ref<ScanResult[]>([]);
const showResults = ref(false);
let dragCounter = 0;

function onDragEnter(e: DragEvent) {
  e.preventDefault();
  dragCounter++;
  isDragging.value = true;
}

function onDragOver(e: DragEvent) {
  e.preventDefault();
  if (e.dataTransfer) {
    e.dataTransfer.dropEffect = 'copy';
  }
}

function onDragLeave(e: DragEvent) {
  e.preventDefault();
  dragCounter--;
  if (dragCounter <= 0) {
    dragCounter = 0;
    isDragging.value = false;
  }
}

async function onDrop(e: DragEvent) {
  e.preventDefault();
  dragCounter = 0;
  isDragging.value = false;

  if (!e.dataTransfer) return;

  const files = e.dataTransfer.files;
  if (files.length === 0) return;

  isScanning.value = true;
  scanResults.value = [];
  showResults.value = true;

  const allResults: ScanResult[] = [];
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    // Tauri provides the full path via webkitRelativePath or the file path
    const path = (file as any).path || file.name;
    if (!path) continue;
    try {
      const results = await scanPath(path);
      allResults.push(...results);
    } catch (err) {
      console.error('Scan failed for', path, err);
    }
  }

  scanResults.value = allResults;
  isScanning.value = false;
}

function dismiss() {
  showResults.value = false;
  scanResults.value = [];
}

function truncatePath(path: string, maxLen = 50): string {
  if (path.length <= maxLen) return path;
  return '...' + path.slice(path.length - maxLen + 3);
}

onMounted(() => {
  document.addEventListener('dragenter', onDragEnter);
  document.addEventListener('dragover', onDragOver);
  document.addEventListener('dragleave', onDragLeave);
  document.addEventListener('drop', onDrop);
});

onUnmounted(() => {
  document.removeEventListener('dragenter', onDragEnter);
  document.removeEventListener('dragover', onDragOver);
  document.removeEventListener('dragleave', onDragLeave);
  document.removeEventListener('drop', onDrop);
});
</script>

<template>
  <Teleport to="body">
    <!-- Drag overlay -->
    <Transition name="fade">
      <div v-if="isDragging" class="drag-overlay">
        <div class="drop-zone">
          <div class="drop-icon">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="8" y="12" width="48" height="40" rx="4" stroke="#6366f1" stroke-width="2" stroke-dasharray="6 4" fill="none"/>
              <path d="M32 24v16M24 32h16" stroke="#6366f1" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
          <div class="drop-title">{{ t('dragdrop.title') }}</div>
          <div class="drop-subtitle">{{ t('dragdrop.subtitle') }}</div>
        </div>
      </div>
    </Transition>

    <!-- Results panel -->
    <Transition name="slide">
      <div v-if="showResults" class="results-panel">
        <div class="results-header">
          <h3 class="results-title">{{ t('dragdrop.results') }}</h3>
          <button class="btn-close" @click="dismiss">&times;</button>
        </div>
        <div v-if="isScanning" class="results-scanning">
          <div class="spinner"></div>
          <span>{{ t('scan.scanning') }}</span>
        </div>
        <div v-else-if="scanResults.length === 0" class="results-empty">
          {{ t('dragdrop.no_results') }}
        </div>
        <div v-else class="results-list">
          <div
            v-for="(result, idx) in scanResults"
            :key="idx"
            class="result-item"
            :class="{ 'result-threat': result.threat_level !== 'Clean' }"
          >
            <div class="result-path" :title="result.path">{{ truncatePath(result.path) }}</div>
            <Badge :level="result.threat_level" />
            <div v-if="result.threat_name" class="result-threat-name">{{ result.threat_name }}</div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.drag-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 15, 26, 0.92);
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
}

.drop-zone {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
  padding: 60px 80px;
  border: 2px dashed #6366f1;
  border-radius: 16px;
  background: rgba(99, 102, 241, 0.06);
}

.drop-icon {
  opacity: 0.8;
}

.drop-title {
  font-size: 22px;
  font-weight: 700;
  color: #e2e8f0;
}

.drop-subtitle {
  font-size: 14px;
  color: #94a3b8;
}

.results-panel {
  position: fixed;
  right: 24px;
  bottom: 24px;
  width: 420px;
  max-height: 480px;
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 12px;
  z-index: 9998;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  overflow: hidden;
}

.results-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid #1e1e3a;
}

.results-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: #e2e8f0;
}

.btn-close {
  background: none;
  border: none;
  color: #94a3b8;
  font-size: 22px;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
}

.btn-close:hover {
  color: #e2e8f0;
}

.results-scanning {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 24px 20px;
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

.results-empty {
  padding: 24px 20px;
  color: #94a3b8;
  font-size: 14px;
  text-align: center;
}

.results-list {
  overflow-y: auto;
  padding: 8px 12px;
  flex: 1;
}

.result-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 8px;
  border-bottom: 1px solid rgba(30, 30, 58, 0.5);
}

.result-item:last-child {
  border-bottom: none;
}

.result-threat {
  background: rgba(99, 102, 241, 0.05);
}

.result-path {
  flex: 1;
  font-family: monospace;
  font-size: 12px;
  color: #ccc;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.result-threat-name {
  font-size: 11px;
  color: #ef4444;
  white-space: nowrap;
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.slide-enter-active,
.slide-leave-active {
  transition: transform 0.3s ease, opacity 0.3s ease;
}
.slide-enter-from,
.slide-leave-to {
  transform: translateY(20px);
  opacity: 0;
}
</style>

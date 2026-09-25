<script setup lang="ts">
import { ref, computed } from 'vue';
import { state } from '../stores/app';
import { updateConfig, updateSignatures, getEngineInfo } from '../stores/tauri';
import { t, setLocale, getLocale, locales } from '../i18n';

const activeTab = ref('general');
const newExcludePath = ref('');
const saving = ref(false);
const updating = ref(false);
const saveMessage = ref('');
const currentLang = ref(getLocale());

const tabKeys = ['general', 'scan', 'update', 'about'] as const;

const maxFileSizeMB = computed({
  get: () => Math.round(state.config.max_file_size / 1048576),
  set: (val: number) => { state.config.max_file_size = val * 1048576; },
});

function changeLang() {
  setLocale(currentLang.value as any);
}

function addExcludePath() {
  const path = newExcludePath.value.trim();
  if (!path || state.config.exclude_paths.includes(path)) return;
  state.config.exclude_paths.push(path);
  newExcludePath.value = '';
}

function removeExcludePath(idx: number) {
  state.config.exclude_paths.splice(idx, 1);
}

async function saveConfig() {
  saving.value = true;
  saveMessage.value = '';
  try {
    await updateConfig(state.config);
    saveMessage.value = t('settings.save_success');
  } catch (err) {
    saveMessage.value = t('settings.save_fail');
    console.error('Save config failed:', err);
  } finally {
    saving.value = false;
    setTimeout(() => { saveMessage.value = ''; }, 3000);
  }
}

async function checkUpdates() {
  updating.value = true;
  try {
    await updateSignatures();
    state.engineInfo = await getEngineInfo();
  } catch (err) {
    console.error('Update failed:', err);
  } finally {
    updating.value = false;
  }
}
</script>

<template>
  <div class="settings-page">
    <h1 class="page-title">{{ t('settings.title') }}</h1>

    <div class="tabs">
      <button
        v-for="key in tabKeys"
        :key="key"
        class="tab-btn"
        :class="{ active: activeTab === key }"
        @click="activeTab = key"
      >
        {{ t('settings.' + key) }}
      </button>
    </div>

    <!-- General -->
    <div v-if="activeTab === 'general'" class="tab-content">
      <div class="setting-group">
        <h3 class="group-title">{{ t('settings.application') }}</h3>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.language') }}</label>
          <select v-model="currentLang" @change="changeLang" class="lang-select">
            <option v-for="l in locales" :key="l.code" :value="l.code">{{ l.name }}</option>
          </select>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.data_dir') }}</label>
          <div class="setting-value mono">~/.prx-sd/</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.theme') }}</label>
          <div class="setting-value">{{ t('settings.theme_value') }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.log_level') }}</label>
          <div class="setting-value">Info</div>
        </div>
      </div>
    </div>

    <!-- Scan -->
    <div v-if="activeTab === 'scan'" class="tab-content">
      <div class="setting-group">
        <h3 class="group-title">{{ t('settings.file_scanning') }}</h3>

        <div class="setting-row">
          <label class="setting-label">
            {{ t('settings.max_file_size') }}
            <span class="setting-hint">{{ maxFileSizeMB }} MB</span>
          </label>
          <input
            type="range"
            v-model.number="maxFileSizeMB"
            min="1"
            max="500"
            step="1"
            class="slider"
          />
        </div>

        <div class="setting-row">
          <label class="setting-label">{{ t('settings.scan_threads') }}</label>
          <input
            type="number"
            v-model.number="state.config.scan_threads"
            min="1"
            max="32"
            class="input-number"
          />
        </div>

        <div class="setting-row">
          <label class="setting-label">
            {{ t('settings.heuristic_threshold') }}
            <span class="setting-hint">{{ state.config.heuristic_threshold }}%</span>
          </label>
          <input
            type="range"
            v-model.number="state.config.heuristic_threshold"
            min="0"
            max="100"
            step="5"
            class="slider"
          />
        </div>

        <div class="setting-row">
          <label class="setting-label">{{ t('settings.scan_archives') }}</label>
          <label class="toggle">
            <input type="checkbox" v-model="state.config.scan_archives" />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="setting-row" v-if="state.config.scan_archives">
          <label class="setting-label">{{ t('settings.archive_depth') }}</label>
          <input
            type="number"
            v-model.number="state.config.max_archive_depth"
            min="1"
            max="10"
            class="input-number"
          />
        </div>
      </div>

      <div class="setting-group">
        <h3 class="group-title">{{ t('settings.exclude_paths') }}</h3>
        <div class="exclude-input-row">
          <input
            v-model="newExcludePath"
            type="text"
            class="text-input"
            :placeholder="t('settings.add_path')"
            @keyup.enter="addExcludePath"
          />
          <button class="btn btn-add" @click="addExcludePath" :disabled="!newExcludePath.trim()">
            {{ t('settings.add') }}
          </button>
        </div>
        <div v-if="state.config.exclude_paths.length === 0" class="empty-list">
          {{ t('settings.no_excludes') }}
        </div>
        <ul v-else class="exclude-list">
          <li v-for="(p, idx) in state.config.exclude_paths" :key="idx" class="exclude-item">
            <span class="exclude-path">{{ p }}</span>
            <button class="btn-remove" @click="removeExcludePath(idx)">&times;</button>
          </li>
        </ul>
      </div>

      <div class="save-row">
        <button class="btn btn-primary" @click="saveConfig" :disabled="saving">
          {{ saving ? t('settings.saving') : t('settings.save') }}
        </button>
        <span v-if="saveMessage" class="save-msg">{{ saveMessage }}</span>
      </div>
    </div>

    <!-- Update -->
    <div v-if="activeTab === 'update'" class="tab-content">
      <div class="setting-group">
        <h3 class="group-title">{{ t('settings.sig_database') }}</h3>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.sig_version') }}</label>
          <div class="setting-value">{{ state.engineInfo.signature_version }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.hash_signatures') }}</label>
          <div class="setting-value">{{ state.engineInfo.hash_count.toLocaleString() }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.yara_rules') }}</label>
          <div class="setting-value">{{ state.engineInfo.yara_rule_count.toLocaleString() }}</div>
        </div>
        <div class="update-action">
          <button class="btn btn-primary" @click="checkUpdates" :disabled="updating">
            {{ updating ? t('settings.updating') : t('settings.check_updates') }}
          </button>
        </div>
      </div>
    </div>

    <!-- About -->
    <div v-if="activeTab === 'about'" class="tab-content">
      <div class="setting-group">
        <h3 class="group-title">{{ t('settings.about_engine') }}</h3>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.about_version') }}</label>
          <div class="setting-value">{{ state.engineInfo.version }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.about_sig_version') }}</label>
          <div class="setting-value">{{ state.engineInfo.signature_version }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.hash_signatures') }}</label>
          <div class="setting-value">{{ state.engineInfo.hash_count.toLocaleString() }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.yara_rules') }}</label>
          <div class="setting-value">{{ state.engineInfo.yara_rule_count.toLocaleString() }}</div>
        </div>
        <div class="setting-row">
          <label class="setting-label">{{ t('settings.about_quarantined') }}</label>
          <div class="setting-value">{{ state.engineInfo.quarantine_count }}</div>
        </div>
      </div>
      <div class="about-footer">
        <p class="about-desc">
          {{ t('settings.about_desc') }}
        </p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  max-width: 700px;
  box-sizing: border-box;
}

.page-title {
  font-size: 24px;
  font-weight: 700;
  color: #e2e8f0;
  margin: 0 0 20px;
}

.tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 20px;
  border-bottom: 1px solid #1e1e3a;
  padding-bottom: 0;
}

.tab-btn {
  padding: 10px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #999;
  font-size: 14px;
  font-weight: 500;
  font-family: system-ui, -apple-system, sans-serif;
  cursor: pointer;
  transition: all 0.2s;
  margin-bottom: -1px;
}

.tab-btn:hover {
  color: #e2e8f0;
}

.tab-btn.active {
  color: #6366f1;
  border-bottom-color: #6366f1;
}

.tab-content {
  animation: fadeIn 0.15s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}

.setting-group {
  background: #1a1a2f;
  border: 1px solid #1e1e3a;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 16px;
}

.group-title {
  font-size: 15px;
  font-weight: 600;
  color: #ccc;
  margin: 0 0 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid #1e1e3a;
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid rgba(15, 52, 96, 0.3);
}

.setting-row:last-child {
  border-bottom: none;
}

.setting-label {
  font-size: 14px;
  color: #ccc;
  display: flex;
  align-items: center;
  gap: 10px;
}

.setting-hint {
  font-size: 12px;
  color: #6366f1;
  font-weight: 600;
}

.setting-value {
  font-size: 14px;
  color: #999;
}

.setting-value.mono {
  font-family: monospace;
  font-size: 13px;
}

.lang-select {
  padding: 8px 12px;
  background: #1a1a2e;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 14px;
  font-family: system-ui, -apple-system, sans-serif;
  outline: none;
  cursor: pointer;
  box-sizing: border-box;
  transition: border-color 0.2s;
}

.lang-select:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.lang-select option {
  background: #1a1a2e;
  color: #e2e8f0;
}

.slider {
  width: 200px;
  accent-color: #6366f1;
  cursor: pointer;
}

.input-number {
  width: 80px;
  padding: 8px 12px;
  background: #1a1a2e;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 14px;
  font-family: system-ui, -apple-system, sans-serif;
  text-align: center;
  outline: none;
  box-sizing: border-box;
}

.input-number:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.toggle {
  position: relative;
  display: inline-block;
  width: 44px;
  height: 24px;
  cursor: pointer;
}

.toggle input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: #1e1e3a;
  border-radius: 24px;
  transition: background 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  left: 3px;
  bottom: 3px;
  background: #999;
  border-radius: 50%;
  transition: all 0.2s;
}

.toggle input:checked + .toggle-slider {
  background: rgba(99, 102, 241, 0.3);
}

.toggle input:checked + .toggle-slider::before {
  transform: translateX(20px);
  background: #6366f1;
}

.exclude-input-row {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}

.text-input {
  flex: 1;
  padding: 10px 14px;
  background: #1a1a2e;
  border: 1px solid #1e1e3a;
  border-radius: 4px;
  color: #e2e8f0;
  font-size: 13px;
  font-family: system-ui, -apple-system, sans-serif;
  outline: none;
  box-sizing: border-box;
  transition: border-color 0.2s;
}

.text-input:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
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

.btn-primary {
  background: #6366f1;
  color: #fff;
}

.btn-primary:hover:not(:disabled) {
  background: #4f46e5;
}

.btn-add {
  background: #1e1e3a;
  color: #ccc;
}

.btn-add:hover:not(:disabled) {
  background: #2a2a4a;
  color: #e2e8f0;
}

.empty-list {
  color: #555;
  font-size: 13px;
  padding: 8px 0;
}

.exclude-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.exclude-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: #1a1a2e;
  border-radius: 4px;
}

.exclude-path {
  font-family: monospace;
  font-size: 13px;
  color: #ccc;
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

.btn-remove:hover {
  color: #ef4444;
}

.save-row {
  display: flex;
  align-items: center;
  gap: 16px;
}

.save-msg {
  font-size: 13px;
  color: #22c55e;
}

.update-action {
  margin-top: 16px;
}

.about-footer {
  padding: 4px 0;
}

.about-desc {
  font-size: 13px;
  color: #666;
  line-height: 1.6;
}
</style>

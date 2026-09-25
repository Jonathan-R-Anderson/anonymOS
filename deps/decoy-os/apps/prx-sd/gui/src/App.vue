<script setup lang="ts">
import { computed, markRaw, onMounted } from 'vue';
import { state } from './stores/app';
import { getEngineInfo, getConfig, getQuarantineList } from './stores/tauri';
import { t } from './i18n';
import NavItem from './components/NavItem.vue';
import DragDropScan from './components/DragDropScan.vue';
import Dashboard from './components/Dashboard.vue';
import AlertHistory from './components/AlertHistory.vue';
import AdblockSettings from './components/AdblockSettings.vue';
import ScanPage from './pages/ScanPage.vue';
import MonitorPage from './pages/MonitorPage.vue';
import QuarantinePage from './pages/QuarantinePage.vue';
import SettingsPage from './pages/SettingsPage.vue';

const pageKeys = ['dashboard', 'scan', 'monitor', 'quarantine', 'adblock', 'alerts', 'settings'] as const;
const pageComponents: Record<string, any> = {
  dashboard: markRaw(Dashboard),
  scan: markRaw(ScanPage),
  monitor: markRaw(MonitorPage),
  quarantine: markRaw(QuarantinePage),
  adblock: markRaw(AdblockSettings),
  alerts: markRaw(AlertHistory),
  settings: markRaw(SettingsPage),
};
const pageIcons: Record<string, string> = {
  dashboard: '📊',
  scan: '🔍',
  monitor: '👁',
  quarantine: '🔒',
  adblock: '🛡',
  alerts: '🔔',
  settings: '⚙',
};

const currentComponent = computed(() => pageComponents[state.currentPage] || Dashboard);

const threatCount = computed(() =>
  state.scanResults.filter(r => r.threat_level !== 'Clean').length
);

const quarantineCount = computed(() => state.quarantineEntries.length);

onMounted(async () => {
  try {
    state.engineInfo = await getEngineInfo();
  } catch { /* backend not ready */ }
  try {
    state.config = await getConfig();
  } catch { /* backend not ready */ }
  try {
    state.quarantineEntries = await getQuarantineList();
  } catch { /* backend not ready */ }
});
</script>

<template>
  <div class="app-layout">
    <aside class="sidebar">
      <div class="sidebar-header">
        <div class="logo">
          <span class="logo-icon">
            <svg width="28" height="28" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
              <polygon points="16,1 28.5,8.5 28.5,23.5 16,31 3.5,23.5 3.5,8.5" stroke="#6366f1" stroke-width="2" fill="none"/>
              <circle cx="16" cy="1" r="2" fill="#6366f1"/>
              <circle cx="28.5" cy="8.5" r="2" fill="#6366f1"/>
              <circle cx="28.5" cy="23.5" r="2" fill="#6366f1"/>
              <circle cx="16" cy="31" r="2" fill="#6366f1"/>
              <circle cx="3.5" cy="23.5" r="2" fill="#6366f1"/>
              <circle cx="3.5" cy="8.5" r="2" fill="#6366f1"/>
              <text x="16" y="18.5" text-anchor="middle" fill="#6366f1" font-size="8" font-weight="700" font-family="system-ui, sans-serif">PRX</text>
            </svg>
          </span>
          <span class="logo-text">{{ t('app.title') }}</span>
        </div>
        <div class="logo-subtitle">{{ t('app.subtitle') }}</div>
      </div>

      <nav class="sidebar-nav">
        <NavItem
          v-for="key in pageKeys"
          :key="key"
          :icon="pageIcons[key]"
          :label="t('nav.' + key)"
          :active="state.currentPage === key"
          :badge="key === 'scan' ? threatCount : key === 'quarantine' ? quarantineCount : undefined"
          @click="state.currentPage = key"
        />
      </nav>

      <div class="sidebar-footer">
        <div class="engine-version">v{{ state.engineInfo.version }}</div>
        <div class="sig-version">{{ t('app.version') }}: {{ state.engineInfo.signature_version }}</div>
      </div>
    </aside>

    <main class="content">
      <component :is="currentComponent" />
    </main>

    <DragDropScan />
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  width: 100vw;
  height: 100vh;
  background: #13131f;
  color: #e2e8f0;
  font-family: system-ui, -apple-system, sans-serif;
  box-sizing: border-box;
  overflow: hidden;
}

.sidebar {
  width: 220px;
  min-width: 220px;
  background: #0f0f1a;
  display: flex;
  flex-direction: column;
  border-right: 1px solid #1e1e3a;
  box-sizing: border-box;
}

.sidebar-header {
  padding: 24px 16px 16px;
  border-bottom: 1px solid #1e1e3a;
}

.logo {
  display: flex;
  align-items: center;
  gap: 10px;
}

.logo-icon {
  font-size: 28px;
  display: flex;
  align-items: center;
}

.logo-text {
  font-size: 22px;
  font-weight: 700;
  color: #6366f1;
  letter-spacing: 1px;
}

.logo-subtitle {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 4px;
  padding-left: 40px;
}

.sidebar-nav {
  flex: 1;
  padding: 12px 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid #1e1e3a;
  text-align: center;
}

.engine-version {
  font-size: 12px;
  color: #94a3b8;
}

.sig-version {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 2px;
}

.content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  box-sizing: border-box;
}
</style>

<script setup lang="ts">
import { t } from '../i18n';

const props = defineProps<{
  level: 'Clean' | 'Suspicious' | 'Malicious' | string;
}>();

const colorMap: Record<string, { bg: string; text: string }> = {
  Clean: { bg: 'rgba(34, 197, 94, 0.15)', text: '#22c55e' },
  Suspicious: { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b' },
  Malicious: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444' },
};

const labelMap: Record<string, string> = {
  Clean: 'badge.clean',
  Suspicious: 'badge.suspicious',
  Malicious: 'badge.malicious',
};

function getColors() {
  return colorMap[props.level] || { bg: 'rgba(153, 153, 153, 0.15)', text: '#999' };
}

function getLabel(): string {
  const key = labelMap[props.level];
  return key ? t(key) : props.level;
}
</script>

<template>
  <span
    class="badge"
    :style="{
      background: getColors().bg,
      color: getColors().text,
      borderColor: getColors().text,
    }"
  >
    {{ getLabel() }}
  </span>
</template>

<style scoped>
.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  font-family: system-ui, -apple-system, sans-serif;
  border: 1px solid;
  white-space: nowrap;
  line-height: 1.4;
}
</style>

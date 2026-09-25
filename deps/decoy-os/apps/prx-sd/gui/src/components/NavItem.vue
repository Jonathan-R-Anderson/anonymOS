<script setup lang="ts">
defineProps<{
  icon: string;
  label: string;
  active?: boolean;
  badge?: number;
}>();

defineEmits<{
  click: [];
}>();
</script>

<template>
  <button
    class="nav-item"
    :class="{ active }"
    @click="$emit('click')"
  >
    <span class="nav-icon">{{ icon }}</span>
    <span class="nav-label">{{ label }}</span>
    <span v-if="badge && badge > 0" class="nav-badge">{{ badge > 99 ? '99+' : badge }}</span>
  </button>
</template>

<style scoped>
.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 12px 16px;
  border: none;
  background: transparent;
  color: #999;
  font-size: 14px;
  font-family: system-ui, -apple-system, sans-serif;
  cursor: pointer;
  border-radius: 8px;
  transition: all 0.2s ease;
  position: relative;
  box-sizing: border-box;
  text-align: left;
}

.nav-item:hover {
  background: rgba(99, 102, 241, 0.08);
  color: #e2e8f0;
}

.nav-item.active {
  background: rgba(99, 102, 241, 0.12);
  color: #6366f1;
}

.nav-item.active .nav-icon {
  color: #6366f1;
}

.nav-icon {
  font-size: 18px;
  width: 24px;
  text-align: center;
  flex-shrink: 0;
}

.nav-label {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-badge {
  background: #6366f1;
  color: #fff;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 10px;
  min-width: 18px;
  text-align: center;
  line-height: 1.3;
}
</style>

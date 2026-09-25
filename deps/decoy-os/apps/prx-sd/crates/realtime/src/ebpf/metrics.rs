//! eBPF runtime metrics and health reporting.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for eBPF runtime health monitoring.
#[derive(Debug, Default)]
pub struct EbpfMetrics {
    pub events_total: AtomicU64,
    pub events_exec: AtomicU64,
    pub events_file_open: AtomicU64,
    pub events_connect: AtomicU64,
    pub events_exit: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_decode_errors: AtomicU64,
    pub ringbuf_poll_errors: AtomicU64,
    pub bpf_ringbuf_drops: AtomicU64,
    pub correlation_alerts: AtomicU64,
    pub process_cache_size: AtomicU64,
    pub policy_matches: AtomicU64,
    pub actions_dispatched: AtomicU64,
    pub actions_dropped: AtomicU64,
}

impl EbpfMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_event(&self, kind: super::RuntimeEventKind) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        match kind {
            super::RuntimeEventKind::Exec => {
                self.events_exec.fetch_add(1, Ordering::Relaxed);
            }
            super::RuntimeEventKind::FileOpen => {
                self.events_file_open.fetch_add(1, Ordering::Relaxed);
            }
            super::RuntimeEventKind::Connect => {
                self.events_connect.fetch_add(1, Ordering::Relaxed);
            }
            super::RuntimeEventKind::Exit => {
                self.events_exit.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn inc_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_decode_error(&self) {
        self.events_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_poll_error(&self) {
        self.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the kernel-side BPF ring buffer drop count (read from per-CPU map).
    pub fn set_bpf_drops(&self, drops: u64) {
        self.bpf_ringbuf_drops.store(drops, Ordering::Relaxed);
    }

    pub fn inc_correlation_alerts(&self, count: u64) {
        self.correlation_alerts.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_cache_size(&self, size: u64) {
        self.process_cache_size.store(size, Ordering::Relaxed);
    }

    pub fn inc_policy_matches(&self) {
        self.policy_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_actions_dispatched(&self) {
        self.actions_dispatched.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_actions_dropped(&self) {
        self.actions_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the current metrics for display.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_total: self.events_total.load(Ordering::Relaxed),
            events_exec: self.events_exec.load(Ordering::Relaxed),
            events_file_open: self.events_file_open.load(Ordering::Relaxed),
            events_connect: self.events_connect.load(Ordering::Relaxed),
            events_exit: self.events_exit.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            events_decode_errors: self.events_decode_errors.load(Ordering::Relaxed),
            ringbuf_poll_errors: self.ringbuf_poll_errors.load(Ordering::Relaxed),
            bpf_ringbuf_drops: self.bpf_ringbuf_drops.load(Ordering::Relaxed),
            correlation_alerts: self.correlation_alerts.load(Ordering::Relaxed),
            process_cache_size: self.process_cache_size.load(Ordering::Relaxed),
            policy_matches: self.policy_matches.load(Ordering::Relaxed),
            actions_dispatched: self.actions_dispatched.load(Ordering::Relaxed),
            actions_dropped: self.actions_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Immutable snapshot of metrics for reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub events_total: u64,
    pub events_exec: u64,
    pub events_file_open: u64,
    pub events_connect: u64,
    pub events_exit: u64,
    pub events_dropped: u64,
    pub events_decode_errors: u64,
    pub ringbuf_poll_errors: u64,
    pub bpf_ringbuf_drops: u64,
    pub correlation_alerts: u64,
    pub process_cache_size: u64,
    pub policy_matches: u64,
    pub actions_dispatched: u64,
    pub actions_dropped: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::events::RuntimeEventKind;
    use super::*;

    #[test]
    fn test_metrics_inc_event() {
        let m = EbpfMetrics::new();
        m.inc_event(RuntimeEventKind::Exec);
        m.inc_event(RuntimeEventKind::Exec);
        m.inc_event(RuntimeEventKind::FileOpen);
        m.inc_event(RuntimeEventKind::Connect);
        m.inc_event(RuntimeEventKind::Exit);

        let s = m.snapshot();
        assert_eq!(s.events_total, 5);
        assert_eq!(s.events_exec, 2);
        assert_eq!(s.events_file_open, 1);
        assert_eq!(s.events_connect, 1);
        assert_eq!(s.events_exit, 1);
    }

    #[test]
    fn test_metrics_dropped_and_errors() {
        let m = EbpfMetrics::new();
        m.inc_dropped();
        m.inc_dropped();
        m.inc_decode_error();
        m.inc_poll_error();
        m.inc_poll_error();
        m.inc_poll_error();

        let s = m.snapshot();
        assert_eq!(s.events_dropped, 2);
        assert_eq!(s.events_decode_errors, 1);
        assert_eq!(s.ringbuf_poll_errors, 3);
    }

    #[test]
    fn test_metrics_bpf_drops_and_cache() {
        let m = EbpfMetrics::new();
        m.set_bpf_drops(42);
        m.set_cache_size(10);
        m.inc_correlation_alerts(3);

        let s = m.snapshot();
        assert_eq!(s.bpf_ringbuf_drops, 42);
        assert_eq!(s.process_cache_size, 10);
        assert_eq!(s.correlation_alerts, 3);
    }

    #[test]
    fn test_metrics_snapshot_display() {
        let m = EbpfMetrics::new();
        m.inc_event(RuntimeEventKind::Exec);
        m.set_bpf_drops(5);
        let s = m.snapshot();
        let display = format!("{s}");
        assert!(display.contains("events total:"));
        assert!(display.contains("bpf ringbuf drops:"));
        assert!(display.contains("5"));
    }
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "eBPF Runtime Metrics:")?;
        writeln!(f, "  events total:    {}", self.events_total)?;
        writeln!(f, "    exec:          {}", self.events_exec)?;
        writeln!(f, "    file_open:     {}", self.events_file_open)?;
        writeln!(f, "    connect:       {}", self.events_connect)?;
        writeln!(f, "    exit:          {}", self.events_exit)?;
        writeln!(f, "  dropped:         {}", self.events_dropped)?;
        writeln!(f, "  decode errors:   {}", self.events_decode_errors)?;
        writeln!(f, "  poll errors:     {}", self.ringbuf_poll_errors)?;
        writeln!(f, "  bpf ringbuf drops: {}", self.bpf_ringbuf_drops)?;
        writeln!(f, "  alerts fired:    {}", self.correlation_alerts)?;
        writeln!(f, "  policy matches:  {}", self.policy_matches)?;
        writeln!(f, "  actions sent:    {}", self.actions_dispatched)?;
        writeln!(f, "  actions dropped: {}", self.actions_dropped)?;
        writeln!(f, "  process cache:   {}", self.process_cache_size)?;
        Ok(())
    }
}

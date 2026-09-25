//! High-level eBPF event processing pipeline.
//!
//! [`EbpfPipeline`] composes the low-level [`EbpfRuntime`] with the
//! [`ProcessCache`], [`Correlator`], [`PolicyEngine`], and [`ActionSender`]
//! to provide a single entry point that emits raw events, correlation
//! alerts, and policy matches.

use super::actions::{ActionDispatcher, ActionExecutor, ActionSender, DispatcherConfig};
use super::correlate::{AlertRule, CorrelationAlert, Correlator};
use super::events::RuntimeEvent;
use super::loader::EbpfRuntime;
use super::metrics::EbpfMetrics;
use super::policy::{PolicyEngine, PolicyMatch};
use super::state::ProcessCache;
use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Default cooldown period for correlation alerts (same rule + pid).
const ALERT_COOLDOWN: Duration = Duration::from_secs(60);

/// Unified output from the eBPF pipeline.
#[derive(Debug, Clone)]
pub enum PipelineOutput {
    /// A raw runtime event from the kernel.
    Event(RuntimeEvent),
    /// A correlation alert derived from event patterns.
    Alert(CorrelationAlert),
    /// A policy match from the policy engine.
    Policy(PolicyMatch),
}

impl std::fmt::Display for PipelineOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Event(e) => write!(f, "{e}"),
            Self::Alert(a) => write!(f, "{a}"),
            Self::Policy(p) => write!(f, "{p}"),
        }
    }
}

/// Configuration for the policy layer of the pipeline.
pub struct PolicyConfig {
    /// The policy engine with loaded rules.
    pub engine: PolicyEngine,
    /// The action executor implementation.
    pub executor: Arc<dyn ActionExecutor>,
    /// Action dispatcher configuration.
    pub dispatcher_config: DispatcherConfig,
}

/// High-level eBPF pipeline that combines event collection, process state
/// tracking, correlation analysis, and policy-driven response.
pub struct EbpfPipeline {
    runtime: EbpfRuntime,
    cache: ProcessCache,
    metrics: Arc<EbpfMetrics>,
}

impl EbpfPipeline {
    /// Start the pipeline without policy enforcement.
    ///
    /// Events are collected, correlated, and forwarded but no actions
    /// are dispatched. Use [`start_with_policy`](Self::start_with_policy)
    /// for full policy-driven response.
    pub fn start(buffer_size: usize) -> Result<(Self, mpsc::Receiver<PipelineOutput>)> {
        let (runtime, raw_rx) = EbpfRuntime::start(buffer_size).context("failed to start eBPF runtime")?;

        let cache = ProcessCache::new();
        let metrics = runtime.metrics().clone();
        let (out_tx, out_rx) = mpsc::channel(buffer_size);

        let process_cache = cache.handle();
        let correlator = Correlator::new(cache.handle());
        let cooldown = Arc::new(AlertCooldown::new(ALERT_COOLDOWN));
        let metrics_clone = Arc::clone(&metrics);

        tokio::spawn(async move {
            pipeline_loop(
                raw_rx,
                out_tx,
                process_cache,
                correlator,
                cooldown,
                None,
                None,
                metrics_clone,
            )
            .await;
        });

        spawn_eviction(cache.handle(), Arc::clone(&metrics));

        Ok((
            Self {
                runtime,
                cache,
                metrics,
            },
            out_rx,
        ))
    }

    /// Start the pipeline with policy enforcement and action dispatching.
    ///
    /// In addition to event collection and correlation, the pipeline
    /// evaluates each event against the policy engine and dispatches
    /// matched actions via the [`ActionExecutor`].
    pub fn start_with_policy(
        buffer_size: usize,
        policy: PolicyConfig,
    ) -> Result<(Self, mpsc::Receiver<PipelineOutput>)> {
        let (runtime, raw_rx) = EbpfRuntime::start(buffer_size).context("failed to start eBPF runtime")?;

        let cache = ProcessCache::new();
        let metrics = runtime.metrics().clone();
        let (out_tx, out_rx) = mpsc::channel(buffer_size);

        // Create action dispatcher.
        let (action_sender, action_dispatcher) =
            ActionDispatcher::new(policy.executor, Arc::clone(&metrics), policy.dispatcher_config);

        // Spawn action dispatcher loop.
        tokio::spawn(action_dispatcher.run());

        let process_cache = cache.handle();
        let correlator = Correlator::new(cache.handle());
        let cooldown = Arc::new(AlertCooldown::new(ALERT_COOLDOWN));
        let metrics_clone = Arc::clone(&metrics);

        tokio::spawn(async move {
            pipeline_loop(
                raw_rx,
                out_tx,
                process_cache,
                correlator,
                cooldown,
                Some(policy.engine),
                Some(action_sender),
                metrics_clone,
            )
            .await;
        });

        spawn_eviction(cache.handle(), Arc::clone(&metrics));

        Ok((
            Self {
                runtime,
                cache,
                metrics,
            },
            out_rx,
        ))
    }

    /// Get a reference to the shared metrics.
    pub fn metrics(&self) -> &Arc<EbpfMetrics> {
        &self.metrics
    }

    /// Get a reference to the process cache.
    pub fn cache(&self) -> &ProcessCache {
        &self.cache
    }

    /// Stop the pipeline and clean up.
    pub fn stop(&mut self) {
        self.runtime.stop();
    }
}

impl Drop for EbpfPipeline {
    fn drop(&mut self) {
        self.stop();
    }
}

// ── Alert cooldown ─────────────────────────────────────────────────────

/// Deduplicates correlation alerts by (rule, pid) within a cooldown window.
struct AlertCooldown {
    entries: Mutex<HashMap<(AlertRule, u32), Instant>>,
    window: Duration,
}

impl AlertCooldown {
    fn new(window: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Returns `true` if the alert should be forwarded (not in cooldown).
    fn should_forward(&self, rule: AlertRule, pid: u32) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let key = (rule, pid);

        if let Some(last) = entries.get(&key) {
            if now.duration_since(*last) < self.window {
                return false;
            }
        }

        entries.insert(key, now);
        true
    }

    /// Evict expired entries.
    fn evict(&self) {
        let now = Instant::now();
        let window = self.window;
        let mut entries = self.entries.lock();
        entries.retain(|_, last| now.duration_since(*last) < window);
    }
}

// ── Pipeline loop ──────────────────────────────────────────────────────

/// Main processing loop: read events → update cache → correlate → policy → output.
#[allow(clippy::too_many_arguments)]
async fn pipeline_loop(
    mut raw_rx: mpsc::Receiver<RuntimeEvent>,
    out_tx: mpsc::Sender<PipelineOutput>,
    cache: ProcessCache,
    correlator: Correlator,
    cooldown: Arc<AlertCooldown>,
    policy_engine: Option<PolicyEngine>,
    action_sender: Option<ActionSender>,
    metrics: Arc<EbpfMetrics>,
) {
    let mut cooldown_evict_counter: u64 = 0;

    while let Some(event) = raw_rx.recv().await {
        // 1. Update process state.
        cache.on_event(&event);

        // 2. Run correlation checks + cooldown dedup.
        let raw_alerts = correlator.check(&event);
        let mut alerts = Vec::new();
        for alert in raw_alerts {
            if cooldown.should_forward(alert.rule, alert.pid) {
                alerts.push(alert);
            }
        }

        if !alerts.is_empty() {
            #[allow(clippy::cast_possible_truncation)]
            metrics.inc_correlation_alerts(alerts.len() as u64);
        }

        // 3. Run policy evaluation.
        let policy_matches = if let Some(ref engine) = policy_engine {
            engine.evaluate(&event)
        } else {
            Vec::new()
        };

        // 4. Dispatch actions for policy matches.
        if let Some(ref sender) = action_sender {
            for m in &policy_matches {
                sender.send_match(m);
            }
        }

        // 5. Forward raw event.
        if out_tx.send(PipelineOutput::Event(event)).await.is_err() {
            break;
        }

        // 6. Forward alerts.
        for alert in alerts {
            if out_tx.send(PipelineOutput::Alert(alert)).await.is_err() {
                return;
            }
        }

        // 7. Forward policy matches.
        for m in policy_matches {
            if out_tx.send(PipelineOutput::Policy(m)).await.is_err() {
                return;
            }
        }

        // Periodic cooldown eviction (every 200 events).
        cooldown_evict_counter = cooldown_evict_counter.wrapping_add(1);
        if cooldown_evict_counter % 200 == 0 {
            cooldown.evict();
        }
    }
}

// ── Eviction loop ──────────────────────────────────────────────────────

fn spawn_eviction(cache: ProcessCache, metrics: Arc<EbpfMetrics>) {
    tokio::spawn(async move {
        eviction_loop(cache, metrics).await;
    });
}

/// Periodic eviction of stale process cache entries.
async fn eviction_loop(cache: ProcessCache, metrics: Arc<EbpfMetrics>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;

        let evicted = cache.evict_stale();
        if evicted > 0 {
            tracing::debug!("evicted {evicted} stale process cache entries");
        }

        #[allow(clippy::cast_possible_truncation)]
        metrics.set_cache_size(cache.len() as u64);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::correlate::AlertSeverity;
    use super::*;

    // ── Synthetic end-to-end helpers ────────────────────────────────────

    /// A mock executor used in synthetic E2E tests to record action calls.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    mod synthetic {
        use super::super::super::actions::{ActionExecutor, ActionResult};
        use super::super::super::policy::PolicyAction;
        use async_trait::async_trait;
        use std::path::Path;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        pub struct MockExecutor {
            pub scan_count: AtomicU32,
            pub mem_scan_count: AtomicU32,
            pub kill_count: AtomicU32,
            pub quarantine_count: AtomicU32,
        }

        impl MockExecutor {
            pub fn new() -> Arc<Self> {
                Arc::new(Self {
                    scan_count: AtomicU32::new(0),
                    mem_scan_count: AtomicU32::new(0),
                    kill_count: AtomicU32::new(0),
                    quarantine_count: AtomicU32::new(0),
                })
            }
        }

        #[async_trait]
        impl ActionExecutor for MockExecutor {
            async fn scan_file(&self, path: &Path) -> anyhow::Result<ActionResult> {
                self.scan_count.fetch_add(1, Ordering::Relaxed);
                Ok(ActionResult {
                    action: PolicyAction::TriggerFileScan,
                    target: path.to_string_lossy().into_owned(),
                    success: true,
                    detail: "mock scan".to_string(),
                })
            }

            async fn scan_memory(&self, pid: u32) -> anyhow::Result<ActionResult> {
                self.mem_scan_count.fetch_add(1, Ordering::Relaxed);
                Ok(ActionResult {
                    action: PolicyAction::TriggerMemoryScan,
                    target: pid.to_string(),
                    success: true,
                    detail: "mock memscan".to_string(),
                })
            }

            async fn kill_process(&self, pid: u32) -> anyhow::Result<ActionResult> {
                self.kill_count.fetch_add(1, Ordering::Relaxed);
                Ok(ActionResult {
                    action: PolicyAction::KillProcess,
                    target: pid.to_string(),
                    success: true,
                    detail: "mock kill".to_string(),
                })
            }

            async fn quarantine_path(&self, path: &Path, _threat_name: &str) -> anyhow::Result<ActionResult> {
                self.quarantine_count.fetch_add(1, Ordering::Relaxed);
                Ok(ActionResult {
                    action: PolicyAction::QuarantinePath,
                    target: path.to_string_lossy().into_owned(),
                    success: true,
                    detail: "mock quarantine".to_string(),
                })
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    use synthetic::MockExecutor;

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn make_exec_event(pid: u32, filename: &str) -> super::super::events::RuntimeEvent {
        use super::super::events::{EventDetail, RuntimeEventKind};
        super::super::events::RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Exec,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "evil".to_string(),
            detail: EventDetail::Exec {
                filename: filename.to_string(),
                argv: String::new(),
            },
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn make_connect_event(pid: u32, port: u16) -> super::super::events::RuntimeEvent {
        use super::super::events::{EventDetail, RuntimeEventKind};
        use std::net::{IpAddr, Ipv4Addr};
        super::super::events::RuntimeEvent {
            ts_ns: 2_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Connect,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "evil".to_string(),
            detail: EventDetail::Connect {
                af: 2,
                port,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        }
    }

    // ── Synthetic E2E tests ─────────────────────────────────────────────

    /// Test 1: Exec from /tmp triggers exec_suspicious_dir policy rule,
    /// which dispatches Alert + TriggerFileScan.  MockExecutor must receive
    /// exactly 1 scan_file call.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[tokio::test]
    async fn synthetic_exec_from_tmp_triggers_scan() {
        use super::super::actions::{ActionDispatcher, DispatcherConfig};
        use super::super::policy::PolicyEngine;
        use std::sync::atomic::Ordering;

        let executor = MockExecutor::new();
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 64,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(300),
        };

        let (action_sender, dispatcher) = ActionDispatcher::new(
            Arc::clone(&executor) as Arc<dyn super::super::actions::ActionExecutor>,
            Arc::clone(&metrics),
            config,
        );
        let dispatch_handle = tokio::spawn(dispatcher.run());

        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);

        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());
        let cooldown = Arc::new(AlertCooldown::new(Duration::from_secs(60)));
        let metrics_clone = Arc::clone(&metrics);
        let engine = PolicyEngine::with_defaults();

        let loop_handle = tokio::spawn(pipeline_loop(
            raw_rx,
            out_tx,
            cache.handle(),
            correlator,
            cooldown,
            Some(engine),
            Some(action_sender.clone()),
            metrics_clone,
        ));

        // Inject synthetic Exec event from /tmp.
        let event = make_exec_event(1000, "/tmp/evil");
        raw_tx.send(event).await.unwrap();

        // Close the channel so pipeline_loop terminates.
        drop(raw_tx);
        loop_handle.await.unwrap();

        // Collect pipeline outputs and verify at least one Event was emitted.
        let mut outputs = Vec::new();
        while let Ok(out) = out_rx.try_recv() {
            outputs.push(out);
        }
        assert!(!outputs.is_empty(), "pipeline should emit at least one output");
        let has_event = outputs.iter().any(|o| matches!(o, PipelineOutput::Event(_)));
        assert!(
            has_event,
            "pipeline should emit at least one Event output, got: {outputs:?}"
        );

        // Drop the action_sender to close the dispatcher channel.
        drop(action_sender);
        dispatch_handle.await.unwrap();

        // exec_suspicious_dir has actions: [Alert, TriggerFileScan]
        // Alert is log-only (no executor call); TriggerFileScan triggers scan_file.
        assert_eq!(
            executor.scan_count.load(Ordering::Relaxed),
            1,
            "expected exactly 1 scan_file call from exec_suspicious_dir"
        );
        assert_eq!(executor.mem_scan_count.load(Ordering::Relaxed), 0);
    }

    /// Test 2: Connect to port 4444 triggers common_c2_ports policy rule,
    /// which dispatches Alert + TriggerMemoryScan.  MockExecutor must receive
    /// exactly 1 scan_memory call.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[tokio::test]
    async fn synthetic_connect_to_c2_port_triggers_memscan() {
        use super::super::actions::{ActionDispatcher, DispatcherConfig};
        use super::super::policy::PolicyEngine;
        use std::sync::atomic::Ordering;

        let executor = MockExecutor::new();
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 64,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(300),
        };

        let (action_sender, dispatcher) = ActionDispatcher::new(
            Arc::clone(&executor) as Arc<dyn super::super::actions::ActionExecutor>,
            Arc::clone(&metrics),
            config,
        );
        let dispatch_handle = tokio::spawn(dispatcher.run());

        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);

        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());
        let cooldown = Arc::new(AlertCooldown::new(Duration::from_secs(60)));
        let engine = PolicyEngine::with_defaults();

        let loop_handle = tokio::spawn(pipeline_loop(
            raw_rx,
            out_tx,
            cache.handle(),
            correlator,
            cooldown,
            Some(engine),
            Some(action_sender.clone()),
            Arc::clone(&metrics),
        ));

        // Inject synthetic Connect event to port 4444.
        let event = make_connect_event(2000, 4444);
        raw_tx.send(event).await.unwrap();

        drop(raw_tx);
        loop_handle.await.unwrap();

        // Collect pipeline outputs and verify at least one Event was emitted.
        let mut outputs = Vec::new();
        while let Ok(out) = out_rx.try_recv() {
            outputs.push(out);
        }
        assert!(!outputs.is_empty(), "pipeline should emit at least one output");
        let has_event = outputs.iter().any(|o| matches!(o, PipelineOutput::Event(_)));
        assert!(has_event, "pipeline should emit at least one Event output for Connect");

        drop(action_sender);
        dispatch_handle.await.unwrap();

        // common_c2_ports has actions: [Alert, TriggerMemoryScan]
        // Alert is log-only; TriggerMemoryScan triggers scan_memory.
        assert_eq!(
            executor.mem_scan_count.load(Ordering::Relaxed),
            1,
            "expected exactly 1 scan_memory call from common_c2_ports"
        );
        assert_eq!(executor.scan_count.load(Ordering::Relaxed), 0);
    }

    /// Test 3: Exec /tmp/evil followed by Connect — Correlator produces
    /// ExecThenConnect alert.  AlertCooldown lets the first through and
    /// blocks the second identical alert.
    ///
    /// This test drives Correlator + AlertCooldown directly (no async
    /// pipeline needed) to avoid wall-clock sensitivity.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn full_pipeline_exec_then_connect_alert() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());
        let cooldown = AlertCooldown::new(Duration::from_secs(60));

        // Step 1: Exec from /tmp/evil — registers process in cache.
        let exec_event = make_exec_event(3000, "/tmp/evil");
        cache.on_event(&exec_event);

        // Step 2: Connect within the 30-second window — Correlator fires.
        let connect_event = make_connect_event(3000, 443);
        cache.on_event(&connect_event);

        let alerts = correlator.check(&connect_event);
        assert_eq!(alerts.len(), 1, "expected ExecThenConnect alert");
        assert_eq!(alerts[0].rule, AlertRule::ExecThenConnect);

        // AlertCooldown: first alert passes.
        let first = cooldown.should_forward(alerts[0].rule, alerts[0].pid);
        assert!(first, "first ExecThenConnect alert must pass cooldown");

        // Second identical alert (same rule + pid) must be blocked.
        let second = cooldown.should_forward(alerts[0].rule, alerts[0].pid);
        assert!(!second, "duplicate ExecThenConnect alert must be blocked by cooldown");
    }

    /// Test 4: Three Exec events for the same /tmp path are deduplicated
    /// by ActionSender — MockExecutor must receive only 1 scan_file call.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[tokio::test]
    async fn policy_match_dedup_only_one_scan() {
        use super::super::actions::{ActionDispatcher, DispatcherConfig};
        use super::super::policy::PolicyEngine;
        use std::sync::atomic::Ordering;

        let executor = MockExecutor::new();
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 64,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(300),
        };

        let (action_sender, dispatcher) = ActionDispatcher::new(
            Arc::clone(&executor) as Arc<dyn super::super::actions::ActionExecutor>,
            Arc::clone(&metrics),
            config,
        );
        let dispatch_handle = tokio::spawn(dispatcher.run());

        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);

        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());
        let cooldown = Arc::new(AlertCooldown::new(Duration::from_secs(60)));
        let engine = PolicyEngine::with_defaults();

        let loop_handle = tokio::spawn(pipeline_loop(
            raw_rx,
            out_tx,
            cache.handle(),
            correlator,
            cooldown,
            Some(engine),
            Some(action_sender.clone()),
            Arc::clone(&metrics),
        ));

        // Send 3 identical Exec events from the same path.
        for _ in 0..3 {
            let event = make_exec_event(4000, "/tmp/evil");
            raw_tx.send(event).await.unwrap();
        }

        drop(raw_tx);
        loop_handle.await.unwrap();

        // Collect pipeline outputs — should have 3 Event outputs (one per injected event).
        let mut outputs = Vec::new();
        while let Ok(out) = out_rx.try_recv() {
            outputs.push(out);
        }
        let event_count = outputs.iter().filter(|o| matches!(o, PipelineOutput::Event(_))).count();
        assert_eq!(
            event_count, 3,
            "pipeline should emit 3 Event outputs (one per injected Exec), got {event_count}"
        );

        drop(action_sender);
        dispatch_handle.await.unwrap();

        // Dedup key is (TriggerFileScan, "/tmp/evil") — only the first is sent.
        assert_eq!(
            executor.scan_count.load(Ordering::Relaxed),
            1,
            "3 identical Exec events should produce only 1 scan_file call after dedup"
        );
        // policy_matches counter sees all 3 evaluations (one per event).
        assert_eq!(
            metrics.policy_matches.load(Ordering::Relaxed),
            3,
            "policy_matches metric should count all 3 evaluations"
        );
    }

    /// Test 5: ProcessCache correctly tracks comm and exec_path for a
    /// process after an Exec event.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn process_cache_tracks_state() {
        use super::super::state::ProcessKey;

        let cache = ProcessCache::new();
        let event = make_exec_event(5000, "/usr/bin/bash");

        cache.on_event(&event);

        // Retrieve by PID.
        let state = cache.get_by_pid(5000);
        assert!(state.is_some(), "process 5000 should be tracked after Exec event");

        let s = state.unwrap();
        assert_eq!(s.pid, 5000);
        assert_eq!(s.comm, "evil", "comm should match the event comm field");
        assert_eq!(
            s.exec_path.as_deref(),
            Some("/usr/bin/bash"),
            "exec_path should be set to the filename from the Exec event"
        );
        assert!(!s.exited, "process should not be marked exited");

        // Also verify via composite key.
        let key = ProcessKey { pid: 5000, mnt_ns: 1 };
        let s2 = cache.get(&key);
        assert!(s2.is_some());
        assert_eq!(s2.unwrap().exec_path.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn test_pipeline_output_display_event() {
        use super::super::events::{EventDetail, RuntimeEventKind};
        let event = RuntimeEvent {
            ts_ns: 1000,
            pid: 1,
            tid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            kind: RuntimeEventKind::Exec,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exec {
                filename: "/bin/sh".to_string(),
                argv: String::new(),
            },
        };
        let out = PipelineOutput::Event(event);
        let s = format!("{out}");
        assert!(s.contains("test"));
    }

    #[test]
    fn test_pipeline_output_display_alert() {
        let alert = CorrelationAlert {
            rule: AlertRule::ExecThenConnect,
            severity: AlertSeverity::High,
            description: "test alert".to_string(),
            pid: 42,
            comm: "evil".to_string(),
            trigger_ts_ns: 1000,
        };
        let out = PipelineOutput::Alert(alert);
        let s = format!("{out}");
        assert!(s.contains("ALERT"));
    }

    #[test]
    fn test_pipeline_output_display_policy() {
        use super::super::policy::PolicyAction;
        let m = PolicyMatch {
            rule_id: "test_rule".to_string(),
            severity: AlertSeverity::High,
            actions: vec![PolicyAction::Alert],
            pid: 42,
            comm: "evil".to_string(),
            description: "test match".to_string(),
            path: None,
            trigger_ts_ns: 1000,
        };
        let out = PipelineOutput::Policy(m);
        let s = format!("{out}");
        assert!(s.contains("POLICY"));
    }

    // -- AlertCooldown tests --

    #[test]
    fn test_cooldown_first_alert_passes() {
        let cd = AlertCooldown::new(Duration::from_secs(60));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
    }

    #[test]
    fn test_cooldown_duplicate_blocked() {
        let cd = AlertCooldown::new(Duration::from_secs(60));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
        assert!(!cd.should_forward(AlertRule::ExecThenConnect, 42));
    }

    #[test]
    fn test_cooldown_different_rule_passes() {
        let cd = AlertCooldown::new(Duration::from_secs(60));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
        assert!(cd.should_forward(AlertRule::RansomwareBurst, 42));
    }

    #[test]
    fn test_cooldown_different_pid_passes() {
        let cd = AlertCooldown::new(Duration::from_secs(60));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 43));
    }

    #[test]
    fn test_cooldown_expired_window_passes() {
        let cd = AlertCooldown::new(Duration::from_millis(1));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cd.should_forward(AlertRule::ExecThenConnect, 42));
    }

    #[test]
    fn test_cooldown_evict() {
        let cd = AlertCooldown::new(Duration::from_millis(1));
        cd.should_forward(AlertRule::ExecThenConnect, 1);
        cd.should_forward(AlertRule::RansomwareBurst, 2);
        assert_eq!(cd.entries.lock().len(), 2);
        std::thread::sleep(Duration::from_millis(5));
        cd.evict();
        assert_eq!(cd.entries.lock().len(), 0);
    }
}

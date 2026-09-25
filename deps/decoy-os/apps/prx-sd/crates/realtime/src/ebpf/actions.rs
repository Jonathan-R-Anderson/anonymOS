//! Action dispatcher for eBPF policy matches.
//!
//! When the policy engine determines that an event matches a rule, the
//! resulting [`PolicyMatch`] is dispatched here. The dispatcher:
//!
//! 1. Deduplicates repeated actions on the same target within a time window
//! 2. Applies backpressure via a bounded channel
//! 3. Delegates execution to an [`ActionExecutor`] trait implementor
//!
//! # Architecture
//!
//! ```text
//! PolicyMatch → ActionSender::send() → mpsc channel → ActionDispatcher::run()
//!                    ↑ dedup check                          ↓ execute()
//!                    ↑ backpressure                     ActionExecutor (trait)
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use tracing;

use super::metrics::EbpfMetrics;
use super::policy::{PolicyAction, PolicyMatch, PolicySeverity};

// ── Action result ──────────────────────────────────────────────────────

/// The outcome of executing a single action.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Which action was executed.
    pub action: PolicyAction,
    /// Target description (path or PID).
    pub target: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Human-readable detail or error message.
    pub detail: String,
}

impl fmt::Display for ActionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.success { "OK" } else { "FAILED" };
        write!(f, "[{}] {} on {}: {}", status, self.action, self.target, self.detail)
    }
}

// ── Action executor trait ──────────────────────────────────────────────

/// Trait for executing policy actions.
///
/// Implementations are provided by the CLI/daemon layer, which has access to
/// the scan engine, quarantine vault, and remediation engine.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// Scan a file for threats.
    async fn scan_file(&self, path: &Path) -> anyhow::Result<ActionResult>;

    /// Scan a process's memory for threats.
    async fn scan_memory(&self, pid: u32) -> anyhow::Result<ActionResult>;

    /// Kill a process by PID.
    async fn kill_process(&self, pid: u32) -> anyhow::Result<ActionResult>;

    /// Quarantine a file path.
    async fn quarantine_path(&self, path: &Path, threat_name: &str) -> anyhow::Result<ActionResult>;
}

// ── Dedup cache ────────────────────────────────────────────────────────

/// Key for deduplication: (action_type, target).
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct DedupKey {
    action: PolicyAction,
    target: String,
}

/// Time-windowed deduplication cache.
///
/// Prevents the same action from firing on the same target within `window`.
struct DedupCache {
    entries: Mutex<HashMap<DedupKey, Instant>>,
    window: Duration,
}

impl DedupCache {
    fn new(window: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Returns `true` if the action should proceed (not a duplicate).
    fn try_acquire(&self, key: &DedupKey) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        if let Some(last) = entries.get(key) {
            if now.duration_since(*last) < self.window {
                return false;
            }
        }

        entries.insert(key.clone(), now);
        true
    }

    /// Remove a specific key (used to rollback after failed send).
    fn remove(&self, key: &DedupKey) {
        self.entries.lock().remove(key);
    }

    /// Remove expired entries to prevent unbounded growth.
    fn evict_expired(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, last| now.duration_since(*last) < self.window);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

// ── Dispatcher config ──────────────────────────────────────────────────

/// Configuration for the action dispatcher.
pub struct DispatcherConfig {
    /// Size of the bounded action queue.
    pub queue_size: usize,
    /// Dedup window — actions on the same target within this window are
    /// collapsed into one.
    pub dedup_window: Duration,
    /// How often to evict expired dedup entries.
    pub evict_interval: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            queue_size: 256,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(30),
        }
    }
}

// ── Action request ─────────────────────────────────────────────────────

/// A single action request queued for execution.
#[derive(Debug)]
pub struct ActionRequest {
    /// Rule that produced this request.
    pub rule_id: String,
    /// The action to execute.
    pub action: PolicyAction,
    /// Severity level.
    pub severity: PolicySeverity,
    /// Process ID from the triggering event.
    pub pid: u32,
    /// Associated path (for file scan / quarantine).
    pub path: Option<PathBuf>,
    /// Human-readable context.
    pub detail: String,
}

/// Expand a [`PolicyMatch`] into individual [`ActionRequest`]s, one per action.
pub fn requests_from_match(m: &PolicyMatch) -> Vec<ActionRequest> {
    m.actions
        .iter()
        .map(|&action| ActionRequest {
            rule_id: m.rule_id.clone(),
            action,
            severity: severity_from_alert(m.severity),
            pid: m.pid,
            path: m.path.as_ref().map(PathBuf::from),
            detail: m.to_string(),
        })
        .collect()
}

/// Convert `AlertSeverity` → `PolicySeverity` for the request.
fn severity_from_alert(s: super::correlate::AlertSeverity) -> PolicySeverity {
    match s {
        super::correlate::AlertSeverity::Low => PolicySeverity::Low,
        super::correlate::AlertSeverity::Medium => PolicySeverity::Medium,
        super::correlate::AlertSeverity::High => PolicySeverity::High,
        super::correlate::AlertSeverity::Critical => PolicySeverity::Critical,
    }
}

// ── Sender handle ──────────────────────────────────────────────────────

/// Clone-able handle for sending action requests into the bounded queue.
///
/// The sender performs dedup checks and backpressure (try_send) before
/// enqueuing. If the queue is full, the request is dropped and a metric
/// is incremented.
#[derive(Clone)]
pub struct ActionSender {
    tx: tokio::sync::mpsc::Sender<ActionRequest>,
    dedup: Arc<DedupCache>,
    metrics: Arc<EbpfMetrics>,
}

impl ActionSender {
    /// Try to enqueue an action request.
    ///
    /// Returns `true` if enqueued, `false` if dropped (dedup or backpressure).
    pub fn try_send(&self, request: ActionRequest) -> bool {
        let target = request
            .path
            .as_ref()
            .map_or_else(|| request.pid.to_string(), |p| p.to_string_lossy().into_owned());
        let key = DedupKey {
            action: request.action,
            target,
        };

        if !self.dedup.try_acquire(&key) {
            tracing::debug!(
                rule_id = %request.rule_id,
                action = %request.action,
                "action deduplicated, skipping"
            );
            return false;
        }

        match self.tx.try_send(request) {
            Ok(()) => {
                self.metrics.inc_actions_dispatched();
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(req)) => {
                // Rollback dedup entry so a future retry can succeed.
                self.dedup.remove(&key);
                tracing::warn!(
                    rule_id = %req.rule_id,
                    action = %req.action,
                    "action queue full, dropping request"
                );
                self.metrics.inc_actions_dropped();
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Rollback dedup entry — channel gone, action never executed.
                self.dedup.remove(&key);
                tracing::error!("action dispatcher channel closed");
                false
            }
        }
    }

    /// Send all actions from a policy match. Returns the number enqueued.
    pub fn send_match(&self, m: &PolicyMatch) -> usize {
        self.metrics.inc_policy_matches();
        let requests = requests_from_match(m);
        let mut sent = 0;
        for req in requests {
            if self.try_send(req) {
                sent += 1;
            }
        }
        sent
    }
}

// ── Dispatcher (receiver side) ─────────────────────────────────────────

/// Receives action requests from the bounded channel and executes them
/// via the [`ActionExecutor`] trait.
pub struct ActionDispatcher {
    rx: tokio::sync::mpsc::Receiver<ActionRequest>,
    executor: Arc<dyn ActionExecutor>,
    dedup: Arc<DedupCache>,
    _metrics: Arc<EbpfMetrics>,
    evict_interval: Duration,
}

impl ActionDispatcher {
    /// Create a new dispatcher and its corresponding sender.
    pub fn new(
        executor: Arc<dyn ActionExecutor>,
        metrics: Arc<EbpfMetrics>,
        config: DispatcherConfig,
    ) -> (ActionSender, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(config.queue_size);
        let dedup = Arc::new(DedupCache::new(config.dedup_window));

        let sender = ActionSender {
            tx,
            dedup: Arc::clone(&dedup),
            metrics: Arc::clone(&metrics),
        };

        let dispatcher = Self {
            rx,
            executor,
            dedup,
            _metrics: metrics,
            evict_interval: config.evict_interval,
        };

        (sender, dispatcher)
    }

    /// Run the dispatcher loop until the channel is closed.
    pub async fn run(mut self) {
        let mut evict_ticker = tokio::time::interval(self.evict_interval);

        loop {
            tokio::select! {
                request = self.rx.recv() => {
                    match request {
                        Some(req) => self.execute(req).await,
                        None => break,
                    }
                }
                _ = evict_ticker.tick() => {
                    self.dedup.evict_expired();
                }
            }
        }

        tracing::info!("action dispatcher shutting down");
    }

    async fn execute(&self, request: ActionRequest) {
        if request.action == PolicyAction::Alert {
            // Alert is a log-only action, no executor call needed.
            tracing::warn!(
                rule_id = %request.rule_id,
                severity = ?request.severity,
                pid = request.pid,
                path = ?request.path,
                "POLICY ALERT: {}",
                request.detail,
            );
            return;
        }

        let result = match request.action {
            PolicyAction::Alert => return, // handled above
            PolicyAction::TriggerFileScan => {
                if let Some(ref path) = request.path {
                    self.executor.scan_file(path).await
                } else {
                    tracing::warn!(
                        rule_id = %request.rule_id,
                        "TriggerFileScan: no path available"
                    );
                    return;
                }
            }
            PolicyAction::TriggerMemoryScan => self.executor.scan_memory(request.pid).await,
            PolicyAction::KillProcess => self.executor.kill_process(request.pid).await,
            PolicyAction::QuarantinePath => {
                if let Some(ref path) = request.path {
                    self.executor.quarantine_path(path, &request.rule_id).await
                } else {
                    tracing::warn!(
                        rule_id = %request.rule_id,
                        "QuarantinePath: no path available"
                    );
                    return;
                }
            }
        };

        match result {
            Ok(action_result) => {
                if action_result.success {
                    tracing::info!(
                        rule_id = %request.rule_id,
                        action = %request.action,
                        "{}",
                        action_result,
                    );
                } else {
                    tracing::warn!(
                        rule_id = %request.rule_id,
                        action = %request.action,
                        "{}",
                        action_result,
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    rule_id = %request.rule_id,
                    action = %request.action,
                    error = %e,
                    "action execution error",
                );
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::correlate::AlertSeverity;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A mock executor that records calls.
    struct MockExecutor {
        scan_count: AtomicU32,
        mem_scan_count: AtomicU32,
        kill_count: AtomicU32,
        quarantine_count: AtomicU32,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                scan_count: AtomicU32::new(0),
                mem_scan_count: AtomicU32::new(0),
                kill_count: AtomicU32::new(0),
                quarantine_count: AtomicU32::new(0),
            }
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
                detail: "mock scan complete".to_string(),
            })
        }

        async fn scan_memory(&self, pid: u32) -> anyhow::Result<ActionResult> {
            self.mem_scan_count.fetch_add(1, Ordering::Relaxed);
            Ok(ActionResult {
                action: PolicyAction::TriggerMemoryScan,
                target: pid.to_string(),
                success: true,
                detail: "mock memscan complete".to_string(),
            })
        }

        async fn kill_process(&self, pid: u32) -> anyhow::Result<ActionResult> {
            self.kill_count.fetch_add(1, Ordering::Relaxed);
            Ok(ActionResult {
                action: PolicyAction::KillProcess,
                target: pid.to_string(),
                success: true,
                detail: "mock kill complete".to_string(),
            })
        }

        async fn quarantine_path(&self, path: &Path, _threat_name: &str) -> anyhow::Result<ActionResult> {
            self.quarantine_count.fetch_add(1, Ordering::Relaxed);
            Ok(ActionResult {
                action: PolicyAction::QuarantinePath,
                target: path.to_string_lossy().into_owned(),
                success: true,
                detail: "mock quarantine complete".to_string(),
            })
        }
    }

    fn make_policy_match(actions: Vec<PolicyAction>, path: Option<&str>) -> PolicyMatch {
        PolicyMatch {
            rule_id: "test_rule".to_string(),
            severity: AlertSeverity::High,
            actions,
            pid: 42,
            comm: "evil".to_string(),
            description: "test match".to_string(),
            path: path.map(String::from),
            trigger_ts_ns: 1000,
        }
    }

    // -- DedupCache tests --

    #[test]
    fn test_dedup_first_acquire_succeeds() {
        let cache = DedupCache::new(Duration::from_secs(60));
        let key = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil".to_string(),
        };
        assert!(cache.try_acquire(&key));
    }

    #[test]
    fn test_dedup_second_acquire_blocked() {
        let cache = DedupCache::new(Duration::from_secs(60));
        let key = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil".to_string(),
        };
        assert!(cache.try_acquire(&key));
        assert!(!cache.try_acquire(&key));
    }

    #[test]
    fn test_dedup_different_action_not_blocked() {
        let cache = DedupCache::new(Duration::from_secs(60));
        let key1 = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil".to_string(),
        };
        let key2 = DedupKey {
            action: PolicyAction::QuarantinePath,
            target: "/tmp/evil".to_string(),
        };
        assert!(cache.try_acquire(&key1));
        assert!(cache.try_acquire(&key2));
    }

    #[test]
    fn test_dedup_different_target_not_blocked() {
        let cache = DedupCache::new(Duration::from_secs(60));
        let key1 = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil1".to_string(),
        };
        let key2 = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil2".to_string(),
        };
        assert!(cache.try_acquire(&key1));
        assert!(cache.try_acquire(&key2));
    }

    #[test]
    fn test_dedup_expired_window_allows_reacquire() {
        let cache = DedupCache::new(Duration::from_millis(1));
        let key = DedupKey {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil".to_string(),
        };
        assert!(cache.try_acquire(&key));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.try_acquire(&key));
    }

    #[test]
    fn test_dedup_evict_expired() {
        let cache = DedupCache::new(Duration::from_millis(1));
        let key = DedupKey {
            action: PolicyAction::Alert,
            target: "test".to_string(),
        };
        assert!(cache.try_acquire(&key));
        assert_eq!(cache.len(), 1);
        std::thread::sleep(Duration::from_millis(5));
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    // -- requests_from_match tests --

    #[test]
    fn test_requests_from_match_single_action() {
        let m = make_policy_match(vec![PolicyAction::Alert], None);
        let reqs = requests_from_match(&m);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs.first().unwrap().action, PolicyAction::Alert);
        assert_eq!(reqs.first().unwrap().pid, 42);
    }

    #[test]
    fn test_requests_from_match_multiple_actions() {
        let m = make_policy_match(
            vec![
                PolicyAction::Alert,
                PolicyAction::TriggerFileScan,
                PolicyAction::KillProcess,
            ],
            Some("/tmp/evil"),
        );
        let reqs = requests_from_match(&m);
        assert_eq!(reqs.len(), 3);
    }

    #[test]
    fn test_requests_from_match_preserves_path() {
        let m = make_policy_match(vec![PolicyAction::TriggerFileScan], Some("/tmp/evil"));
        let reqs = requests_from_match(&m);
        assert_eq!(reqs.first().unwrap().path.as_deref(), Some(Path::new("/tmp/evil")));
    }

    // -- ActionResult display --

    #[test]
    fn test_action_result_display_success() {
        let r = ActionResult {
            action: PolicyAction::TriggerFileScan,
            target: "/tmp/evil".to_string(),
            success: true,
            detail: "clean".to_string(),
        };
        let s = format!("{r}");
        assert!(s.contains("[OK]"));
        assert!(s.contains("trigger_file_scan"));
        assert!(s.contains("/tmp/evil"));
    }

    #[test]
    fn test_action_result_display_failure() {
        let r = ActionResult {
            action: PolicyAction::KillProcess,
            target: "42".to_string(),
            success: false,
            detail: "permission denied".to_string(),
        };
        let s = format!("{r}");
        assert!(s.contains("[FAILED]"));
        assert!(s.contains("permission denied"));
    }

    // -- Integration: sender + dispatcher --

    #[tokio::test]
    async fn test_dispatcher_executes_file_scan() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 8,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(300),
        };

        let (sender, dispatcher) = ActionDispatcher::new(
            Arc::clone(&executor) as Arc<dyn ActionExecutor>,
            Arc::clone(&metrics),
            config,
        );

        let handle = tokio::spawn(dispatcher.run());

        let m = make_policy_match(vec![PolicyAction::TriggerFileScan], Some("/tmp/evil"));
        sender.send_match(&m);

        // Give dispatcher time to process.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drop sender to close the channel and stop dispatcher.
        drop(sender);
        handle.await.unwrap();

        assert_eq!(executor.scan_count.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.policy_matches.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.actions_dispatched.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_dispatcher_executes_kill() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig::default();

        let (sender, dispatcher) = ActionDispatcher::new(Arc::clone(&executor) as _, Arc::clone(&metrics), config);

        let handle = tokio::spawn(dispatcher.run());

        let m = make_policy_match(vec![PolicyAction::KillProcess], None);
        sender.send_match(&m);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(sender);
        handle.await.unwrap();

        assert_eq!(executor.kill_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_dispatcher_executes_quarantine() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig::default();

        let (sender, dispatcher) = ActionDispatcher::new(Arc::clone(&executor) as _, Arc::clone(&metrics), config);

        let handle = tokio::spawn(dispatcher.run());

        let m = make_policy_match(vec![PolicyAction::QuarantinePath], Some("/tmp/malware.bin"));
        sender.send_match(&m);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(sender);
        handle.await.unwrap();

        assert_eq!(executor.quarantine_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_dispatcher_dedup_blocks_repeated_scan() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 8,
            dedup_window: Duration::from_secs(60),
            evict_interval: Duration::from_secs(300),
        };

        let (sender, dispatcher) = ActionDispatcher::new(Arc::clone(&executor) as _, Arc::clone(&metrics), config);

        let handle = tokio::spawn(dispatcher.run());

        let m = make_policy_match(vec![PolicyAction::TriggerFileScan], Some("/tmp/evil"));
        sender.send_match(&m);
        sender.send_match(&m); // duplicate → should be deduped
        sender.send_match(&m); // duplicate → should be deduped

        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(sender);
        handle.await.unwrap();

        // Only 1 scan should have executed.
        assert_eq!(executor.scan_count.load(Ordering::Relaxed), 1);
        // But policy_matches counted all 3.
        assert_eq!(metrics.policy_matches.load(Ordering::Relaxed), 3);
        // Only 1 action dispatched (2 deduped).
        assert_eq!(metrics.actions_dispatched.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_dispatcher_multi_action_match() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig::default();

        let (sender, dispatcher) = ActionDispatcher::new(Arc::clone(&executor) as _, Arc::clone(&metrics), config);

        let handle = tokio::spawn(dispatcher.run());

        // Match with multiple actions: alert + file scan + memscan
        let m = make_policy_match(
            vec![
                PolicyAction::Alert,
                PolicyAction::TriggerFileScan,
                PolicyAction::TriggerMemoryScan,
            ],
            Some("/tmp/evil"),
        );
        sender.send_match(&m);

        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(sender);
        handle.await.unwrap();

        // Alert doesn't call executor. File scan and mem scan should both fire.
        assert_eq!(executor.scan_count.load(Ordering::Relaxed), 1);
        assert_eq!(executor.mem_scan_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_backpressure_drops_on_full_queue() {
        let executor = Arc::new(MockExecutor::new());
        let metrics = Arc::new(EbpfMetrics::new());
        let config = DispatcherConfig {
            queue_size: 2,
            dedup_window: Duration::from_millis(1), // very short, so dedup doesn't interfere
            evict_interval: Duration::from_secs(300),
        };

        let (sender, _dispatcher) = ActionDispatcher::new(Arc::clone(&executor) as _, Arc::clone(&metrics), config);

        // Don't start the dispatcher — queue will fill up.
        // Send 5 requests with different paths to avoid dedup.
        let mut sent_count = 0usize;
        for i in 0..5 {
            std::thread::sleep(Duration::from_millis(2)); // let dedup expire
            let m = make_policy_match(vec![PolicyAction::TriggerFileScan], Some(&format!("/tmp/file_{i}")));
            if sender.try_send(requests_from_match(&m).into_iter().next().unwrap()) {
                sent_count += 1;
            }
        }

        // Queue size is 2, so at most 2 should have been sent.
        assert_eq!(sent_count, 2);
        // Remaining 3 should be dropped.
        assert!(metrics.actions_dropped.load(Ordering::Relaxed) >= 3);
    }

    #[test]
    fn test_severity_from_alert() {
        assert_eq!(severity_from_alert(AlertSeverity::Low), PolicySeverity::Low);
        assert_eq!(severity_from_alert(AlertSeverity::Critical), PolicySeverity::Critical);
    }
}

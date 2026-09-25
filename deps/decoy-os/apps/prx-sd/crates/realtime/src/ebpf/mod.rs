//! eBPF-based runtime telemetry for Linux.
//!
//! This module provides kernel-level process, file, and network event
//! collection via eBPF tracepoints, consumed through a ring buffer and
//! delivered as [`RuntimeEvent`]s to the async event pipeline.
//!
//! # Feature gate
//!
//! All code in this module requires the `ebpf` cargo feature and
//! `target_os = "linux"`.

pub mod actions;
pub mod correlate;
pub mod events;
pub mod loader;
pub mod metrics;
pub mod pipeline;
pub mod policy;
pub mod state;

pub use actions::{ActionDispatcher, ActionExecutor, ActionResult, ActionSender, DispatcherConfig};
pub use correlate::{AlertRule, AlertSeverity, CorrelationAlert, Correlator};
pub use events::{RuntimeEvent, RuntimeEventKind};
pub use loader::EbpfRuntime;
pub use metrics::EbpfMetrics;
pub use pipeline::{EbpfPipeline, PipelineOutput, PolicyConfig};
pub use policy::{PolicyAction, PolicyEngine, PolicyMatch, PolicyRule, PolicySeverity};
pub use state::ProcessCache;

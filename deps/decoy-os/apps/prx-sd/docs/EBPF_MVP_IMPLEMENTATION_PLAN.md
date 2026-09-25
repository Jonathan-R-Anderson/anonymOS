# PRX-SD Linux eBPF MVP Implementation Plan

## 1. Objective

This plan defines a complete Linux-first eBPF MVP for `sd` CLI and daemon mode.

The MVP goal is not to replace the existing scan engine. The goal is to add a kernel-assisted runtime telemetry and response layer so that `sd` can:

1. Observe high-value process, file, and network events with low overhead.
2. Correlate those events in userspace with the existing detection engine.
3. Trigger scan, alert, and selective response actions fast enough for runtime defense.
4. Establish a stable foundation for later enforcement and policy expansion.

## 2. Product Positioning

After the MVP, `sd` on Linux becomes:

- A file scanner and signature engine.
- A host runtime detector for process, file, and network activity.
- A daemon capable of event-driven scanning and behavioral correlation.

It does not become a full EDR platform yet. The MVP should stay focused on host runtime telemetry plus targeted response.

## 3. Scope

### In Scope

- Linux only.
- `sd daemon` and `sd monitor` first.
- eBPF event collection for process execution, file access, and outbound network connect.
- Userspace correlation and policy evaluation in Rust.
- Event-driven scan scheduling into the current engine.
- Structured logging and basic metrics.
- Minimal policy and CLI controls.

### Out of Scope for MVP

- Kubernetes awareness.
- Full in-kernel blocking for every event class.
- XDP firewalling.
- Full container security inventory.
- Distributed management plane.
- UI-first workflows.

## 4. MVP Definition

The MVP is complete when all of the following are true:

1. `sd daemon --ebpf` runs on supported Linux kernels and attaches eBPF programs successfully.
2. `sd monitor --backend ebpf` streams normalized process, file, and network events.
3. `exec`, `open`, and `connect` events are correlated to `pid`, `ppid`, `uid`, `gid`, `comm`, `exe`, and timestamps.
4. Suspicious exec/file/net patterns can trigger:
   - alert
   - targeted file scan
   - targeted process memory scan request
   - optional remediation through the existing policy engine
5. Metrics and logs allow operators to answer:
   - are programs attached
   - are events flowing
   - are events dropped
   - what policies fired
   - what scans were triggered
6. Existing non-eBPF paths still work as fallback.

## 5. Target Architecture

### 5.1 High-Level Data Path

1. eBPF programs attach to Linux hooks.
2. eBPF emits filtered event records to a ring buffer.
3. `prx-sd-realtime` consumes ring buffer events.
4. Events are normalized into a stable Rust event model.
5. A userspace policy engine evaluates event rules.
6. Matching rules trigger one or more actions:
   - log
   - metric increment
   - submit targeted scan job
   - submit memory scan job
   - quarantine or kill through existing remediation path
7. Results are surfaced in `sd monitor`, `sd daemon`, and `sd status`.

### 5.2 Module Layout

Add these modules under [`crates/realtime`](/opt/worker/code/prx-sd/crates/realtime):

- `src/ebpf/mod.rs`
- `src/ebpf/loader.rs`
- `src/ebpf/events.rs`
- `src/ebpf/policy.rs`
- `src/ebpf/runtime.rs`
- `src/ebpf/metrics.rs`
- `src/ebpf/state.rs`

Add BPF sources:

- `src/bpf/prxsd.bpf.c`
- `src/bpf/prxsd.h`

Add build integration:

- `build.rs` in `crates/realtime`
- generated skeleton in `OUT_DIR`

CLI integration points:

- [`crates/cli/src/commands/realtime.rs`](/opt/worker/code/prx-sd/crates/cli/src/commands/realtime.rs)
- [`crates/cli/src/commands/daemon.rs`](/opt/worker/code/prx-sd/crates/cli/src/commands/daemon.rs)
- [`crates/cli/src/main.rs`](/opt/worker/code/prx-sd/crates/cli/src/main.rs)

## 6. Technical Stack

### 6.1 Required Rust Crates

- `libbpf-rs`
- `libbpf-cargo`
- `libbpf-sys`
- `plain` or equivalent for safe event decoding if needed
- existing `tokio`, `tracing`, `serde`, `anyhow`, `thiserror`

### 6.2 System Dependencies

Build-time:

- `clang`
- `llvm`
- `libelf-dev` or distro equivalent
- `zlib1g-dev` or distro equivalent
- `pkg-config`
- `build-essential`

Runtime:

- Linux kernel with BPF and BTF support preferred
- `CAP_BPF`, `CAP_PERFMON`, and possibly `CAP_SYS_ADMIN` depending on kernel and attach type
- root support for initial rollout

### 6.3 Build Integration

Use `libbpf-cargo::SkeletonBuilder` in `crates/realtime/build.rs`.

The build script will:

1. Compile `src/bpf/prxsd.bpf.c`.
2. Generate Rust skeleton bindings.
3. Embed object output into the realtime crate.

## 7. Event Model

Use a single normalized event schema in Rust.

```rust
enum RuntimeEventKind {
    Exec,
    FileOpen,
    FileWrite,
    FileRename,
    Connect,
    Dns,
    ModuleLoad,
    PrivEscAttempt,
}
```

Common fields:

- `ts_ns`
- `pid`
- `tid`
- `ppid`
- `uid`
- `gid`
- `comm`
- `exe`
- `cwd` when available
- `cgroup_id`
- `mnt_ns`
- `pid_ns`
- `path`
- `argv`
- `remote_addr`
- `remote_port`
- `result`
- `flags`

The BPF layer should emit compact binary structs. String-heavy enrichment should stay in userspace unless the kernel hook already exposes it cheaply.

## 8. Hook Selection

### Phase 1 Hooks

These hooks are sufficient for MVP:

1. `sched_process_exec` tracepoint or equivalent for process execution.
2. `sys_enter_openat` and `sys_enter_openat2` tracepoints for high-value file opens.
3. `sys_enter_connect` tracepoint for outbound connections.
4. `sched_process_exit` for lifecycle cleanup.

### Phase 2 Hooks

- `sys_enter_renameat` or `renameat2`
- `sys_enter_unlinkat`
- `security_file_open` LSM when available
- `sys_enter_ptrace`
- `sys_enter_memfd_create`

### Phase 3 Hooks

- `bprm_check_security` or LSM-based exec gating where supported
- module load hooks
- additional privilege and persistence hooks

## 9. Userspace Policy Engine

Keep policy evaluation in Rust for MVP.

### 9.1 Why Userspace First

- Faster iteration.
- Easier testing.
- Lower risk than early in-kernel enforcement.
- Reuses your current remediation pipeline.

### 9.2 MVP Policy Types

1. Exec policy:
   - execution from `/tmp`, `/dev/shm`, user cache, browser download directories
   - execution by interpreter from untrusted path
   - suspicious parent-child chains

2. File policy:
   - access to sensitive paths
   - write bursts to protected directories
   - executable creation followed by immediate exec

3. Network policy:
   - outbound connects from newly dropped binaries
   - connects to suspicious IPs or unusual ports
   - execution followed by connect within a short time window

### 9.3 Policy Actions

- `Alert`
- `TriggerFileScan`
- `TriggerMemoryScan`
- `KillProcess`
- `QuarantinePath`
- `TagProcess`

## 10. Synchronization and State Management

This is the most important part of the MVP.

### 10.1 Event Pipeline

Use a bounded async pipeline:

1. ring buffer consumer thread
2. event normalizer
3. policy evaluator
4. action dispatcher

Suggested design:

- one blocking thread reads libbpf ring buffer
- sends decoded events into `tokio::mpsc`
- one async task performs enrichment and correlation
- one async task executes actions and scan jobs

### 10.2 Process State Cache

Maintain a process state table keyed by `pid + start_time` to reduce PID reuse issues.

Store:

- process lineage
- first seen timestamp
- first exec path
- recent file accesses
- recent network destinations
- policy tags
- last scan verdict

Recommended storage:

- in-memory `DashMap` or `RwLock<HashMap<...>>` for MVP
- TTL-based eviction on process exit or inactivity

### 10.3 Correlation Windows

Define fixed windows:

- `exec -> connect`: 30 seconds
- `drop -> exec`: 10 minutes
- ransomware write burst: 10 to 60 seconds sliding window
- repeated sensitive file access: 60 seconds

### 10.4 Backpressure Strategy

Backpressure rules must be explicit:

1. ring buffer overflow increments drop metrics
2. userspace queue overflow drops low-priority events first
3. high-value event classes are preserved:
   - exec
   - module load
   - sensitive file access
4. file-open noise is sampled or path-filtered

## 11. Observation and Operations

### 11.1 Logs

All eBPF runtime components should log through `tracing`.

Required log events:

- program attach success or failure
- map initialization
- ring buffer open
- event decode errors
- event drops
- policy match
- action dispatch
- scan result linked to source event

### 11.2 Metrics

Add counters and gauges:

- `ebpf_program_attach_total`
- `ebpf_program_attach_fail_total`
- `ebpf_events_total{kind=...}`
- `ebpf_events_dropped_total{reason=...}`
- `ebpf_ringbuf_poll_errors_total`
- `policy_matches_total{policy=...,action=...}`
- `triggered_scans_total{source=ebpf}`
- `runtime_cache_entries`
- `runtime_queue_depth`

Expose MVP metrics in one of two ways:

1. `sd status --verbose`
2. JSON status output under the data directory

Prometheus exporter can wait until post-MVP.

### 11.3 Health Signals

`sd status` on Linux should report:

- eBPF enabled: yes or no
- attached hooks count
- last event timestamp
- drop rate
- queue depth
- last policy match
- last triggered scan

## 12. CLI Design

### 12.1 New Flags

Add to `sd monitor`:

- `--backend auto|notify|fanotify|ebpf`
- `--ebpf`
- `--json-events`
- `--event-kinds exec,file,net`

Add to `sd daemon`:

- `--ebpf`
- `--ebpf-policy <path>`
- `--ebpf-events-buffer <n>`
- `--ebpf-fail-open`

### 12.2 New Commands

Add a new top-level command:

`sd runtime`

Subcommands:

- `sd runtime status`
- `sd runtime top`
- `sd runtime events`
- `sd runtime policy show`
- `sd runtime policy test`

For MVP, only `status` and `events` are mandatory. `top` and `policy test` are optional if schedule slips.

## 13. Delivery Plan

### Stage 1: Telemetry MVP

#### Goal

Attach eBPF successfully and stream normalized events into `sd monitor` and `sd daemon`.

#### Deliverables

- `libbpf-rs` integrated into `crates/realtime`
- build script and skeleton generation
- tracepoints for `exec`, `openat/openat2`, `connect`, `exit`
- ring buffer consumer
- normalized Rust event model
- CLI flag `--ebpf`
- `sd monitor --backend ebpf`
- health and drop metrics

#### Implementation Tasks

1. Add build dependencies and update Linux build docs.
2. Create initial `.bpf.c` program with compact event structs.
3. Implement loader and attach lifecycle.
4. Implement ring buffer reader and decoder.
5. Add path filters in kernel or immediate userspace filter for noise control.
6. Emit events to console and JSON.
7. Add fallback to existing monitor path on attach failure if `--ebpf-fail-open` is enabled.

#### Tools Required

- `clang`
- `libbpf-cargo`
- `cargo check`
- `cargo test`
- privileged local Linux test host
- `bpftool` for inspection

#### Synchronization Design

- one ring buffer reader thread
- one async normalizer task
- one output sink
- no scan triggering yet except debug hooks

#### Observation

- verify attach logs
- verify event counters
- verify ring buffer drop counter
- verify `sd runtime status`

#### Acceptance Criteria

- on a supported Linux host, `sd monitor --backend ebpf /tmp` shows live exec/file/connect events
- CPU remains acceptable under a synthetic file event burst
- no crash on process churn

### Stage 2: Correlation and Response MVP

#### Goal

Turn eBPF telemetry into actionable runtime detection for the daemon.

#### Deliverables

- process state cache
- policy engine in Rust
- event correlation windows
- action dispatcher
- integration with file scan and optional memory scan
- integration with remediation policy

#### Implementation Tasks

1. Add process cache and lifecycle cleanup.
2. Implement initial policy rules:
   - exec from suspicious path
   - exec followed by outbound connect
   - sensitive path open
   - write or rename burst near protected directories
3. Trigger existing scan engine on matched file paths.
4. Trigger `scan-memory` request for suspicious live processes.
5. Route confirmed malicious verdicts into existing quarantine and kill flow.
6. Persist recent events and policy matches in the data directory.

#### Tools Required

- existing scan engine
- remediation engine
- synthetic test binaries and file event generators
- `bpftool map` inspection

#### Synchronization Design

- state cache writes centralized in one task when possible
- actions dispatched over bounded queue
- scans deduplicated by `(path hash, time bucket)`

#### Observation

- policy match counters
- scan trigger counters
- action success or failure counters
- recent correlated event chains in logs

#### Acceptance Criteria

- suspicious execution chains trigger targeted scans
- sensitive file access is visible with process attribution
- outbound connect after risky exec produces alert
- daemon remains stable under sustained event flow

### Stage 3: Enforcement and Productization

#### Goal

Add selective runtime enforcement where it is stable and high-value.

#### Deliverables

- optional enforcement mode for specific policies
- expanded hooks for rename, unlink, ptrace, memfd, module load
- persistent policy file format
- `sd runtime policy show`
- production build and rollout docs

#### Implementation Tasks

1. Add policy file schema and versioning.
2. Add enforcement-capable hooks where support is reliable.
3. Add fail-open and fail-closed behavior per policy class.
4. Expand `sd status` and diagnostics.
5. Add packaging and install checks for Linux eBPF prerequisites.

#### Tools Required

- `bpftool prog`
- kernel capability inspection
- distro matrix test hosts

#### Synchronization Design

- enforcement path must remain minimal
- userspace must not block ring buffer polling
- kernel-side filtering should reduce userspace load before more hooks are added

#### Observation

- enforcement attempts
- enforcement success or fallback
- false-positive audit log

#### Acceptance Criteria

- selected high-confidence policies can block or kill safely
- fallback path is documented and works
- users can inspect why a process was flagged or stopped

## 14. Policy File MVP

Use a JSON or TOML file under the existing data directory.

Example shape:

```toml
[[rule]]
id = "exec_tmp"
kind = "exec"
match_path_prefix = ["/tmp", "/dev/shm"]
action = ["alert", "trigger_file_scan"]
severity = "high"

[[rule]]
id = "sensitive_shadow_open"
kind = "file_open"
match_path_exact = ["/etc/shadow"]
action = ["alert", "trigger_memory_scan"]
severity = "critical"
```

## 15. Testing Strategy

### 15.1 Unit Tests

- event decode
- policy evaluation
- correlation window logic
- cache eviction
- action deduplication

### 15.2 Integration Tests

- attach and detach lifecycle
- synthetic exec event seen in userspace
- synthetic open/connect events trigger policies
- scan dispatch from runtime events

### 15.3 Manual Validation

Run on at least:

- Ubuntu LTS current kernel
- Debian stable kernel
- one newer Fedora kernel

Validate:

- shell execs
- curl connects
- file drop plus exec
- access to protected files
- process churn

## 16. Rollout Plan

### Wave 1

- hidden behind `--ebpf`
- root-only
- Linux x86_64 first

### Wave 2

- default backend `auto`
- falls back to current monitor implementation if unsupported

### Wave 3

- policy enabled in daemon by configuration

## 17. Risks and Mitigations

1. Kernel compatibility risk.
Mitigation: tracepoint-first design, fallback backend, documented kernel matrix.

2. Event volume overload.
Mitigation: high-value hooks only, path filters, bounded queues, metrics on drops.

3. False positives.
Mitigation: userspace policy iteration first, alert-first mode, enforcement only for high-confidence rules.

4. Build complexity.
Mitigation: isolate eBPF support to Linux-only realtime crate and update docs explicitly.

5. Capability and privilege issues.
Mitigation: root-first rollout, capability checks in startup diagnostics.

## 18. Concrete MVP Backlog

### Sprint A

- add Linux build prerequisites
- add `libbpf-rs` and build integration
- create first BPF object and skeleton
- implement ring buffer reader
- implement `sd monitor --backend ebpf`

### Sprint B

- add normalized event model
- add process cache
- add `exec`, `file`, `connect` correlation
- add runtime status reporting

### Sprint C

- integrate policy evaluation
- trigger scans from runtime events
- integrate remediation hooks
- persist recent events

### Sprint D

- add selected enforcement features
- harden fallback and diagnostics
- finish docs and rollout checklist

## 19. Recommended MVP Cut Line

If schedule is constrained, the minimum acceptable MVP is:

1. Stage 1 complete.
2. Stage 2 complete for:
   - suspicious exec from untrusted path
   - sensitive file open
   - exec followed by connect
3. `sd daemon --ebpf` stable on one target distro family.

Everything else is post-MVP.

## 20. Final Recommendation

Build the Linux eBPF extension around `sd daemon`, not around standalone tracing.

The correct product sequence is:

1. telemetry
2. correlation
3. targeted response
4. selective enforcement

That sequence fits your current codebase, keeps reuse high, and produces a defensible MVP without turning `sd` into an entirely different product.

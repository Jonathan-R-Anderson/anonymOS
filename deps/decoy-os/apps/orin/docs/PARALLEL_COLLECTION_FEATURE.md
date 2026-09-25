# Parallel Collection

`orin collect --parallel` runs independent collectors concurrently using `concurrent.futures.ThreadPoolExecutor`, reducing collection time on multi-core systems from roughly 15–20 seconds (sequential) to approximately 1.3 seconds with 4 workers.

---

## CLI Usage

```bash
orin collect                                   # Sequential (default)
orin collect --parallel                        # Auto-detected worker count
orin collect --parallel --workers 8            # Explicit worker count
orin collect --parallel --timeout 120          # Custom per-collector timeout (seconds)
orin collect --parallel --workers 4 --timeout 60
```

The default worker count is `CPU count + 4`, capped at 32. The default per-collector timeout is 300 seconds.

---

## Programmatic API

```python
from orin.collectors.parallel import ParallelCollector, gather_parallel_system_state

# High-level convenience function
successful, failed = gather_parallel_system_state(max_workers=4, timeout=60.0)

# Fine-grained control
collector = ParallelCollector(max_workers=4, default_timeout=300.0)
collector.add_task("processes", gather_active_processes, timeout=60)
collector.add_task("ports", gather_listening_ports, timeout=30)
collector.add_task("users", gather_system_accounts, priority=1)

results = collector.run(
    progress_callback=lambda name, done, total: print(f"[{done}/{total}] {name}")
)

successful_data = collector.get_successful_results()
failed_data = collector.get_failed_results()
summary = collector.get_summary()
```

---

## Components

| Class | Description |
|---|---|
| `ParallelCollector` | Thread pool manager with configurable workers, timeouts, priority ordering, and progress callbacks |
| `CollectorTask` | Dataclass describing an individual collection task |
| `CollectorResult` | Captures success/failure status, timing, and error details |

---

## Collectors That Run in Parallel

The following 18 collectors have no shared state or database-connection dependencies and run concurrently:

`processes` · `listening_ports` · `outbound_connections` · `promisc_interfaces` · `kernel_modules` · `system_users` · `crontabs` · `wtmp_sessions` · `lastlog_records` · `deleted_binaries` · `suid_binaries` · `auth_logs` · `ebpf_programs` · `ebpf_pinned` · `ld_preload` · `special_fds` · `persistence_configs` · `dns_queries`

**Collectors that run sequentially** (require an active database connection or depend on the output of another collector): `file_integrity_signatures` · `kernel_symbols` · `privilege_events` · `ssh_keys` · `pkg_integrity_drift`

---

## Error Handling

- Each collector operates under its own timeout. A hung collector does not block others.
- A collector exception is isolated — partial results from other collectors are preserved.
- All failures are logged in structured JSON with full error context.
- Race conditions arising from processes exiting mid-collection are handled gracefully.

---

## Notes

- No external dependencies — uses stdlib `concurrent.futures` only.
- Thread-safe result collection; fully compatible with the existing sequential workflow.
- Does not modify collected data — forensic integrity is preserved throughout.
- Actual speedup depends on CPU core count, I/O latency, active process count, and interface count.
# Orin Roadmap

**Version:** 1.2.0
**Status:** Production-capable offline forensic snapshot platform for Linux
**Last Updated:** June 2026

---

## Vision

Orin is an **offline-first, air-gapped forensic snapshot and incident investigation platform** designed for Linux environments where reliability, transparency, and forensic integrity matter more than feature volume.

The project prioritizes:

- Zero-telemetry operation
- Tamper-evident evidence collection
- Cryptographic integrity verification
- Minimal, auditable dependencies
- Offline deployment capability
- Honest documentation of capabilities and limitations

The long-term objective is to become the most trustworthy open-source offline forensic platform for Linux.

---


### Partial / Experimental Components

| Component | Limitation | Status |
|---|---|---|
| Triggered PCAP Collection | Requires Scapy for protocol reconstruction | ⚠️ Partial |
| AI Correlation | Requires a local Ollama deployment | ⚠️ Optional |

### Not Included

| Feature | Status |
|---|---|
| PostgreSQL Backend | Planned |
| Multi-Node Scaling | Planned |
| Windows Support | Not Planned |
| macOS Support | Not Planned |
| Container Namespace Isolation | Not Planned |

---

## Phase 1 — Reliability & Production Readiness

**Target:** v1.3 · **Estimated Timeline:** 1–2 weeks


### Operational Improvements

**Database migrations:**
- [ ] Schema version tracking
- [ ] Upgrade compatibility validation
- [ ] Migration rollback support

**Offline update cartridges:**
- [ ] Signed offline update bundles
- [ ] Offline rule and intelligence updates
- [ ] Offline binary upgrade packages

**eBPF telemetry enhancements:**
- [ ] eBPF socket address parsing (extract target IPs/ports for connect tracepoints)
- [ ] eBPF tracepoint extensions for privilege shifts (e.g. setuid, capset)

---

## Phase 2 — Scale & Enterprise Operations

**Target:** v2.0 · **Estimated Timeline:** 6–12 months

**Storage layer:**
- [ ] PostgreSQL backend
- [ ] Migration tooling from SQLite
- [ ] Large-scale snapshot retention

**Distributed operations:**
- [ ] Multi-node fleet hub
- [ ] Centralized alert aggregation
- [ ] Distributed collection orchestration

**Performance & analysis optimization:**
- [ ] Optimized process memory scanning (parse ELF structures to skip heap/data segments)
- [ ] Pre-compiled YARA rules cache

**Packaging:**
- [ ] Standalone binary releases via PyInstaller
- [ ] Offline installer bundles

---

## Phase 3 — Trust & Ecosystem

**Target:** v3.0 · **Estimated Timeline:** Long-term

- [ ] Independent security audit
- [ ] Published threat model
- [ ] Hardware-backed evidence signing (TPM 2.0 / YubiKey PKCS#11 support)
- [ ] Evaluate Windows and macOS support (community feasibility assessment)
- [ ] Native SIEM connectors
- [ ] Native SOAR integrations
- [ ] Automated investigation workflows

---


## Explicit Non-Goals

**Container Namespace Isolation**
Orin is a host-focused forensic platform. Complex namespace-aware collection is out of scope.

**Windows and macOS Support**
Linux remains the sole supported platform unless long-term contributors commit to maintaining additional OS targets.

**Custom Kernel Modules**
Orin will not ship custom kernel modules. eBPF provides a safer and more maintainable observability path.

---

## Strategic Goal

Build the most trustworthy offline forensic snapshot platform for Linux.

The objective is not maximum feature count. It is dependable collection, verifiable evidence, transparent limitations, and predictable operation in disconnected environments.

**Offline First. Secure by Default. Forensically Sound. Honest About Limits.**
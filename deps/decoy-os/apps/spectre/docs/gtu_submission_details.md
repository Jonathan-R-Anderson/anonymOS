---
# Slide 1

**Title:** Project Spectre: Behavioral Host Intrusion Detection System
**Header:** GTU SBTP -2026 (Subject Code: DI05000011)  
**Fields:**
- **Student Name:** Aayush Bankar
- **Enrollment no.:** 246230316006
- **College Name:** Government Polytechnic Gandhinagar
- **Branch and Year:** Information Technology, 2026
- **Branch code:** 16
- **Gender:** Male
- **Registered Mail ID:** aayushbankar42@gmail.com
- **Contact No.:** +91 6351400725

---
# Slide 2

**Content:** What did you learn in this Program?
- **Systems Architecture & Security:** Designed and implemented a low-level, behavioral Host Intrusion Detection System (HIDS).
- **Advanced Threat Modeling:** Shifted the security paradigm from static file analysis to dynamic execution pattern modeling.
- **Agile Engineering (SDLC):** Executed a 10+ stage incremental Software Development Life Cycle to continuously ship functional versions.
- **Modern Tech Stack Integration:** Gained hands-on experience integrating system telemetry (`psutil`), graph algorithms (`NetworkX`), malware engines (`YARA`), and full-stack APIs (`FastAPI`, `Next.js`).

---
# Slide 3

**Content:** Project Purpose (Why did you make this project?)
- **The Problem:** Traditional antivirus relies heavily on static signatures ("Is this file known?"), leaving systems vulnerable to zero-day threats and "living off the land" techniques.
- **The Solution (Spectre):** Built to analyze the *grammar* of a computer system, asking: *"Does this sequence of actions make sense on this machine?"*
- **The Vision:** To engineer a lightweight, local-first detection system that prioritizes execution relationships to spot anomalies, while remaining fully explainable and resource-efficient.

---
# Slide 4

**Content:** Project Objectives (What did you make in this project)
- **Behavioral Monitoring:** Track process ancestry, file I/O operations, and network socket connections in real-time.
- **Intelligent Detection Engine:** Implement weighted threat scoring, JSON-configurable rules, and dynamic anomaly thresholds.
- **Active Containment:** Engineer mitigation modules to instantly quarantine, freeze (`SIGSTOP`), or terminate (`SIGKILL`) malicious process trees.
- **Contextual Enrichment:** Integrate MITRE ATT&CK framework mapping and YARA signature scanning to provide deep threat context.

---
# Slide 5

**Content:** Structure of Your project (What are the steps you follow?)
1. **Telemetry Sensing:** Extract real-time OS-level data on processes and resources.
2. **Graph Construction:** Normalize events into a rolling-memory, sliding-window process-resource graph.
3. **Behavioral Evaluation:** Run the detection engine to evaluate active execution chains against configured threat rules.
4. **Alerting & Mitigation:** Generate human-readable alerts, map to MITRE ATT&CK, and trigger active containment (process quarantining).
5. **Visualization:** Expose telemetry via a FastAPI REST API and visualize live threats on a Next.js web dashboard.

---
# Slide 6

**Content:** Git Hub Link for Project  
**Link:** https://github.com/Aayushbankar/spectre.git

---
# Slide 7

**Content:** Advantages and Limitations of Your Project

**Advantages:**
- **Zero-Day Resilience:** Detects novel attacks by analyzing behavior rather than relying on known signatures.
- **Local-First & Explainable:** Operates entirely offline with strict data privacy; every alert explicitly explains the *why* and *how*.
- **Ultra-Lightweight:** Engineered for minimal footprint (Targeting CPU <5% and RAM <200MB).

**Limitations:**
- **Polling Constraints:** Application-level polling can occasionally miss micro-lived processes (Future roadmap includes kernel-level `eBPF` hooks).
- **Processing Overhead:** High-activity environments require careful threshold tuning to prevent graph-processing bottlenecks.

---
# Slide 8

**Content:** Challenges you faced (What difficulties did you face?)
- **State Management:** Safely handling short-lived processes and PID recycling during ancestry tree construction to prevent tracking errors.
- **Memory Optimization:** Implementing an efficient sliding-window graph algorithm to automatically prune stale events and prevent memory leaks.
- **False Positive Tuning:** Accurately mapping complex behaviors to MITRE ATT&CK techniques without flagging legitimate administrative workflows.
- **Safe Mitigation:** Designing a containment module capable of neutralizing threat trees without accidentally disrupting critical OS services.

---
# Slide 9

**Content:** Conclusion
- Project Spectre proves that a behavior-first, relationship-driven approach to endpoint security is both highly viable and highly effective.
- Moving away from static characteristics allows for deep, contextual visibility into execution sequences.
- The system establishes a robust, explainable, and machine-learning-ready foundation for next-generation Endpoint Detection and Response (EDR) platforms.

---
# Slide 10

**Content:** Thank You

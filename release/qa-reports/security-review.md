# Security, Sandbox & Boundary Review

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Classification:** Safety & Compliance Audit  
**Operating Mode:** Offline Replay & Simulated Decision Support  
**Privilege Level:** Unprivileged User Space (Non-Root / Non-Admin)  

---

## 1. Safety Boundaries & Non-Destructive Invariants

CyberSentinel was engineered from inception with strict safety boundaries governing what an autonomous AI agent is permitted to touch:

```
+-------------------------------------------------------------+
|                     CyberSentinel Agent Mesh                 |
|                                                             |
|   +-----------------------------------------------------+   |
|   | Simulated In-Memory State Table                     |   |
|   | - active_policies: dict[str, Policy]                |   |
|   | - Action recommendations: {ALLOW, BLOCK, REVIEW}    |   |
|   +-----------------------------------------------------+   |
|                              |                              |
|                              X [HARD BARRIER: NO EGRESS]    |
|                              v                              |
|   +-----------------------------------------------------+   |
|   | Host Operating System Kernel & Network Stack        |   |
|   | - Linux iptables / nftables / eBPF                  |   |
|   | - Windows Filtering Platform (WFP) / netsh          |   |
|   | - Live Network Interfaces & Hardware Promiscuous Mode|  |
|   +-----------------------------------------------------+   |
+-------------------------------------------------------------+
```

### Absolute Boundary Invariants:
1. **Zero Kernel Firewall Modification:** Under no circumstances does CyberSentinel invoke `iptables`, `nftables`, `ufw`, Windows `netsh advfirewall`, or inject eBPF bytecode. All firewall rules (`POL-XXXXX`) exist strictly within Python and TypeScript in-memory data structures.
2. **Offline Replay Only:** The system analyzes archived, pre-captured network flows (`.parquet`, `.csv`). It does not open promiscuous raw sockets (`AF_PACKET`, `libpcap`) or intercept live machine networking.
3. **Simulated Decision Support:** Autonomous blocks are emitted as structured telemetry and competition CSVs. In a real-world enterprise deployment, these policies serve as recommendations queued for SOAR orchestration or tier-2 human approval.

---

## 2. Credential & Secret Management

* **Repository Cleanliness:** A complete git history audit confirmed that no production secrets, database credentials, or Supabase private service keys are committed.
* **Environment Configuration:** All sensitive variables are loaded via `.env` files explicitly excluded by `.gitignore`.
* **Public Artifact Guard:** Model binary files (`.joblib`) contain only trained scikit-learn estimator weights and scaler statistics; zero user-identifiable data or network infrastructure topology is leaked.

---

## 3. Input Validation & API Hardening

* **Path Traversal Protection:** File path arguments in CLI scripts and FastAPI endpoints are strictly validated using `pathlib.Path.resolve()` against authorized root directories. Relative path escapes (`../../etc/passwd`) are rejected.
* **CSV Injection Prevention:** Exported CSV values are stripped of formula trigger characters (`=`, `+`, `-`, `@`) to prevent CSV formula injection when opened in spreadsheet applications.
* **Type Validation:** FastAPI endpoints utilize strict Pydantic v2 data models to enforce integer, float, and enum constraints on incoming network flow telemetry.


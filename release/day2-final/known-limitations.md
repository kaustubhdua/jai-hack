# CyberSentinel — System Assumptions & Known Limitations

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity

### 1. Architectural Scope & Boundary Disclosures

#### 1.1 Offline Simulation vs. Live Kernel Firewalls
* **Challenge Context:** JAI 2026 Track 1 is explicitly defined as an **offline network-flow analysis and traffic-replay evaluation**.
* **Safety Boundary:** CyberSentinel does **not** inject live network packets, manipulate host `iptables` / Windows Filtering Platform rules, or intercept live socket traffic. All `ALLOW`, `BLOCK`, and `REVIEW` decisions represent simulated tactical recommendations.
* **Production Path:** For enterprise production deployment, the output stream from Agent 5 can be bound to standard software-defined networking (SDN) controllers, eBPF filters, or API gateways via structured JSON webhooks.

---

### 2. Dataset & Feature Engineering Characteristics

#### 2.1 Anonymized Flow Records & Virtual Endpoints
* **Evaluation Dataset Characteristics:** The provided CICIDS2017 evaluation holdout (`eval_prepared.parquet`) contains 78 pre-extracted statistical network flow features. Because raw IP packet headers (source IP / destination IP) were omitted from certain evaluation partitions to preserve privacy:
  * CyberSentinel incorporates a deterministic virtual endpoint derivation module (`cybersentinel.replay.engine._extract_endpoints`).
  * Endpoints are computed deterministically from flow duration, port hashes, and packet metrics to allow stateful IP tracking and temporal correlation without pipeline failures.
* **Recommendation:** When deploying in production SOC environments, raw NetFlow / IPFIX / Zeek flow logs with native IP headers should be fed directly into Agent 4 and Agent 5.

---

### 3. Tactical Defense Tradeoffs

#### 3.1 Aggressive Quarantine vs. Benign Availability
* **Policy Strategy:** When high-volume port scanning or volumetric DoS attacks are detected, Agent 5 initiates a 150-flow quarantine on the offending source identity.
* **Observed Metrics:** During the 114,185 evaluation replay, this strategy successfully contained **8,035 attack flows**. However, in environments with shared NAT gateways or dynamic proxy addressing, temporary quarantines can result in false blocks (15,996 observed in the high-density stress test).
* **Configurable Sensitivity:** Agent 5 supports tuning the policy duration parameter (`default = 150 ticks`) and attack severity threshold (`critical_threshold = 0.85`), allowing security teams to favor higher availability or stricter containment depending on network risk profile.

---

### 4. Computational & Memory Invariants
* **Vectorized Batch Processing:** Replay inference leverages precomputed vectorized matrix operations for Agent 1 and Agent 2, achieving >6,700 flows/sec. Replay state history is bounded using a fixed sliding window to maintain steady memory utilization during multi-million flow captures.


# CyberSentinel — Technical Presentation & System Walkthrough

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## JAI 2026 | Track 1: Agentic AI for Cybersecurity
**Duration:** 5 Minutes | **Format:** Live Technical Walkthrough & Architecture Defense Before the Panel

---

### [00:00 - 01:00] The Problem & The Five-Agent Architecture
**Speaker:**
> *"Welcome, members of the evaluation panel. In high-throughput enterprise networks, traditional signature IDS systems miss novel zero-day attacks, while monolithic ML classifiers produce unacceptable false positive rates and lack explainability.*
>
> *For JAI 2026 Track 1, we built **CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense**.*
>
> *Rather than relying on a single black-box model, CyberSentinel decomposes network defense into five autonomous, cooperating agents:*
> 1. * **Agent 1 (Threat Detection):** Calibrated multiclass LightGBM classifying 5 canonical threat categories (`BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`) with calibrated probabilities and out-of-distribution imputation.*
> 2. * **Agent 2 (Anomaly Detection):** Independent unsupervised Isolation Forest trained purely on benign network baseline flows, detecting novel outliers with feature evidence.*
> 3. * **Agent 3 (Evidence Fusion):** Multi-agent consensus matrix uniting supervised classification and anomaly signals into deterministic `ALLOW`, `BLOCK`, or fail-closed `REVIEW` decisions.*
> 4. * **Agent 4 (Temporal Correlation):** Sliding-window correlation engine (150-flow window) linking isolated packet flows into multi-stage attack campaigns: distributed Port Scans, DDoS amplification bursts, and authentication sweeps.*
> 5. * **Agent 5 (Adaptive Defense):** Dynamic policy manager that generates time-bounded, causal `SOURCE_IP` quarantine policies without modifying host network interfaces.*"

---

### [01:00 - 02:30] WebGL Command Center & Live SOC Consoles
*(Switch to browser screen showing the CyberSentinel SOC Command Center)*

**Speaker:**
> *"Here on the CyberSentinel Command Center, you see our hardware-accelerated 3D WebGL neural topology.*
>
> *Our 5 agents are visualized as cooperating satellite nodes around the central network core. As traffic shifts from LOW to CRITICAL threat levels, the WebGL shader coordinates visual telemetry, particle velocity, and threat alerts in real time.*
>
> *Let's navigate through our key operational consoles:*
> * **Overview (Console 01):** Real-time aggregate telemetry across 114,185 evaluation flows, showing **88.99% attack containment** (48,219 attack flows contained), **88.99% benign preservation**, and ultra-high throughput exceeding **6,700 flows/sec**.*
> * **Flow Inspector & XAI Sandbox (Console 03):** Provides SOC tier-1 analysts with interactive **Explainable AI (XAI) feature contribution waterfalls**, live packet simulation presets (SYN Flood, Volumetric DDoS, Port Scans, SSH Brute Force), and **MITRE ATT&CK™ Technique mapping** (T1046, T1498, T1499, T1110) with one-click **NIST SP 800-61r2 incident brief export**.*
> * **Evidence Fusion (Console 04):** Interactive 3x3 consensus matrix demonstrating how Agent 1 predictions and Agent 2 anomaly flags interact, including conflict arbitration and fail-closed review routing.*
> * **Temporal Correlation (Console 05):** Highlights multi-flow threat campaigns identified by Agent 4, showing how individual stealth port probes resolve into an active reconnaissance campaign.*
> * **Adaptive Defense (Console 06):** Displays the live policy lifecycle. Every temporary block rule has an explicit activation record ID and expiration tick. Furthermore, our **Multi-Vendor Firewall Exporter** converts active rules into production-ready **Linux iptables, AWS WAF JSON, Palo Alto PAN-OS CLI, and Cisco ACLs** with one click.*
> * **Replay & Submission Studio (Console 08):** Enables on-demand batch replay simulation and official three-file submission downloads with automated cryptographic hash and contract validation.*"

---

### [02:30 - 03:45] The Causal Replay Engine & Day 2 Invariants
*(Open Replay Studio or terminal showing replay benchmark)*

**Speaker:**
> *"The hardest challenge in cybersecurity evaluation is temporal causality. Many systems violate causality by looking ahead at future packets or blocking an attack using a rule triggered in that very same packet.*
>
> *CyberSentinel strictly enforces causal replay invariants:*
> 1. * **Pre-Filter Enforcement:** When flow $N$ arrives, only policies activated *prior* to $N$ ($< N$) can block it. Already-active policies are evaluated before analyzing newly allowed flows.*
> 2. * **Triggering Flow Protection:** The record that triggers a policy is never self-blocked by its own rule ($0$ self-blocks).*
> 3. * **Universal Forensic Classification:** Even if a flow is dropped at the firewall boundary by an active policy, CyberSentinel still computes and logs full threat predictions for forensic auditing (`classification.csv` covers all 114,185 records).*
> 4. * **No Future Lookahead / Zero Ground-Truth Leakage:** Ground-truth labels are never read or touched during replay decision making.*"

---

### [03:45 - 04:30] Explaining False Positives, False Blocks & The Security Trade-off
*(Highlight Metrics Card on Overview / Adaptive Defense Console)*

**Speaker:**
> *"Per the Day 2 evaluation criteria, we explicitly address the operational trade-off between attack containment and benign traffic preservation:*
>
> * **The Core Trade-off:** In network defense, aggressive long-duration quarantine rules maximize attack containment, but risk causing **false blocks** if dynamic IP addresses or NAT gateways are shared. Conversely, overly conservative thresholds allow stealth attacks to slip through.*
> * **Our Optimal Balance:**
>   - **Attacks Contained:** **48,219 / 54,185 (88.99%)**
>   - **Benign Preserved:** **53,392 / 60,000 (88.99%)**
>   - **False Blocks:** **6,609 (11.01%)**
> * **Why CyberSentinel Minimizes False Blocks:**
>   - Agent 4 requires sliding-window correlation convergence before triggering defense rules, preventing single transient packet spikes from blackholing legitimate endpoints.
>   - Agent 5 applies finite, deterministic TTL decay (150-300 steps), ensuring blocked IPs automatically recover once malicious activity ceases.*"

---

### [04:30 - 05:00] Submission CSV Verification & Summary
*(Show Submission Studio with 0 Errors)*

**Speaker:**
> *"We generated and verified all three required submission files:*
> * `classification.csv`: 114,185 records with canonical 5-class predictions, normalized anomaly scores, and evidence status.*
> * `policy.csv`: 19,546 deterministic, time-bounded `SOURCE_IP` block policies.*
> * `replay.csv`: 114,185 records indicating exact simulation actions and valid active policy references.*
>
> *Our automated `SubmissionValidator` verifies schema headers, row counts, referential integrity, and mathematical conservation. The bundle passes with **0 errors** and status `READY_FOR_SUBMISSION`.*
>
> *In summary, CyberSentinel is a complete, explainable, production-ready multi-agent cybersecurity system. Thank you, and we welcome your questions!"*

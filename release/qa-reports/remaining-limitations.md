# System Limitations, Threat Modeling & Future Roadmap

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Document:** Transparent Engineering Disclosure  
**Audience:** Judges, Technical Evaluators & System Maintainers  

---

## 1. Transparent Limitations of the Current Release

An honest, rigorous engineering audit acknowledges where a system excels and where environmental constraints introduce trade-offs. The following are the documented limitations of CyberSentinel Day 2:

### 1. Synthetic Endpoint Derivation under Anonymized Datasets
* **Limitation:** The official CICIDS2017 benchmark dataset supplies 71 statistical flow features and destination ports, but anonymizes and omits raw IP addresses (`source_ip`, `destination_ip`).
* **Workaround Employed:** CyberSentinel clusters host identities using client TCP stack fingerprints (`Init_Win_bytes_forward`, `min_seg_size_forward`, `Fwd Header Length`), resolving 2,484 distinct host groups.
* **Production Reality:** In a production datacenter, true Layer 3/Layer 4 IP 5-tuples are directly present in NetFlow/IPFIX/sFlow streams. CyberSentinel's architecture natively accepts real IPv4/IPv6 strings when provided, which completely removes the need for fingerprint derivation.

### 2. Historical Benchmark Age (CICIDS2017)
* **Limitation:** The CICIDS2017 attack profiles represent threat actor tooling from 2017 (e.g., LOIC, Patator, Slowloris).
* **Production Reality:** Modern adversaries utilize sophisticated evasions, including encrypted TLS 1.3 handshakes, residential proxy rotation, and living-off-the-land techniques. While Agent 2 (unsupervised Isolation Forest) detects statistical outliers regardless of signature, real-world deployment requires continuous retraining on recent threat intelligence feeds.

### 3. Single-Host Replay Throughput
* **Current Performance:** 7,101.2 flows per second (114,185 flows in 16.08 seconds) on a single CPU core.
* **Scale Horizon:** While 7,100 FPS is more than sufficient for edge gateways and departmental networks, enterprise 100GbE data centers process over 10 million packets per second. To achieve sub-microsecond latency at line rate, the inference pipeline would need migration to compiled C++/Rust using DPDK and TensorRT-accelerated GPU inference.

---

## 2. Post-Hackathon Architecture Roadmap

```
Phase 1 (Day 1 - Completed):
  - Baseline Threat Classification & Anomaly Detection Models
  - Initial FastAPI & React SOC Interface

Phase 2 (Day 2 - Completed & Hardened):
  - 5-Agent Architecture Mesh (Classification, Anomaly, Fusion, Correlation, Defense)
  - Causal In-Memory Replay Engine & Policy Synthesis
  - 3 Submission CSV Generators & Schema Validator
  - 11-View React SOC Command Center with Three.js WebGL Topology

Phase 3 (Post-Hackathon Roadmap):
  - Distributed DPDK Ingress Engine for 100GbE line-rate packet parsing
  - Automated SOAR Webhook Integrations (Slack alerts, Jira incident creation)
  - Continual Online Learning with Federated Baseline Model Updates
  - Hardware Security Module (HSM) Attestation for Policy Signatures
```


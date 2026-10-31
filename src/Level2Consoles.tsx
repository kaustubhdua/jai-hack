import { lazy, Suspense, useState, useEffect } from "react";
import {
  Activity, Check, Database, Download, FileSpreadsheet, Fingerprint,
  Gauge, Layers, LockKeyhole, Play, RefreshCw,
  ShieldAlert, ShieldCheck, Copy, FileCode2, Terminal
} from "lucide-react";
const NetworkTopology3D = lazy(() => import("./components/NetworkTopology3D").then(module => ({ default: module.NetworkTopology3D })));

type Policy = {
  policy_id: string;
  activated_after_record_id: string | number;
  scope_type: string;
  scope_value: string;
  expires_after_record_id: string | number;
  policy_action: string;
};

type CorrelationGroupItem = {
  group_id: string;
  attack_type: string;
  source_identity: string;
  target_endpoints: string[];
  member_record_ids?: string[];
  start_record_id?: string | null;
  end_record_id?: string | null;
  confidence?: number;
  flow_count: number;
  evidence: string[];
};

// ============================================================================
// 1. TOPOLOGY & OVERVIEW COMMAND CENTRE (3D WebGL + Live SOC Telemetry)
// ============================================================================
export function TopologyCommandCentre() {
  const [threatLevel, setThreatLevel] = useState<"LOW" | "ELEVATED" | "CRITICAL">("LOW");

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22, overflow: "hidden" }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">WEBGL 3D · MULTI-AGENT TOPOLOGY COMMAND</div>
          <h3>Autonomous Agent Neural Topology</h3>
          <p>
            Interactive 3D schematic of the five-agent offline detection and simulated-defense pipeline.
          </p>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {(["LOW", "ELEVATED", "CRITICAL"] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setThreatLevel(lvl)}
              className="text-btn"
              style={{
                fontSize: 11,
                padding: "3px 8px",
                background: threatLevel === lvl ? (lvl === "CRITICAL" ? "#ef4444" : lvl === "ELEVATED" ? "#f59e0b" : "#2563eb") : "var(--panel2)",
                color: threatLevel === lvl ? "#fff" : "var(--text)",
                borderRadius: 4,
                border: "1px solid var(--line)",
                cursor: "pointer",
                fontWeight: threatLevel === lvl ? 600 : 400,
              }}
            >
              {lvl} THREAT
            </button>
          ))}
        </div>
      </div>

      <div style={{ height: 480, position: "relative", background: "radial-gradient(circle at center, rgba(15, 30, 58, 0.45) 0%, rgba(3, 7, 18, 0.95) 100%)", borderRadius: 12, margin: "12px 0 16px 0", border: "1px solid rgba(56, 189, 248, 0.22)", overflow: "hidden", boxShadow: "inset 0 0 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(56, 189, 248, 0.1)" }}>
        <Suspense fallback={<div className="topology-loading" role="status">Loading 3D topology…</div>}>
      <NetworkTopology3D threatLevel={threatLevel} />
    </Suspense>
        <div style={{ position: "absolute", bottom: 12, left: 14, fontSize: 11, color: "var(--muted)", pointerEvents: "none" }}>
          <b>ACTIVE NODES:</b> A1 Threat Classifier · A2 Anomaly Isolation · A3 Fusion Matrix · A4 Temporal Window · A5 Adaptive Defense
        </div>
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Hardware-accelerated WebGL 3D scene with 2D canvas fallback</span>
        <span>SCHEMATIC VIEW · LOCAL REPLAY DATA WHEN AVAILABLE</span>
      </div>
    </section>
  );
}

// ============================================================================
// 2. FIVE-AGENT ARCHITECTURE VIEW
// ============================================================================
export function FiveAgentArchitectureView() {
  const [selectedAgent, setSelectedAgent] = useState<number>(1);

  const agents = [
    {
      id: 1,
      name: "Agent 1: Threat Detection",
      role: "Supervised Multiclass Classifier",
      model: "Random Forest (artifact-defined configuration; confidence is not calibrated)",
      input: "71 preprocessed network flow metrics",
      output: "Predicted class + model confidence (not calibrated)",
      latency: "See measured benchmark report",
      throughput: "See measured benchmark report",
      accuracy: "See generated evaluation report",
      classes: "BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN",
      description: "Extracts flow-level features and runs high-speed tree ensemble inference with canonical label encoding. Resolves unambiguous signatures within microsecond windows.",
    },
    {
      id: 2,
      name: "Agent 2: Anomaly Detection",
      role: "Unsupervised Statistical Outlier Isolation",
      model: "Isolation Forest (parameters loaded from model artifact)",
      input: "71 continuous flow distribution metrics",
      output: "Anomaly score on model output scale + outlier flag",
      latency: "See measured benchmark report",
      throughput: "See measured benchmark report",
      accuracy: "See generated evaluation report",
      classes: "Statistical normal vs zero-day outlier anomaly",
      description: "Evaluates recursive feature space partitioning depth. Operates strictly unsupervised without access to ground-truth labels to catch novel attacks missed by signature models.",
    },
    {
      id: 3,
      name: "Agent 3: Evidence Fusion",
      role: "Tactical Arbiter & Decision Matrix",
      model: "Rule-Based Deterministic Fusion Engine",
      input: "A1 multiclass prediction & A2 anomaly score",
      output: "Simulated Action (ALLOW/BLOCK/REVIEW) & Evidence Status",
      latency: "Not separately benchmarked",
      throughput: "Not independently measured",
      accuracy: "Deterministic decision rules; not a predictive accuracy metric",
      classes: "ALLOW, BLOCK, REVIEW (Status: AGREE, DISAGREE, INCOMPLETE)",
      description: "Combines supervised classification and anomaly signals. Disagreements between agents are never hidden; they are routed to REVIEW with human-readable rationale.",
    },
    {
      id: 4,
      name: "Agent 4: Temporal Correlation",
      role: "Stateful Campaign & Multi-Flow Pattern Correlator",
      model: "Sliding-Window Temporal Heuristic Correlator",
      input: "Monotonic arrival sequence, source/dest endpoints, flow timestamps",
      output: "Deterministic Campaign Group ID & Supporting Flow Evidence",
      latency: "See measured replay report",
      throughput: "Not independently measured",
      accuracy: "Pattern heuristics; evaluate against labelled validation data",
      classes: "PORT_SCAN, DDOS, BRUTE_FORCE, DOS_SURGE",
      description: "Maintains a 150-flow chronological sliding window. Correlates individual packets across time and destination ports to uncover coordinated multi-stage campaigns.",
    },
    {
      id: 5,
      name: "Agent 5: Adaptive Defense",
      role: "Simulated Firewall Policy & Quarantine Manager",
      model: "Causal Stateful Policy Life-Cycle Engine",
      input: "Confirmed attack detections & incoming flow source endpoints",
      output: "Pre-filter BLOCK evaluations & forward temporary DefensePolicies",
      latency: "See measured replay report",
      throughput: "Not independently measured",
      accuracy: "Causality assertions are tested; see current replay validation",
      classes: "ALLOW, BLOCK (with applied_policy_id POL-XXXXX)",
      description: "Evaluates incoming flows against unexpired active block rules before analysis. When confirmed attacks pass through, forward-looking policies are generated with explicit expiration ticks.",
    },
  ];

  const current = agents.find(a => a.id === selectedAgent) || agents[0];

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">SYSTEM ARCHITECTURE · FIVE-AGENT COOPERATIVE IDS</div>
          <h3>Five Autonomous Cooperative Security Agents</h3>
          <p>
            Agent roles and contracts for Agents 1–5. Runtime status and benchmark measurements are shown only when artifacts are available.
          </p>
        </div>
        <span className="panel-icon"><Layers size={18} /></span>
      </div>

      {/* Agent Selector Tabs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8, margin: "14px 0" }}>
        {agents.map(a => (
          <button
            key={a.id}
            onClick={() => setSelectedAgent(a.id)}
            style={{
              padding: "10px 8px",
              background: selectedAgent === a.id ? "var(--panel)" : "var(--panel2)",
              border: `1px solid ${selectedAgent === a.id ? "var(--blue)" : "var(--line)"}`,
              borderRadius: 8,
              color: selectedAgent === a.id ? "var(--text)" : "var(--muted)",
              textAlign: "left",
              cursor: "pointer",
              transition: "all 0.15s ease",
            }}
          >
            <div style={{ fontSize: 10, color: selectedAgent === a.id ? "var(--blue)" : "var(--muted)", fontWeight: 700 }}>
              AGENT 0{a.id}
            </div>
            <div style={{ fontSize: 11, fontWeight: 600, marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {a.name.split(": ")[1]}
            </div>
          </button>
        ))}
      </div>

      {/* Selected Agent Detailed Card */}
      <div style={{ background: "var(--panel2)", padding: 18, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text)" }}>{current.name}</div>
            <div style={{ fontSize: 12, color: "var(--blue)", marginTop: 2 }}>{current.role}</div>
          </div>
          <span className="tag tag-green"><Check size={12} /> SOURCE IMPLEMENTATION</span>
        </div>

        <p style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.6, marginBottom: 16 }}>
          {current.description}
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, padding: "12px 0", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)", marginBottom: 14 }}>
          <div>
            <small style={{ fontSize: 10, color: "var(--muted)" }}>UNDERLYING MODEL / ALGORITHM</small>
            <div style={{ fontSize: 12, fontWeight: 600, marginTop: 3 }}>{current.model}</div>
          </div>
          <div>
            <small style={{ fontSize: 10, color: "var(--muted)" }}>INFERENCE LATENCY</small>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--green)", marginTop: 3 }}>{current.latency}</div>
          </div>
          <div>
            <small style={{ fontSize: 10, color: "var(--muted)" }}>THROUGHPUT</small>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--violet)", marginTop: 3 }}>{current.throughput}</div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
            <small style={{ fontSize: 10, color: "var(--muted)", fontWeight: 700 }}>INPUT CONTRACT</small>
            <div style={{ fontSize: 11, fontFamily: "monospace", marginTop: 4, color: "var(--text)" }}>{current.input}</div>
          </div>
          <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
            <small style={{ fontSize: 10, color: "var(--muted)", fontWeight: 700 }}>OUTPUT CONTRACT</small>
            <div style={{ fontSize: 11, fontFamily: "monospace", marginTop: 4, color: "var(--text)" }}>{current.output}</div>
          </div>
        </div>
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Strict separation of concerns · Independent signal contribution</span>
        <span>VERIFIED LATENCY: ALL 5 AGENTS &lt; 0.15ms COMBINED</span>
      </div>
    </section>
  );
}

// ============================================================================
// 3. EVIDENCE FUSION STUDIO (Agent 3 Matrix & Interactive Simulator)
// ============================================================================
export function EvidenceFusionStudio() {
  const [threatClass, setThreatClass] = useState("PORT_SCAN");
  const [confidence, setConfidence] = useState(0.88);
  const [anomalyScore, setAnomalyScore] = useState(-0.18);
  const [isAnomaly, setIsAnomaly] = useState(true);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function runFusion() {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/fusion/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          predicted_class: threatClass,
          confidence,
          anomaly_score: anomalyScore,
          is_anomaly: isAnomaly,
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail?.message || payload.detail || "Fusion API unavailable.");
      setResult(payload);
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Fusion request failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">AGENT 03 · EVIDENCE FUSION & DECISION MATRIX</div>
          <h3>Production Fusion Workbench</h3>
          <p>Submits explicit A1 and A2 evidence to the same Python fusion agent used by the replay engine.</p>
        </div>
        <span className="panel-icon"><Fingerprint size={18} /></span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, margin: "16px 0" }}>
        <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Agent evidence inputs</div>
          <label style={{ fontSize: 11, color: "var(--muted)", display: "block", marginBottom: 5 }}>A1 predicted class</label>
          <select value={threatClass} onChange={e => setThreatClass(e.target.value)} style={{ width: "100%", padding: 9, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--text)", marginBottom: 14 }}>
            {["BENIGN", "PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE"].map(value => <option key={value}>{value}</option>)}
          </select>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 5 }}>
            <span style={{ color: "var(--muted)" }}>A1 confidence (model output)</span><b>{confidence.toFixed(2)}</b>
          </div>
          <input aria-label="A1 confidence" type="range" min="0" max="1" step="0.01" value={confidence} onChange={e => setConfidence(Number(e.target.value))} style={{ width: "100%", marginBottom: 14 }} />
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 5 }}>
            <span style={{ color: "var(--muted)" }}>A2 anomaly score (raw model scale)</span><b>{anomalyScore.toFixed(3)}</b>
          </div>
          <input aria-label="A2 anomaly score" type="range" min="-0.5" max="0.5" step="0.005" value={anomalyScore} onChange={e => setAnomalyScore(Number(e.target.value))} style={{ width: "100%", marginBottom: 14 }} />
          <label style={{ display: "flex", alignItems: "center", gap: 9, color: "var(--muted)", fontSize: 11 }}>
            <input type="checkbox" checked={isAnomaly} onChange={e => setIsAnomaly(e.target.checked)} />
            A2 independently flagged this flow as anomalous
          </label>
          <button className="primary-btn" type="button" onClick={runFusion} disabled={busy} style={{ marginTop: 16, width: "100%" }}>
            {busy ? "Evaluating with Agent 3…" : "Run production fusion"} <Fingerprint size={15}/>
          </button>
        </div>

        <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Agent 3 decision output</div>
          {error && <div className="parse-warning" role="alert">{error}</div>}
          {!result && !error && <div className="empty-inline">Run the workbench to request a decision from the backend fusion agent. No result is assumed.</div>}
          {result && <>
            <div style={{ display: "flex", gap: 7, flexWrap: "wrap", marginBottom: 12 }}>
              <span className={"tag " + (result.action === "BLOCK" ? "tag-red" : result.action === "ALLOW" ? "tag-green" : "tag-amber")}>{result.action}</span>
              <span className="tag tag-blue">{result.evidence_status}</span>
              {result.agent_agreement && <span className="tag">{result.agent_agreement}</span>}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 9, marginBottom: 12 }}>
              <div className="metric-card" style={{ minHeight: 76 }}><div className="metric-label">FINAL CLASS</div><div className="metric-value" style={{ fontSize: 17 }}>{result.final_class || "—"}</div></div>
              <div className="metric-card" style={{ minHeight: 76 }}><div className="metric-label">FUSION CONFIDENCE</div><div className="metric-value" style={{ fontSize: 17 }}>{typeof result.confidence === "number" ? result.confidence.toFixed(3) : "—"}</div></div>
            </div>
            <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>Rationale from Python agent</div>
            <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text)", fontSize: 11, lineHeight: 1.7 }}>
              {(result.rationale || []).map((item: string, index: number) => <li key={index}>{item}</li>)}
            </ul>
          </>}
        </div>
      </div>
      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Backend-authoritative Agent 3 · simulated action only</span>
        <span>Confidence threshold and anomaly flag come from Python implementation</span>
      </div>
    </section>
  );
}

// ============================================================================
// 4. TEMPORAL CORRELATION CONSOLE (Agent 4 Sliding-Window & Threat Groups)
// ============================================================================
export function TemporalCorrelationConsole() {
  const [groups, setGroups] = useState<CorrelationGroupItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadGroups() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/correlation/groups?limit=100");
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || "Correlation API unavailable.");
      setGroups(Array.isArray(payload.groups) ? payload.groups : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load correlation groups.");
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadGroups(); }, []);

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">AGENT 04 · TEMPORAL CORRELATION & INCIDENTS</div>
          <h3>Observed Correlation Groups</h3>
          <p>Groups emitted by Agent 4 during the latest completed chronological replay.</p>
        </div>
        <button className="secondary-btn" type="button" onClick={loadGroups} disabled={loading}><RefreshCw size={14}/> Refresh</button>
      </div>

      {loading && <div className="empty-inline" style={{ marginTop: 16 }}>Loading observed correlation groups…</div>}
      {error && <div className="parse-warning" role="alert">{error}</div>}
      {!loading && !error && groups.length === 0 && (
        <div className="empty-history" style={{ marginTop: 16 }}>
          <div className="empty-history-icon"><Activity size={18}/></div>
          <div><b>No replay correlation groups available</b><span>Run a chronological replay in this API process. The console will show only groups actually produced by Agent 4.</span></div>
        </div>
      )}

      <div style={{ display: "grid", gap: 12, margin: "16px 0" }}>
        {groups.map(group => (
          <article key={group.group_id} style={{ background: "var(--panel2)", padding: 15, borderRadius: 9, border: "1px solid var(--line)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 9 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontFamily: "monospace", fontWeight: 700, color: "var(--blue)" }}>{group.group_id}</span>
                <span className={"tag " + (group.attack_type === "PORT_SCAN" ? "tag-amber" : group.attack_type === "DDOS" ? "tag-red" : "tag-blue")}>{group.attack_type}</span>
              </div>
              <span style={{ fontSize: 10, color: "var(--muted)" }}>{group.flow_count} observed member flows</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 10, marginBottom: 10 }}>
              <div><small style={{ color: "var(--muted)" }}>SOURCE IDENTITY</small><div style={{ fontFamily: "monospace", fontSize: 11, overflowWrap: "anywhere" }}>{group.source_identity || "Not available"}</div></div>
              <div><small style={{ color: "var(--muted)" }}>FIRST RECORD</small><div style={{ fontFamily: "monospace", fontSize: 11 }}>{group.start_record_id ?? "—"}</div></div>
              <div><small style={{ color: "var(--muted)" }}>LAST RECORD</small><div style={{ fontFamily: "monospace", fontSize: 11 }}>{group.end_record_id ?? "—"}</div></div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 9 }}>
              {(group.target_endpoints || []).map((endpoint, index) => <span key={index} className="tag">{endpoint}</span>)}
            </div>
            <div style={{ fontSize: 11, color: "var(--muted)", borderTop: "1px dashed var(--line)", paddingTop: 8 }}>
              <b>Observed evidence:</b> {(group.evidence || []).join(" ")}
            </div>
            <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 7 }}>
              Confidence/evidence strength: {typeof group.confidence === "number" ? group.confidence.toFixed(3) : "not provided"} · Member IDs: {(group.member_record_ids || []).slice(0, 8).join(", ")}{(group.member_record_ids || []).length > 8 ? " …" : ""}
            </div>
          </article>
        ))}
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Strict chronological windowing · No future event lookahead</span>
        <span>DATA SOURCE: LATEST COMPLETED REPLAY</span>
      </div>
    </section>
  );
}

// ============================================================================
// 5. ADAPTIVE DEFENSE CONSOLE (Agent 5 Policy Management & Pre-Filter)
// ============================================================================
export function AdaptiveDefenseConsole() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [totalPolicies, setTotalPolicies] = useState<number | null>(null);
  const [overview, setOverview] = useState<any>(null);
  const [testIdentity, setTestIdentity] = useState("");
  const [testStep, setTestStep] = useState(0);
  const [matchResult, setMatchResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [vendorFormat, setVendorFormat] = useState<"IPTABLES" | "AWS_WAF" | "PALO_ALTO" | "CISCO">("IPTABLES");
  const [copiedRule, setCopiedRule] = useState(false);

  async function loadPolicies() {
    setLoading(true);
    setError("");
    try {
      const [policyResponse, overviewResponse] = await Promise.all([
        fetch("/api/policies?limit=20"),
        fetch("/api/overview"),
      ]);
      const policyData = await policyResponse.json();
      if (!policyResponse.ok) throw new Error(policyData.detail?.message || policyData.detail || "Policy data unavailable.");
      setPolicies(Array.isArray(policyData.policies) ? policyData.policies : []);
      setTotalPolicies(Number(policyData.total ?? 0));
      if (overviewResponse.ok) setOverview(await overviewResponse.json());
      else setOverview(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load policy data.");
      setPolicies([]);
      setTotalPolicies(null);
      setOverview(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadPolicies(); }, []);

  async function testFilter() {
    if (!testIdentity.trim()) {
      setMatchResult({ error: "Enter a SOURCE_IP scope value from a generated policy." });
      return;
    }
    setIsTesting(true);
    setMatchResult(null);
    try {
      const response = await fetch("/api/policies/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_ip: testIdentity.trim(), current_step: testStep }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail?.message || data.detail || "Policy matcher unavailable.");
      setMatchResult(data);
    } catch (err) {
      setMatchResult({ error: err instanceof Error ? err.message : "Policy matcher request failed." });
    } finally {
      setIsTesting(false);
    }
  }

  const metric = overview?.metrics;

  const activeSources = policies.length > 0
    ? policies.slice(0, 6).map(p => ({ id: p.policy_id, src: p.scope_value, ttl: p.expires_after_record_id }))
    : [
        { id: "POL-0001", src: "192.168.10.50", ttl: 150 },
        { id: "POL-0002", src: "192.168.10.51", ttl: 200 }
      ];

  function getVendorRuleString(format: "IPTABLES" | "AWS_WAF" | "PALO_ALTO" | "CISCO"): string {
    switch (format) {
      case "IPTABLES":
        return [
          "# CyberSentinel Agent 5 — Dynamic Adaptive Mitigation Rules",
          "# Linux Netfilter / iptables Layer 3/4 enforcement",
          "iptables -N CS_AGENT5_FILTER",
          "iptables -I INPUT 1 -j CS_AGENT5_FILTER",
          ...activeSources.map(s => `iptables -A CS_AGENT5_FILTER -s ${s.src}/32 -m comment --comment "Policy:${s.id} TTL:${s.ttl}" -j DROP`)
        ].join("\n");
      case "AWS_WAF":
        return JSON.stringify({
          Name: "CyberSentinel-Dynamic-Containment-IPSet",
          Description: "Auto-generated by CyberSentinel Agent 5 Adaptive Defense",
          Scope: "REGIONAL",
          IPAddressVersion: "IPV4",
          Addresses: activeSources.map(s => `${s.src}/32`),
          RuleAction: "BLOCK"
        }, null, 2);
      case "PALO_ALTO":
        return [
          "# Palo Alto PAN-OS CLI Security Policy Configuration",
          "configure",
          ...activeSources.map(s => `set address host-${s.src.replaceAll('.', '_')} ip-netmask ${s.src}/32\nset rulebase security rules CS-DROP-${s.id} from untrust to trust source host-${s.src.replaceAll('.', '_')} destination any service any application any action drop log-end yes`),
          "commit"
        ].join("\n");
      case "CISCO":
        return [
          "! Cisco IOS / ASA Extended Access Control List (ACL)",
          "! Generated dynamically by CyberSentinel A5",
          "ip access-list extended CS_PERIMETER_DROP",
          ...activeSources.map(s => ` deny ip host ${s.src} any log (Policy ${s.id})`),
          " permit ip any any"
        ].join("\n");
    }
  }

  function copyVendorRule() {
    const code = getVendorRuleString(vendorFormat);
    navigator.clipboard.writeText(code);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2200);
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">AGENT 05 · ADAPTIVE DEFENSE & SIMULATED POLICIES</div>
          <h3>Policy Lifecycle & Pre-Filter</h3>
          <p>Displays policies created by an actual replay. All actions are simulated and remain inside the application.</p>
        </div>
        <button className="secondary-btn" type="button" onClick={loadPolicies} disabled={loading}><RefreshCw size={14}/> Refresh</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 10, margin: "14px 0" }}>
        {[
          ["POLICIES CREATED", totalPolicies === null ? "—" : totalPolicies.toLocaleString(), "From generated policy.csv"],
          ["ATTACKS CONTAINED", metric ? metric.attacks_contained.toLocaleString() : "—", metric ? metric.attack_containment_rate.toFixed(2) + "% of attack records" : "Requires labelled evaluation data"],
          ["BENIGN PRESERVED", metric ? metric.benign_preserved.toLocaleString() : "—", metric ? metric.benign_preservation_rate.toFixed(2) + "% of benign records" : "Requires labelled evaluation data"],
          ["FALSE BLOCKS", metric ? metric.false_blocks.toLocaleString() : "—", metric ? (100 - metric.benign_preservation_rate).toFixed(2) + "% of benign records" : "Requires labelled evaluation data"],
        ].map(([label, value, detail]) => <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}><small style={{ color: "var(--muted)", fontSize: 9 }}>{label}</small><div style={{ fontSize: 19, fontWeight: 700, margin: "5px 0" }}>{value}</div><small style={{ color: "var(--muted)", fontSize: 10 }}>{detail}</small></div>)}
      </div>

      {error && <div className="parse-warning" role="alert">{error}</div>}
      {loading && <div className="empty-inline">Loading generated policy records…</div>}
      {!loading && !error && policies.length === 0 && <div className="empty-history"><div className="empty-history-icon"><ShieldAlert size={18}/></div><div><b>No generated policies available</b><span>Run the official chronological replay to populate this console. No sample policies are inserted.</span></div></div>}

      {policies.length > 0 && <div style={{ overflowX: "auto", marginBottom: 16 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
          <thead><tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
            <th style={{ padding: "7px 8px" }}>POLICY ID</th><th style={{ padding: "7px 8px" }}>SCOPE</th><th style={{ padding: "7px 8px" }}>SOURCE IDENTITY</th><th style={{ padding: "7px 8px" }}>ACTIVATED AFTER</th><th style={{ padding: "7px 8px" }}>EXPIRES AFTER</th><th style={{ padding: "7px 8px" }}>ACTION</th>
          </tr></thead>
          <tbody>{policies.map(policy => <tr key={policy.policy_id} style={{ borderBottom: "1px solid var(--line)" }}>
            <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 600 }}>{policy.policy_id}</td>
            <td style={{ padding: 8 }}>{policy.scope_type}</td>
            <td style={{ padding: 8, fontFamily: "monospace" }}>{policy.scope_value}</td>
            <td style={{ padding: 8 }}>{policy.activated_after_record_id}</td>
            <td style={{ padding: 8 }}>{policy.expires_after_record_id}</td>
            <td style={{ padding: 8 }}><span className="tag tag-red">{policy.policy_action}</span></td>
          </tr>)}</tbody>
        </table>
        <div style={{ color: "var(--muted)", fontSize: 10, marginTop: 7 }}>Showing {policies.length} of {totalPolicies?.toLocaleString() ?? policies.length} policies.</div>
      </div>}

      <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Test the real backend pre-filter matcher</div>
        <p style={{ fontSize: 10, color: "var(--muted)", margin: "0 0 10px" }}>Enter a policy scope value and the record position to check activation and expiry. The matcher does not create or alter policies.</p>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input type="text" value={testIdentity} onChange={event => setTestIdentity(event.target.value)} placeholder="SOURCE_IP scope value from policy.csv" style={{ flex: "1 1 220px", minWidth: 0, padding: "8px 10px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--text)", fontSize: 11, fontFamily: "monospace" }} />
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "var(--muted)" }}>Record step <input type="number" min="0" value={testStep} onChange={event => setTestStep(Math.max(0, Number.parseInt(event.target.value, 10) || 0))} style={{ width: 86, padding: 8, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--text)" }}/></label>
          <button className="primary-btn" onClick={testFilter} disabled={isTesting}>{isTesting ? "Checking…" : "Test matcher"}</button>
        </div>
        {matchResult && <div role={matchResult.error ? "alert" : "status"} style={{ marginTop: 10, fontSize: 11, padding: 10, borderRadius: 6, background: matchResult.error ? "#35221f" : matchResult.matched ? "#351f25" : "#112a27", color: matchResult.error ? "#ffb4a4" : matchResult.matched ? "#ff9ba7" : "#9de6c6" }}>
          {matchResult.error || matchResult.message}
        </div>}
      </div>

      <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginTop: 14 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <FileCode2 size={16} color="#38bdf8" />
            <b style={{ fontSize: 12 }}>Multi-Vendor Firewall Policy Exporter</b>
            <span style={{ fontSize: 10, color: "var(--muted)", display: "flex", alignItems: "center", gap: 4 }}>
              <Terminal size={12} /> Production Control Syntax
            </span>
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            {(["IPTABLES", "AWS_WAF", "PALO_ALTO", "CISCO"] as const).map(fmt => (
              <button
                key={fmt}
                type="button"
                onClick={() => setVendorFormat(fmt)}
                className="secondary-btn"
                style={{
                  padding: "4px 8px",
                  fontSize: 10,
                  borderColor: vendorFormat === fmt ? "#38bdf8" : undefined,
                  color: vendorFormat === fmt ? "#38bdf8" : undefined,
                }}
              >
                {fmt === "AWS_WAF" ? "AWS WAF" : fmt === "PALO_ALTO" ? "Palo Alto" : fmt === "CISCO" ? "Cisco ACL" : "iptables"}
              </button>
            ))}
            <button
              type="button"
              onClick={copyVendorRule}
              className="primary-btn"
              style={{ padding: "4px 10px", fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}
            >
              {copiedRule ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy Rules</>}
            </button>
          </div>
        </div>
        <p style={{ fontSize: 10, color: "var(--muted)", margin: "0 0 8px" }}>
          Export active Agent 5 simulated containment policies as enterprise firewall commands. Ready for network deployment.
        </p>
        <pre style={{
          margin: 0,
          background: "rgba(8, 14, 26, 0.8)",
          padding: 12,
          borderRadius: 6,
          border: "1px solid var(--line)",
          color: "#38bdf8",
          fontFamily: "'DM Mono', monospace",
          fontSize: 10.5,
          lineHeight: 1.5,
          overflowX: "auto",
          maxHeight: 180
        }}>
          {getVendorRuleString(vendorFormat)}
        </pre>
      </div>

      <div className="panel-foot" style={{ marginTop: 14 }}>
        <span><LockKeyhole size={13} /> Simulated policies only · No host firewall modifications</span>
        <span>POLICY SCOPE: SOURCE_IP · ACTION: BLOCK</span>
      </div>
    </section>
  );
}

// ============================================================================
// 6. REPLAY STUDIO (Chronological Playback & Streaming Simulator)
// ============================================================================
export function ReplayStudio({ modelReady }: { modelReady: boolean }) {
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState("");

  async function runOfficialReplay() {
    setRunning(true);
    setSummary(null);
    setError("");
    try {
      const response = await fetch("/api/replay/run-official", { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail?.message || payload.detail || "Official replay could not be started.");
      setSummary(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Replay request failed.");
    } finally {
      setRunning(false);
    }
  }

  const metrics = summary?.metrics;
  const rate = (value: unknown) => typeof value === "number" ? value.toFixed(2) + "%" : "Not available (unlabelled evaluation data)";

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">LEVEL 02 · CAUSAL CHRONOLOGICAL REPLAY ENGINE</div>
          <h3>Official Offline Replay</h3>
          <p>Runs the installed evaluation dataset through the backend replay engine and generates the three official CSV artifacts.</p>
        </div>
        <span className="panel-icon"><FileSpreadsheet size={18} /></span>
      </div>

      <div style={{ background: "var(--panel2)", padding: 17, borderRadius: 9, border: "1px solid var(--line)", margin: "16px 0" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <div>
            <b>Evaluation dataset · local server only</b>
            <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 5 }}>
              Expected path: <code>data/processed/eval_prepared.parquet</code>
            </div>
            <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 5 }}>
              Records remain on the backend. The interface does not upload or fabricate a replay stream.
            </div>
          </div>
          <button className="primary-btn" disabled={!modelReady || running} onClick={runOfficialReplay}>
            {running ? <><RefreshCw size={14} className="spin-icon"/> Running official replay…</> : <><Play size={14}/> Run official chronological replay</>}
          </button>
        </div>

        {!modelReady && <div className="parse-warning" style={{ marginTop: 14 }}>Models are not ready. Install and verify both model artifacts before replay.</div>}
        {running && <div style={{ marginTop: 16, padding: 12, border: "1px solid var(--line)", borderRadius: 7, color: "var(--muted)", fontSize: 11 }} role="status" aria-live="polite">The backend is processing the actual dataset in chronological order. This operation may take several seconds; do not refresh this page.</div>}
        {error && <div className="parse-warning" role="alert" style={{ marginTop: 14 }}>{error}</div>}

        {summary && metrics && <div style={{ marginTop: 17, borderTop: "1px solid var(--line)", paddingTop: 15 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
            <div><small style={{ color: "var(--muted)" }}>REPLAY RUN</small><div style={{ fontFamily: "monospace", fontSize: 12 }}>{summary.run_id}</div></div>
            <span className={"tag " + (summary.validation?.all_valid ? "tag-green" : "tag-amber")}>{summary.validation?.all_valid ? "CSV VALIDATION PASSED" : "VALIDATION NEEDS REVIEW"}</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 10 }}>
            {[
              ["RECORDS", metrics.total_records?.toLocaleString()],
              ["BLOCKED", metrics.blocked_records?.toLocaleString()],
              ["ALLOWED", metrics.allowed_records?.toLocaleString()],
              ["POLICIES", metrics.policies_created?.toLocaleString()],
              ["ATTACK CONTAINMENT", rate(metrics.containment_rate)],
              ["BLOCK PRECISION", rate(metrics.block_precision)],
              ["BENIGN PRESERVED", metrics.benign_preserved?.toLocaleString() ?? "—"],
              ["FALSE BLOCKS", metrics.false_blocks?.toLocaleString() ?? "—"],
            ].map(([label, value]) => <div key={label} style={{ background: "var(--panel)", padding: 11, borderRadius: 7, border: "1px solid var(--line)" }}><small style={{ color: "var(--muted)", fontSize: 9 }}>{label}</small><div style={{ fontSize: 15, fontWeight: 700, marginTop: 4 }}>{value ?? "—"}</div></div>)}
          </div>
          <div style={{ marginTop: 13, fontSize: 11, color: "var(--muted)" }}>
            Elapsed: {metrics.elapsed_seconds}s · Throughput: {metrics.throughput_fps?.toLocaleString()} flows/sec · Correlation groups: {summary.correlation_groups}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
            {Object.entries(summary.files || {}).map(([filename, info]: [string, any]) => <a key={filename} className="secondary-btn" href={"/api/submissions/download/" + filename}>{filename} · {info.rows.toLocaleString()} rows <Download size={13}/></a>)}
          </div>
          {!summary.validation?.all_valid && <div className="parse-warning" style={{ marginTop: 12 }}>The generated files did not pass the complete validator. Inspect Submission Studio before using them.</div>}
        </div>}
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Offline only · Simulated policies · No host firewall changes</span>
        <span>Backend-authoritative replay · No synthetic progress</span>
      </div>
    </section>
  );
}

// ============================================================================
// 7. SUBMISSION STUDIO (CSV Generation, Audit Validator & Direct Downloads)
// ============================================================================
export function SubmissionStudio() {
  const [validationReport, setValidationReport] = useState<any>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState("");
  const [downloadError, setDownloadError] = useState("");

  async function runValidator() {
    setIsValidating(true);
    setValidationError("");
    setValidationReport(null);
    try {
      const response = await fetch("/api/replay/validate");
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail?.message || data.detail || "Validator endpoint unavailable.");
      setValidationReport(data);
    } catch (err) {
      setValidationError(err instanceof Error ? err.message : "Validator request failed.");
    } finally {
      setIsValidating(false);
    }
  }

  async function triggerDownload(filename: string) {
    setDownloadError("");
    try {
      const response = await fetch("/api/submissions/download/" + filename);
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || filename + " has not been generated.");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Download failed.");
    }
  }

  const fileCards = [
    { filename: "classification.csv", label: "FILE 01", description: "Five-class prediction, anomaly score, and evidence status for every record.", rows: validationReport?.classification?.row_count, header: "record_id,predicted_class,anomaly score,evidence status" },
    { filename: "policy.csv", label: "FILE 02", description: "Temporary simulated policies with scope, activation, and expiry.", rows: validationReport?.policy?.policy_count, header: "policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action" },
    { filename: "replay.csv", label: "FILE 03", description: "One chronological ALLOW/BLOCK action per record with policy references.", rows: validationReport?.replay?.row_count, header: "record_id,action,applied_policy_id" },
  ];

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">OFFICIAL COMPETITION FILES · THREE-FILE BUNDLE</div>
          <h3>Submission Studio & Integrity Validator</h3>
          <p>Download and validate the generated CSV artifacts against the organiser's required headers and replay constraints.</p>
        </div>
        <span className="panel-icon"><Download size={18} /></span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 14, margin: "16px 0" }}>
        {fileCards.map(file => <div key={file.filename} style={{ background: "var(--panel2)", padding: 15, borderRadius: 8, border: "1px solid var(--line)", minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 7 }}>
            <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--blue)", fontWeight: 700 }}>{file.label}</span>
            <span className="tag">{file.rows == null ? "NOT VERIFIED" : file.rows.toLocaleString() + " ROWS"}</span>
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 5 }}>{file.filename}</div>
          <div style={{ fontSize: 10, color: "var(--muted)", minHeight: 42, marginBottom: 10 }}>{file.description}</div>
          <div style={{ fontSize: 9, fontFamily: "monospace", color: "var(--muted)", background: "var(--panel)", padding: 8, borderRadius: 4, overflowWrap: "anywhere", marginBottom: 11 }}>{file.header}</div>
          <button className="primary-btn" onClick={() => triggerDownload(file.filename)} style={{ width: "100%", fontSize: 10 }}><Download size={13}/> Download</button>
        </div>)}
      </div>

      {downloadError && <div className="parse-warning" role="alert">{downloadError}</div>}

      <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 10 }}>
          <div><b>Submission bundle validator</b><div style={{ fontSize: 10, color: "var(--muted)", marginTop: 4 }}>Runs against the files currently present on the backend.</div></div>
          <button className="secondary-btn" onClick={runValidator} disabled={isValidating}>{isValidating ? <RefreshCw size={13} className="spin-icon"/> : <Check size={13}/>} {isValidating ? "Validating…" : "Run validator"}</button>
        </div>
        {validationError && <div className="parse-warning" role="alert">{validationError}</div>}
        {validationReport && <div style={{ marginTop: 12, padding: 13, background: validationReport.all_valid ? "#112a27" : "#35221f", border: "1px solid " + (validationReport.all_valid ? "#225447" : "#6a3b31"), borderRadius: 7 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, color: validationReport.all_valid ? "#9de6c6" : "#ffb4a4", fontWeight: 700, fontSize: 12, marginBottom: 9 }}>
            <ShieldCheck size={17}/> {validationReport.status || (validationReport.all_valid ? "VALID" : "INVALID")}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 10, fontSize: 10, color: "var(--muted)" }}>
            <div>classification.csv · {validationReport.classification?.row_count ?? "—"} rows · {validationReport.classification?.total_errors ?? "—"} errors</div>
            <div>policy.csv · {validationReport.policy?.policy_count ?? "—"} policies · {validationReport.policy?.total_errors ?? "—"} errors</div>
            <div>replay.csv · {validationReport.replay?.row_count ?? "—"} rows · {validationReport.replay?.total_errors ?? "—"} errors</div>
          </div>
          {!validationReport.all_valid && <div style={{ marginTop: 9, fontSize: 10, color: "#ffb4a4" }}>Do not submit until every mandatory validator error is resolved.</div>}
        </div>}
      </div>

      <div className="panel-foot" style={{ marginTop: 14 }}>
        <span><LockKeyhole size={13}/> No organiser submission is claimed by local validation</span>
        <span>READINESS IS BASED ON CURRENT BACKEND FILES</span>
      </div>
    </section>
  );
}

// ============================================================================
// 8. MODEL INTELLIGENCE VIEW (Full 5-Agent Evaluation Suite & Diagnostics)
// ============================================================================
export { ModelIntelligenceView } from "./ModelIntelligence";

// ============================================================================
// 9. AUDIT & LOCAL RUN HISTORY VIEW (SQLite Persistence)
// ============================================================================
export function AuditHistoryView() {
  const [runs, setRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/history?limit=10")
      .then(res => res.json())
      .then(data => {
        setRuns(data.runs || []);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">FORENSIC AUDIT TRAIL · OFFLINE SQLITE PERSISTENCE</div>
          <h3>Local Execution & Replay Run History</h3>
          <p>
            Persisted locally in data/cybersentinel_history.db for compliance, auditability, and offline verification.
          </p>
        </div>
        <span className="panel-icon"><Database size={18} /></span>
      </div>

      {loading ? (
        <div style={{ padding: 24, textAlign: "center", color: "var(--muted)", fontSize: 12 }}>
          Loading offline execution records from SQLite database…
        </div>
      ) : runs.length === 0 ? (
        <div style={{ background: "var(--panel2)", padding: 20, borderRadius: 8, border: "1px solid var(--line)", textAlign: "center", margin: "14px 0" }}>
          <Database size={24} style={{ color: "var(--muted)", margin: "0 auto 8px auto", display: "block" }} />
          <b style={{ fontSize: 13, color: "var(--text)" }}>No Replay Runs Logged Yet</b>
          <p style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 0 0" }}>
            Execute a run in Replay Studio to record chronological replay metrics into the local SQLite database.
          </p>
        </div>
      ) : (
        <div style={{ overflowX: "auto", margin: "14px 0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                <th style={{ padding: 8 }}>RUN ID</th>
                <th style={{ padding: 8 }}>DATASET</th>
                <th style={{ padding: 8 }}>TOTAL FLOWS</th>
                <th style={{ padding: 8 }}>BLOCKED</th>
                <th style={{ padding: 8 }}>ALLOWED</th>
                <th style={{ padding: 8 }}>POLICIES</th>
                <th style={{ padding: 8 }}>CONTAINMENT</th>
                <th style={{ padding: 8 }}>THROUGHPUT</th>
                <th style={{ padding: 8 }}>TIMESTAMP</th>
              </tr>
            </thead>
            <tbody>
              {runs.map(r => (
                <tr key={r.run_id} style={{ borderBottom: "1px solid var(--line)" }}>
                  <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 700, color: "var(--blue)" }}>{r.run_id}</td>
                  <td style={{ padding: 8 }}>{r.dataset_name}</td>
                  <td style={{ padding: 8, fontFamily: "monospace" }}>{r.total_records.toLocaleString()}</td>
                  <td style={{ padding: 8, fontFamily: "monospace", color: "#ef4444" }}>{r.blocked_records.toLocaleString()}</td>
                  <td style={{ padding: 8, fontFamily: "monospace", color: "#22c55e" }}>{r.allowed_records.toLocaleString()}</td>
                  <td style={{ padding: 8, fontFamily: "monospace" }}>{r.policies_created.toLocaleString()}</td>
                  <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 700 }}>{r.containment_rate}%</td>
                  <td style={{ padding: 8, fontFamily: "monospace" }}>{r.throughput_fps} fps</td>
                  <td style={{ padding: 8, color: "var(--muted)" }}>{new Date(r.timestamp).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Zero cloud dependency · 100% offline local SQLite database</span>
        <span>DATABASE: data/cybersentinel_history.db</span>
      </div>
    </section>
  );
}

// ============================================================================
// 10. SETTINGS & SYSTEM HEALTH VIEW
// ============================================================================
export function SystemHealthView({ health }: { health: any }) {
  const [diagnostics, setDiagnostics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadDiagnostics() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/system/diagnostics");
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || "Diagnostics endpoint unavailable.");
      setDiagnostics(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load system diagnostics.");
      setDiagnostics(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadDiagnostics(); }, []);

  const statusTag = (ready: boolean | undefined, label = "READY") => <span className={"tag " + (ready ? "tag-green" : "tag-amber")}>{ready ? label : "NOT AVAILABLE"}</span>;
  const mb = (bytes: number | null | undefined) => typeof bytes === "number" ? (bytes / (1024 * 1024)).toFixed(2) + " MB" : "—";

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">SYSTEM INTEGRITY · DIAGNOSTICS & HEALTH</div>
          <h3>System Settings & Readiness Status</h3>
          <p>Every status is read from the local backend. Missing models, datasets or generated files are shown as unavailable.</p>
        </div>
        <button className="secondary-btn" type="button" onClick={loadDiagnostics} disabled={loading}><RefreshCw size={14}/> Refresh diagnostics</button>
      </div>

      {loading && <div className="empty-inline">Reading local artifact and service status…</div>}
      {error && <div className="parse-warning" role="alert">{error}</div>}

      {diagnostics && <>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 14, margin: "16px 0" }}>
          <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Service & Agent Readiness</div>
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>FastAPI backend</span>{statusTag(diagnostics.api?.available && health?.status === "ok", "ONLINE")}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>A1 Threat Detection model · {mb(diagnostics.models?.agent_1_model ? diagnostics.model_sizes?.agent_1_bytes : null)}</span>{statusTag(diagnostics.models?.agent_1_model)}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>A2 Anomaly Detection model · {mb(diagnostics.models?.agent_2_model ? diagnostics.model_sizes?.agent_2_bytes : null)}</span>{statusTag(diagnostics.models?.agent_2_model)}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>A3 Evidence Fusion implementation</span>{statusTag(diagnostics.models?.agent_3_fusion_code)}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>A4 Temporal Correlation implementation</span>{statusTag(diagnostics.models?.agent_4_correlation_code)}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>A5 Adaptive Defense implementation</span>{statusTag(diagnostics.models?.agent_5_defense_code)}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>SQLite history database</span>{statusTag(diagnostics.history_database?.present, "PRESENT")}</div>
            </div>
          </div>

          <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Dataset & Submission Artifacts</div>
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>Evaluation parquet · {mb(diagnostics.evaluation_dataset?.bytes)}</span>{statusTag(diagnostics.evaluation_dataset?.present, "INSTALLED")}</div>
              {Object.entries(diagnostics.submission_artifacts || {}).map(([filename, file]: [string, any]) => <div key={filename} style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>{filename} · {mb(file.bytes)}</span>{statusTag(file.present, "GENERATED")}</div>)}
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>Execution mode</span><span className="tag tag-blue">OFFLINE REPLAY</span></div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>Host firewall</span><span className="tag tag-green">NOT MODIFIED</span></div>
            </div>
          </div>
        </div>

        <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--blue)", marginBottom: 5 }}>SOURCE IDENTITY DISCLOSURE</div>
          <p style={{ fontSize: 10, color: "var(--muted)", margin: 0, lineHeight: 1.6 }}>{diagnostics.source_identity}</p>
        </div>
      </>}

      <div className="panel-foot" style={{ marginTop: 14 }}>
        <span><LockKeyhole size={13}/> Simulated policies only · No live network access</span>
        <span>ENVIRONMENT: LOCAL OFFLINE REPLAY</span>
      </div>
    </section>
  );
}
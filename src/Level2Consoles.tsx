import { lazy, Suspense, useState, useEffect } from "react";
import { apiFetch, downloadAuthenticatedFile } from "./lib/api";
import {
  Activity, Check, Database, Download, FileSpreadsheet, Fingerprint,
  Gauge, Layers, LockKeyhole, Play, RefreshCw,
  ShieldAlert, ShieldCheck
} from "lucide-react";
const NetworkTopology3D = lazy(() => import("./components/NetworkTopology3D").then(module => ({ default: module.NetworkTopology3D })));

type Policy = {
  policy_id: string;
  activated_after_record_id: string | number;
  scope_type: string;
  scope_value: string;
  expires_after_record_id: string | number;
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
// 1. ILLUSTRATIVE 3D REPLAY ARCHITECTURE (not live SOC telemetry)
// ============================================================================
export function TopologyCommandCentre() {
  const [visualTone, setVisualTone] = useState<"COOL" | "AMBER" | "ROSE">("COOL");

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22, overflow: "hidden" }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">WEBGL 3D · ILLUSTRATIVE REPLAY ARCHITECTURE</div>
          <h3>Five-Agent Replay Architecture</h3>
          <p>
            Illustrative 3D schematic of the offline five-agent pipeline. It is not a live network map or traffic feed; the visual-tone selector changes colors only; no traffic telemetry is represented.
          </p>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {(["COOL", "AMBER", "ROSE"] as const).map((tone) => (
            <button
              key={tone}
              onClick={() => setVisualTone(tone)}
              className="text-btn"
              style={{
                fontSize: 11,
                padding: "3px 8px",
                background: visualTone === tone ? (tone === "ROSE" ? "#ef4444" : tone === "AMBER" ? "#f59e0b" : "#2563eb") : "var(--panel2)",
                color: visualTone === tone ? "#fff" : "var(--text)",
                borderRadius: 4,
                border: "1px solid var(--line)",
                cursor: "pointer",
                fontWeight: visualTone === tone ? 600 : 400,
              }}
            >
              {tone} TONE
            </button>
          ))}
        </div>
      </div>

      <div style={{ height: 480, position: "relative", background: "radial-gradient(circle at center, rgba(15, 30, 58, 0.45) 0%, rgba(3, 7, 18, 0.95) 100%)", borderRadius: 12, margin: "12px 0 16px 0", border: "1px solid rgba(56, 189, 248, 0.22)", overflow: "hidden", boxShadow: "inset 0 0 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(56, 189, 248, 0.1)" }}>
        <Suspense fallback={<div className="topology-loading" role="status">Loading 3D topology…</div>}>
      <NetworkTopology3D visualTone={visualTone} />
    </Suspense>
        <div style={{ position: "absolute", bottom: 12, left: 14, fontSize: 11, color: "var(--muted)", pointerEvents: "none" }}>
          <b>COMPONENTS:</b> A1 Threat Classifier · A2 Anomaly Isolation · A3 Fusion Matrix · A4 Temporal Window · A5 Adaptive Defense
        </div>
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Hardware-accelerated WebGL 3D scene with 2D canvas fallback</span>
        <span>ILLUSTRATIVE SYSTEM DIAGRAM · NO LIVE TRAFFIC OR PACKET PULSES</span>
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
      model: "Random Forest (artifact-defined; calibration provenance is artifact-dependent)",
      input: "78 numeric network flow features",
      output: "Predicted class + model confidence; calibration depends on the saved artifact",
      latency: "See measured benchmark report",
      throughput: "See measured benchmark report",
      accuracy: "See generated evaluation report",
      classes: "BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN",
      description: "Extracts flow-level features and runs high-speed tree ensemble inference with canonical label encoding. Produces a class prediction and artifact-defined confidence; request latency is measured separately.",
    },
    {
      id: 2,
      name: "Agent 2: Anomaly Detection",
      role: "Unsupervised Statistical Outlier Isolation",
      model: "Isolation Forest (parameters loaded from model artifact)",
      input: "78 numeric flow features",
      output: "Bounded 0–1 anomaly index (not a probability) + outlier flag",
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
      classes: "ALLOW, BLOCK, REVIEW (Status: AGREE, CONFLICT, UNCERTAIN)",
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
      description: "Maintains a fixed 150-flow cap and configured 300-second age window when timestamps exist. Uses only literal observed source/destination endpoints from the hidden input; missing or invalid endpoints remain unknown.",
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
      classes: "ALLOW (active_policy_id=NONE), BLOCK (smallest matching active policy ID)",
      description: "Checks earlier active policies before downstream correlation. Confirmed attacks can create a forward-only simulated SOURCE_IP block with a fixed default 150-position lifetime; it never blocks its own trigger row.",
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
        <span>LATENCY: REPORT ONLY MEASURED REQUEST/REPLAY VALUES</span>
      </div>
    </section>
  );
}

// ============================================================================
// 3. EVIDENCE FUSION STUDIO (Agent 3 Matrix & Interactive Simulator)
// ============================================================================
export function EvidenceFusionStudio() {
  const [threatClass, setThreatClass] = useState("BENIGN");
  const [confidence, setConfidence] = useState(0.5);
  const [anomalyScore, setAnomalyScore] = useState(0);
  const [isAnomaly, setIsAnomaly] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function runFusion() {
    setBusy(true);
    setError("");
    try {
      const response = await apiFetch("/api/fusion/simulate", {
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
          <h3>Evidence Fusion Rule Simulator</h3>
          <p>Evaluates manually entered what-if evidence using the same Python fusion rules as replay. Inputs are not model predictions or observed traffic.</p>
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
            <span style={{ color: "var(--muted)" }}>A1 confidence input (manual)</span><b>{confidence.toFixed(2)}</b>
          </div>
          <input aria-label="A1 confidence" type="range" min="0" max="1" step="0.01" value={confidence} onChange={e => setConfidence(Number(e.target.value))} style={{ width: "100%", marginBottom: 14 }} />
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 5 }}>
            <span style={{ color: "var(--muted)" }}>A2 anomaly index (0–1; higher = more anomalous)</span><b>{anomalyScore.toFixed(3)}</b>
          </div>
          <input aria-label="A2 anomaly score" type="range" min="0" max="1" step="0.01" value={anomalyScore} onChange={e => setAnomalyScore(Number(e.target.value))} style={{ width: "100%", marginBottom: 14 }} />
          <label style={{ display: "flex", alignItems: "center", gap: 9, color: "var(--muted)", fontSize: 11 }}>
            <input type="checkbox" checked={isAnomaly} onChange={e => setIsAnomaly(e.target.checked)} />
            Manual A2 anomaly flag input
          </label>
          <button className="primary-btn" type="button" onClick={runFusion} disabled={busy} style={{ marginTop: 16, width: "100%" }}>
            {busy ? "Evaluating with Agent 3…" : "Evaluate manual scenario"} <Fingerprint size={15}/>
          </button>
        </div>

        <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Agent 3 decision output</div>
          {error && <div className="parse-warning" role="alert">{error}</div>}
          {!result && !error && <div className="empty-inline">Set the what-if inputs and evaluate them. This panel does not create a flow record or change replay artifacts.</div>}
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
            <div className="empty-inline" style={{ marginBottom: 10 }}>Supabase audit: {result.supabase_persistence?.stored ? "Manual scenario metadata saved to your private account." : "Scenario evaluated, but cloud persistence was not confirmed (" + (result.supabase_persistence?.reason || "not reported") + ")."}</div>
            <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>Rationale from Python agent</div>
            <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text)", fontSize: 11, lineHeight: 1.7 }}>
              {(result.rationale || []).map((item: string, index: number) => <li key={index}>{item}</li>)}
            </ul>
          </>}
        </div>
      </div>
      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Backend-authoritative Agent 3 · simulated action only</span>
        <span>Manual inputs only · no flow is analyzed by this simulator</span>
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
      const response = await apiFetch("/api/correlation/groups?limit=100");
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
  const [testStep, setTestStep] = useState(1);
  const [matchResult, setMatchResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadPolicies() {
    setLoading(true);
    setError("");
    try {
      const [policyResponse, overviewResponse] = await Promise.all([
        apiFetch("/api/policies?limit=20"),
        apiFetch("/api/overview"),
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
      const response = await apiFetch("/api/policies/test", {
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
  const hasGroundTruthMetrics = typeof metric?.attack_containment_rate === "number" && typeof metric?.benign_preservation_rate === "number";

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
          ["POLICIES CREATED", totalPolicies === null ? "—" : totalPolicies.toLocaleString(), "From generated policies.csv"],
          ["ATTACKS CONTAINED", hasGroundTruthMetrics ? metric.attacks_contained.toLocaleString() : "—", hasGroundTruthMetrics ? metric.attack_containment_rate.toFixed(2) + "% of attack records" : "Not measurable on unlabelled replay input"],
          ["BENIGN PRESERVED", hasGroundTruthMetrics ? metric.benign_preserved.toLocaleString() : "—", hasGroundTruthMetrics ? metric.benign_preservation_rate.toFixed(2) + "% of benign records" : "Not measurable on unlabelled replay input"],
          ["FALSE BLOCKS", hasGroundTruthMetrics && typeof metric.false_blocks === "number" ? metric.false_blocks.toLocaleString() : "—", hasGroundTruthMetrics ? (100 - metric.benign_preservation_rate).toFixed(2) + "% of benign records" : "Not measurable on unlabelled replay input"],
        ].map(([label, value, detail]) => <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}><small style={{ color: "var(--muted)", fontSize: 9 }}>{label}</small><div style={{ fontSize: 19, fontWeight: 700, margin: "5px 0" }}>{value}</div><small style={{ color: "var(--muted)", fontSize: 10 }}>{detail}</small></div>)}
      </div>

      {error && <div className="parse-warning" role="alert">{error}</div>}
      {loading && <div className="empty-inline">Loading generated policy records…</div>}
      {!loading && !error && policies.length === 0 && <div className="empty-history"><div className="empty-history-icon"><ShieldAlert size={18}/></div><div><b>No generated policies available</b><span>Run the official chronological replay to populate this console. No sample policies are inserted.</span></div></div>}

      {policies.length > 0 && <div style={{ overflowX: "auto", marginBottom: 16 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
          <thead><tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
            <th style={{ padding: "7px 8px" }}>POLICY ID</th><th style={{ padding: "7px 8px" }}>SCOPE</th><th style={{ padding: "7px 8px" }}>OBSERVED SOURCE IP</th><th style={{ padding: "7px 8px" }}>ACTIVATED AFTER</th><th style={{ padding: "7px 8px" }}>EXPIRES AFTER</th><th style={{ padding: "7px 8px" }}>ACTION</th>
          </tr></thead>
          <tbody>{policies.map(policy => <tr key={policy.policy_id} style={{ borderBottom: "1px solid var(--line)" }}>
            <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 600 }}>{policy.policy_id}</td>
            <td style={{ padding: 8 }}>{policy.scope_type}</td>
            <td style={{ padding: 8, fontFamily: "monospace" }}>{policy.scope_value}</td>
            <td style={{ padding: 8 }}>{policy.activated_after_record_id}</td>
            <td style={{ padding: 8 }}>{policy.expires_after_record_id}</td>
            <td style={{ padding: 8 }}><span className="tag tag-red">{"BLOCK"}</span></td>
          </tr>)}</tbody>
        </table>
        <div style={{ color: "var(--muted)", fontSize: 10, marginTop: 7 }}>Showing {policies.length} of {totalPolicies?.toLocaleString() ?? policies.length} policies.</div>
      </div>}

      <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Test the real backend pre-filter matcher</div>
        <p style={{ fontSize: 10, color: "var(--muted)", margin: "0 0 10px" }}>Enter a policy scope value and the record position to check activation and expiry. The matcher does not create or alter policies.</p>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input type="text" value={testIdentity} onChange={event => setTestIdentity(event.target.value)} placeholder="Observed SOURCE_IP from policies.csv" style={{ flex: "1 1 220px", minWidth: 0, padding: "8px 10px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--text)", fontSize: 11, fontFamily: "monospace" }} />
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "var(--muted)" }}>Record step <input type="number" min="1" value={testStep} onChange={event => setTestStep(Math.max(1, Number.parseInt(event.target.value, 10) || 1))} style={{ width: 86, padding: 8, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--text)" }}/></label>
          <button className="primary-btn" onClick={testFilter} disabled={isTesting}>{isTesting ? "Checking…" : "Test matcher"}</button>
        </div>
        {matchResult && <div role={matchResult.error ? "alert" : "status"} style={{ marginTop: 10, fontSize: 11, padding: 10, borderRadius: 6, background: matchResult.error ? "#35221f" : matchResult.matched ? "#351f25" : "#112a27", color: matchResult.error ? "#ffb4a4" : matchResult.matched ? "#ff9ba7" : "#9de6c6" }}>
          {matchResult.error || matchResult.message}
          {!matchResult.error && <div style={{ marginTop: 6, fontSize: 10 }}>Supabase audit: {matchResult.supabase_persistence?.stored ? "Policy simulation saved." : "Persistence not confirmed (" + (matchResult.supabase_persistence?.reason || "not reported") + ")."}</div>}
        </div>}
      </div>

      <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginTop: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
          <LockKeyhole size={15} color="#38bdf8" />
          <b style={{ fontSize: 12 }}>Enforcement boundary</b>
        </div>
        <p style={{ fontSize: 10, color: "var(--muted)", margin: 0, lineHeight: 1.6 }}>
          Policy records are offline simulation results for analyst review. This product has no firewall adapter, deployment credentials, approval workflow, rollback controller, or live enforcement path. Download the CSV ledger for review; do not paste these records into a firewall.
        </p>
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
  const [uploading, setUploading] = useState(false);
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState("");
  const [inputStatus, setInputStatus] = useState<any>(null);

  useEffect(() => {
    apiFetch("/api/system/diagnostics")
      .then(response => response.ok ? response.json() : Promise.reject(new Error("Local API unavailable")))
      .then(data => setInputStatus(data.hidden_replay_input ?? null))
      .catch(() => setInputStatus(null));
  }, []);

  async function installReplayInput(file?: File) {
    if (!file) return;
    setUploading(true);
    setError("");
    setSummary(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await apiFetch("/api/replay/input/upload", { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) {
        const detail = payload.detail;
        const message = typeof detail === "string" ? detail : detail?.message ?? detail?.report?.errors?.join(" ") ?? "Replay input could not be installed.";
        throw new Error(message);
      }
      setInputStatus({ present: true, validation: payload.input_validation, path: payload.path });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Replay input upload failed.");
    } finally {
      setUploading(false);
    }
  }

  async function runOfficialReplay() {
    setRunning(true);
    setSummary(null);
    setError("");
    try {
      const response = await apiFetch("/api/replay/run-official", { method: "POST" });
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
          <p>Runs the installed unlabelled hidden replay input through the backend replay engine and generates the three official CSV artifacts.</p>
        </div>
        <span className="panel-icon"><FileSpreadsheet size={18} /></span>
      </div>

      <div style={{ background: "var(--panel2)", padding: 17, borderRadius: 9, border: "1px solid var(--line)", margin: "16px 0" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <div>
            <b>Organizer replay input · local server only</b>
            <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 5 }}>
              Expected path: <code>data/processed/hidden_replay_input.csv</code>
            </div>
            <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 5 }}>
              Install the organizer CSV or cyber-hidden.zip. The backend validates original IDs, sequence, timestamps, numeric features and observed endpoints; it never creates missing endpoint values.
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <label className="secondary-btn" style={{ cursor: uploading ? "wait" : "pointer" }}>
              {uploading ? "Installing input…" : "Choose CSV / ZIP"}
              <input type="file" accept=".csv,.zip,text/csv,application/zip" hidden disabled={uploading} onChange={event => { void installReplayInput(event.target.files?.[0]); event.currentTarget.value = ""; }} />
            </label>
            <button className="primary-btn" disabled={!modelReady || running || !inputStatus?.present || !inputStatus?.validation?.valid} onClick={runOfficialReplay}>
              {running ? <><RefreshCw size={14} className="spin-icon"/> Running official replay…</> : <><Play size={14}/> Run chronological replay</>}
            </button>
          </div>
        </div>

        {!inputStatus?.present && <div className="empty-inline" style={{ marginTop: 14 }}>No organizer replay input is installed. Choose the original CSV or cyber-hidden.zip.</div>}
        {inputStatus?.present && <div className="empty-inline" style={{ marginTop: 14 }}>Input check: {inputStatus.validation?.rows ?? "—"} records · {inputStatus.validation?.feature_count ?? "—"} numeric flow features · {inputStatus.validation?.rows_with_both_observed_endpoints ?? "—"} rows with both observed endpoints. {inputStatus.validation?.valid ? "Schema and chronology valid." : "Input needs correction before replay."}</div>}
        {!modelReady && <div className="parse-warning" style={{ marginTop: 14 }}>Model artifacts are not ready. Install the authorized labelled training pack, train both agents, and verify the saved artifacts.</div>}
        {inputStatus?.validation?.warnings?.length > 0 && <div className="parse-warning" style={{ marginTop: 10 }}>{inputStatus.validation.warnings.join(" ")}</div>}
        {inputStatus?.validation?.errors?.length > 0 && <div className="parse-warning" style={{ marginTop: 10 }}>{inputStatus.validation.errors.join(" ")}</div>}
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
          <div className="empty-inline" style={{ marginTop: 10 }}>
            Supabase audit: {summary.supabase_persistence?.stored
              ? "Replay summary, " + Number(summary.supabase_persistence.artifacts?.decisions_saved || 0).toLocaleString() + " decisions, " + Number(summary.supabase_persistence.artifacts?.policies_saved || 0).toLocaleString() + " policies and " + Number(summary.supabase_persistence.artifacts?.correlation_groups_saved || 0).toLocaleString() + " correlation groups saved."
              : "Replay completed, but cloud persistence was not confirmed (" + (summary.supabase_persistence?.reason || "not reported") + ")."}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
            {Object.entries(summary.files || {}).map(([filename, info]: [string, any]) => <button key={filename} className="secondary-btn" onClick={() => { void downloadAuthenticatedFile("/api/submissions/download/" + filename, filename).catch(reason => setError(reason instanceof Error ? reason.message : "Download failed.")); }}>{filename} · {info.rows.toLocaleString()} rows <Download size={13}/></button>)}
          </div>
          {!summary.validation?.all_valid && <div className="parse-warning" style={{ marginTop: 12 }}>The generated files did not pass the complete validator. Inspect Submission Studio before using them.</div>}
        </div>}
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Local execution only · Simulated policies · No host firewall changes</span>
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
      const response = await apiFetch("/api/replay/validate");
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
      const response = await apiFetch("/api/submissions/download/" + filename);
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
    { filename: "classification.csv", label: "FILE 01", description: "Five-class prediction, anomaly score, and evidence status for every record.", rows: validationReport?.classification?.row_count, header: "record_id,predicted_class,anomaly_score,evidence_status" },
    { filename: "policies.csv", label: "FILE 02", description: "Temporary simulated policies with scope, activation, and expiry.", rows: validationReport?.policies?.policy_count, header: "policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id" },
    { filename: "replay.csv", label: "FILE 03", description: "One chronological ALLOW/BLOCK action per record; ALLOW uses NONE and BLOCK references the smallest matching active policy ID.", rows: validationReport?.replay?.row_count, header: "record_id,action,active_policy_id" },
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
            <div>policies.csv · {validationReport.policies?.policy_count ?? "—"} policies · {validationReport.policies?.total_errors ?? "—"} errors</div>
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
// 8. MODEL INTELLIGENCE VIEW (Real Confusion Matrix, Per-Class Metrics, ROC/PR)
// ============================================================================
export function ModelIntelligenceView() {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [evaluationReports, setEvaluationReports] = useState<any>(null);
  const [evaluationLoading, setEvaluationLoading] = useState(true);
  const [evaluationError, setEvaluationError] = useState("");
  const [snapshotSaving, setSnapshotSaving] = useState(false);
  const [snapshotMessage, setSnapshotMessage] = useState("");

  useEffect(() => {
    apiFetch("/api/evaluation/all")
      .then(async response => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail?.message || "Evaluation reports unavailable.");
        setEvaluationReports(data);
      })
      .catch(err => setEvaluationError(err instanceof Error ? err.message : "Evaluation reports could not be loaded."))
      .finally(() => setEvaluationLoading(false));
  }, []);

  useEffect(() => {
    apiFetch("/api/benchmarks")
      .then(async response => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail?.message || data.detail || "No generated benchmark report is available.");
        setReport(data.verified_report || null);
      })
      .catch(err => setError(err instanceof Error ? err.message : "Benchmark report could not be loaded."))
      .finally(() => setLoading(false));
  }, []);

  async function saveEvaluationSnapshot() {
    if (!evaluationReports || evaluationReports.available_reports < 1) return;
    setSnapshotSaving(true);
    setSnapshotMessage("");
    try {
      const classification = evaluationReports.reports?.classification || {};
      const metrics = classification.metrics || {};
      const dataset = classification.evaluation_dataset || report?.evaluation_dataset || {};
      const rowCount = Number(dataset.rows || dataset.total_rows || 0);
      const response = await apiFetch("/api/evaluation/snapshot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dataset_name: dataset.name || dataset.path || "generated-evaluation-reports",
          dataset_rows: rowCount,
          processed_rows: rowCount,
          status: "completed",
          model_version: threat?.model_type || "model-artifact",
          accuracy: typeof metrics.accuracy === "number" ? metrics.accuracy : typeof threat?.accuracy === "number" ? threat.accuracy : null,
          macro_f1: typeof metrics.macro_f1 === "number" ? metrics.macro_f1 : typeof threat?.macro_f1 === "number" ? threat.macro_f1 : null,
          summary: {
            available_reports: evaluationReports.available_reports,
            expected_reports: evaluationReports.expected_reports,
            missing_reports: evaluationReports.missing_reports || [],
            classification: metrics,
            anomaly: evaluationReports.reports?.anomaly || {},
            temporal: evaluationReports.reports?.temporal || {},
            defense: evaluationReports.reports?.defense || {},
          },
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail?.message || data.detail || "Could not save evaluation snapshot.");
      if (!data.supabase_persistence?.stored) throw new Error(data.supabase_persistence?.reason || "Supabase did not confirm the snapshot.");
      setSnapshotMessage("Evaluation snapshot saved to your private Supabase history.");
    } catch (reason) {
      setSnapshotMessage(reason instanceof Error ? reason.message : "Evaluation snapshot could not be saved.");
    } finally {
      setSnapshotSaving(false);
    }
  }

  const threat = report?.agent_1_threat_detection;
  const anomaly = report?.agent_2_anomaly_detection;
  const classes: string[] = threat?.class_order || [];
  const matrix: number[][] | null = Array.isArray(threat?.confusion_matrix) ? threat.confusion_matrix : null;
  const perClass = threat?.per_class || {};
  const pct = (value: unknown) => typeof value === "number" ? (value * 100).toFixed(3) + "%" : "—";

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">MODEL EVALUATION · GENERATED BENCHMARK REPORT</div>
          <h3>Model Intelligence & Diagnostics</h3>
          <p>Displays metrics only when a benchmark report is available. A1 confidence calibration depends on the loaded artifact; A2 exports a bounded anomaly index, not an attack probability.</p>
        </div>
        <span className="panel-icon"><Gauge size={18} /></span>
      </div>

      {loading && <div className="empty-inline" style={{ marginTop: 15 }}>Loading benchmark report…</div>}
      {error && <div className="parse-warning" role="alert" style={{ marginTop: 15 }}>{error}</div>}

      {report && <>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 10, margin: "16px 0" }}>
          {[
            ["A1 ACCURACY", pct(threat?.accuracy)],
            ["A1 MACRO F1", typeof threat?.macro_f1 === "number" ? threat.macro_f1.toFixed(6) : "—"],
            ["A2 BENIGN FPR", pct(anomaly?.benign_false_positive_rate)],
            ["A1 INFERENCE", typeof threat?.inference_ms_per_flow === "number" ? threat.inference_ms_per_flow.toFixed(4) + " ms/flow" : "—"],
          ].map(([label, value]) => <div key={label} style={{ background: "var(--panel2)", padding: 13, borderRadius: 8, border: "1px solid var(--line)" }}><small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small><div style={{ fontSize: 19, fontWeight: 700, marginTop: 5 }}>{value}</div></div>)}
        </div>

        {matrix && <div style={{ background: "var(--panel2)", padding: 15, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 15 }}>
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>A1 multiclass confusion matrix · {report.evaluation_dataset?.rows?.toLocaleString() ?? "—"} evaluation rows</div>
          <div style={{ overflowX: "auto" }}><table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10, textAlign: "center" }}>
            <thead><tr style={{ borderBottom: "1px solid var(--line)", color: "var(--muted)" }}><th style={{ textAlign: "left", padding: 8 }}>TRUE / PREDICTED</th>{classes.map(value => <th key={value} style={{ padding: 8 }}>{value}</th>)}</tr></thead>
            <tbody>{classes.map((value, row) => <tr key={value} style={{ borderBottom: "1px solid var(--line)" }}>
              <td style={{ textAlign: "left", padding: 8, fontWeight: 600 }}>{value}</td>
              {(matrix[row] || []).map((count, col) => <td key={col} style={{ padding: 8, fontFamily: "monospace", fontWeight: row === col ? 700 : 400, background: row === col ? "rgba(34,197,94,.12)" : count > 0 ? "rgba(239,68,68,.15)" : "transparent", color: row === col ? "var(--green)" : count > 0 ? "#ef4444" : "var(--muted)" }}>{count.toLocaleString()}</td>)}
            </tr>)}</tbody>
          </table></div>
        </div>}

        {Object.keys(perClass).length > 0 && <div style={{ background: "var(--panel2)", padding: 15, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>A1 per-class evaluation metrics</div>
          <div style={{ overflowX: "auto" }}><table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
            <thead><tr style={{ borderBottom: "1px solid var(--line)", color: "var(--muted)", textAlign: "left" }}><th style={{ padding: 8 }}>CLASS</th><th style={{ padding: 8 }}>PRECISION</th><th style={{ padding: 8 }}>RECALL</th><th style={{ padding: 8 }}>F1</th><th style={{ padding: 8 }}>SUPPORT</th></tr></thead>
            <tbody>{classes.map(value => {
              const item = perClass[value] || {};
              return <tr key={value} style={{ borderBottom: "1px solid var(--line)" }}>
                <td style={{ padding: 8, fontWeight: 600 }}>{value}</td>
                <td style={{ padding: 8, fontFamily: "monospace" }}>{typeof item.precision === "number" ? item.precision.toFixed(5) : "—"}</td>
                <td style={{ padding: 8, fontFamily: "monospace" }}>{typeof item.recall === "number" ? item.recall.toFixed(5) : "—"}</td>
                <td style={{ padding: 8, fontFamily: "monospace", color: "var(--green)" }}>{typeof item.f1 === "number" ? item.f1.toFixed(5) : "—"}</td>
                <td style={{ padding: 8, fontFamily: "monospace" }}>{typeof item.support === "number" ? item.support.toLocaleString() : "—"}</td>
              </tr>;
            })}</tbody>
          </table></div>
        </div>}

        <div style={{ marginTop: 12, fontSize: 10, color: "var(--muted)" }}>
          A1 backend: {threat?.model_type || "not specified"} · A2 algorithm: {anomaly?.algorithm || "not specified"} · A2 threshold: {anomaly?.threshold ?? "—"} · A2 attack anomaly recall: {pct(anomaly?.attack_anomaly_recall)}
        </div>
        <div style={{ marginTop: 6, fontSize: 10, color: "var(--muted)" }}>Source: {report.evaluation_dataset?.path || "benchmark report"} · Training/evaluation provenance must be checked against the accompanying experiment documentation.</div>
      </>}
      <div style={{ marginTop: 18, padding: 15, border: "1px solid var(--line)", borderRadius: 10, background: "var(--panel2)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <div>
            <div className="panel-kicker">EXTENDED EVALUATION · LOCAL GENERATED REPORTS</div>
            <b style={{ fontSize: 13 }}>Five-agent evaluation suite</b>
            <p style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 0" }}>Only metrics from generated reports are shown. Missing reports are not replaced with estimates.</p>
          </div>
          <span style={{ fontSize: 10, color: "var(--muted)" }}>{evaluationLoading ? "Loading…" : evaluationReports?.status === "ready" ? "All reports available" : evaluationReports?.status === "partial" ? "Partial reports" : "Not generated"}</span>
        </div>
        {evaluationError && <div className="parse-warning" role="alert" style={{ marginTop: 10 }}>{evaluationError}</div>}
        {!evaluationLoading && !evaluationError && <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))", gap: 9, marginTop: 13 }}>
            {[
              ["A1 accuracy", evaluationReports?.reports?.classification?.metrics?.accuracy],
              ["A1 macro F1", evaluationReports?.reports?.classification?.metrics?.macro_f1],
              ["A2 ROC-AUC", evaluationReports?.reports?.anomaly?.roc_auc],
              ["A2 PR-AUC", evaluationReports?.reports?.anomaly?.average_precision],
              ["A4 campaigns", evaluationReports?.reports?.temporal?.evaluation_summary?.total_campaigns_detected],
              ["A5 containment", evaluationReports?.reports?.defense?.comparison_table?.config_4_temporal_plus_defense?.containment_rate],
            ].map(([label, value]) => <div key={String(label)} style={{ padding: 11, borderRadius: 7, border: "1px solid var(--line)", background: "var(--panel)" }}>
              <small style={{ color: "var(--muted)", fontSize: 9 }}>{label}</small>
              <div style={{ fontSize: 17, fontWeight: 700, marginTop: 5 }}>{typeof value === "number" ? (String(label).includes("campaigns") ? value.toLocaleString() : value.toFixed(4)) : "—"}</div>
            </div>)}
          </div>
          {evaluationReports?.status === "not_generated" && <p style={{ fontSize: 11, color: "var(--muted)", margin: "12px 0 0" }}>Run <code>python scripts/evaluate_full_system.py</code> locally after preparing the authorized training/evaluation datasets and training both model artifacts. The hidden replay input is not a labelled evaluation set.</p>}
          {evaluationReports?.missing_reports?.length > 0 && <p style={{ fontSize: 10, color: "var(--muted)", margin: "8px 0 0" }}>Missing: {evaluationReports.missing_reports.join(", ")}</p>}
          {evaluationReports?.available_reports > 0 && <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button className="secondary-btn" type="button" onClick={() => void saveEvaluationSnapshot()} disabled={snapshotSaving}>
              {snapshotSaving ? "Saving…" : "Save evaluation snapshot to Supabase"}
            </button>
            {snapshotMessage && <span style={{ fontSize: 10, color: snapshotMessage.includes("saved") ? "var(--green)" : "var(--muted)" }}>{snapshotMessage}</span>}
          </div>}
        </>}
      </div>

      <div className="panel-foot" style={{ marginTop: 14 }}>
        <span><LockKeyhole size={13} /> No fallback metrics or confusion matrix are fabricated</span>
        <span>CONFIDENCE CALIBRATION IS ARTIFACT-DEPENDENT</span>
      </div>
    </section>
  );
}

// ============================================================================
// 9. AUDIT & SUPABASE RUN HISTORY VIEW
// ============================================================================
export function AuditHistoryView() {
  const [runs, setRuns] = useState<any[]>([]);
  const [evaluationRuns, setEvaluationRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch("/api/history?limit=10")
      .then(res => res.json())
      .then(data => {
        setRuns(data.runs || []);
        setEvaluationRuns(data.evaluation_runs || []);
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
          <div className="panel-kicker">FORENSIC AUDIT TRAIL · SUPABASE USER HISTORY</div>
          <h3>Cloud Execution & Replay Run History</h3>
          <p>
            Persisted to your private Supabase account with row-level access controls. Raw flow data and uploaded CSV files remain local.
          </p>
        </div>
        <span className="panel-icon"><Database size={18} /></span>
      </div>

      {loading ? (
        <div style={{ padding: 24, textAlign: "center", color: "var(--muted)", fontSize: 12 }}>
          Loading your private replay records from Supabase…
        </div>
      ) : runs.length === 0 ? (
        <div style={{ background: "var(--panel2)", padding: 20, borderRadius: 8, border: "1px solid var(--line)", textAlign: "center", margin: "14px 0" }}>
          <Database size={24} style={{ color: "var(--muted)", margin: "0 auto 8px auto", display: "block" }} />
          <b style={{ fontSize: 13, color: "var(--text)" }}>No Replay Runs Logged Yet</b>
          <p style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 0 0" }}>
            Execute a run in Replay Studio to save its summary to your private Supabase history.
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
                  <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 700 }}>{typeof r.containment_rate === "number" ? `${r.containment_rate.toFixed(2)}%` : "—"}</td>
                  <td style={{ padding: 8, fontFamily: "monospace" }}>{r.throughput_fps} fps</td>
                  <td style={{ padding: 8, color: "var(--muted)" }}>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {evaluationRuns.length > 0 && <div style={{ marginTop: 18 }}>
        <div className="panel-kicker" style={{ marginBottom: 8 }}>MODEL EVALUATION SNAPSHOTS</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
            <thead><tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
              <th style={{ padding: 8 }}>DATASET</th><th style={{ padding: 8 }}>ROWS</th><th style={{ padding: 8 }}>PROCESSED</th><th style={{ padding: 8 }}>ACCURACY</th><th style={{ padding: 8 }}>MACRO F1</th><th style={{ padding: 8 }}>STATUS</th><th style={{ padding: 8 }}>TIMESTAMP</th>
            </tr></thead>
            <tbody>{evaluationRuns.map(item => <tr key={item.id} style={{ borderBottom: "1px solid var(--line)" }}>
              <td style={{ padding: 8 }}>{item.dataset_name}</td><td style={{ padding: 8 }}>{Number(item.dataset_rows).toLocaleString()}</td><td style={{ padding: 8 }}>{Number(item.processed_rows).toLocaleString()}</td>
              <td style={{ padding: 8 }}>{typeof item.accuracy === "number" ? item.accuracy.toFixed(5) : "—"}</td><td style={{ padding: 8 }}>{typeof item.macro_f1 === "number" ? item.macro_f1.toFixed(5) : "—"}</td><td style={{ padding: 8 }}>{item.status}</td><td style={{ padding: 8, color: "var(--muted)" }}>{new Date(item.created_at).toLocaleString()}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </div>}
      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Private Supabase history · Raw network data stays local</span>
        <span>DATABASE: public.replay_runs · public.analysis_runs</span>
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
      const response = await apiFetch("/api/system/diagnostics");
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
          <p>Backend, model-artifact and Supabase configuration status are shown separately. Missing models, datasets or generated files are shown as unavailable.</p>
        </div>
        <button className="secondary-btn" type="button" onClick={loadDiagnostics} disabled={loading}><RefreshCw size={14}/> Refresh diagnostics</button>
      </div>

      {loading && <div className="empty-inline">Reading local artifacts and Supabase configuration…</div>}
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
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>Local SQLite fallback</span>{statusTag(diagnostics.history_database?.present, "PRESENT")}</div>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}><span style={{ fontSize: 11 }}>Supabase cloud audit</span>{statusTag(diagnostics.supabase?.configured, "CONFIGURED")}</div>
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

        <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--blue)", marginBottom: 7 }}>KNOWN LIMITATIONS · JUDGE DISCLOSURE</div>
          <ul style={{ margin: 0, paddingLeft: 17, fontSize: 10, color: "var(--muted)", lineHeight: 1.65 }}>
            <li>When native Layer-3 source IP is absent, the source identity is synthesized from three TCP-stack fingerprint fields. It is not observed; identical fingerprints share an identity and the 24-bit hash can collide, potentially causing false blocks.</li>
            <li>8.58% of the audited evaluation rows share exact feature vectors with training data; repeated-flow results can therefore be optimistic.</li>
            <li>A1 confidence is calibrated only when a separate held-out temperature-calibration run is recorded in the model artifact. A2's 0–1 anomaly index is not a probability.</li>
            <li>The 150-flow correlation cap, 300-second timestamp window, and 150-position default policy lifetime are fixed parameters, not adaptive learned values.</li>
            <li>Evaluation is CICIDS2017-only and offline. Cross-dataset generalization and live-network operation are untested; all defense actions are simulated.</li>
          </ul>
        </div>
      </>}

      <div className="panel-foot" style={{ marginTop: 14 }}>
        <span><LockKeyhole size={13}/> Simulated policies only · No live network access</span>
        <span>ENVIRONMENT: LOCAL OFFLINE REPLAY</span>
      </div>
    </section>
  );
}
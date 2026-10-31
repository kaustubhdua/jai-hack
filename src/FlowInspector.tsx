import { useState } from "react";
import {
  Activity, ArrowRight, Cpu, LockKeyhole, Network,
  Copy, Check, BarChart3
} from "lucide-react";

type FlowResult = {
  final_class: string | null;
  evidence_status: string;
  action: string;
  rationale: string[];
  threat_detection?: { predicted_class?: string; confidence?: number; status?: string; message?: string };
  model_provenance?: { a1_confidence_calibrated?: boolean; a2_score_is_probability?: boolean };
  execution_mode?: string;
  stateful_agents?: string;
  anomaly_detection?: {
    anomaly_score?: number | null;
    is_anomaly?: boolean | null;
    evidence?: { feature: string; evidence_code: string; observed_value: number; baseline_q01: number; baseline_median: number; baseline_q99: number; deviation_strength_iqr: number; interpretation: string; }[];
    status?: string;
    message?: string;
  };
  latency_ms?: number;
};

export function FlowInspector({ modelReady }: { modelReady: boolean }) {
  const [flowJson, setFlowJson] = useState("");
  const [result, setResult] = useState<FlowResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copiedReport, setCopiedReport] = useState(false);

  async function analyze() {
    let flow: Record<string, unknown>;
    try {
      flow = JSON.parse(flowJson);
      if (!flow || Array.isArray(flow) || typeof flow !== "object" || !Object.keys(flow).length) {
        throw new Error("Enter a non-empty JSON object for one network flow.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invalid JSON.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Analysis request failed."));
      }
      setResult(payload as FlowResult);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The flow could not be analyzed.");
    } finally {
      setBusy(false);
    }
  }

  const anomalyTelemetry = result?.anomaly_detection;
  const anomalyEvidence = anomalyTelemetry?.evidence ?? [];
  const threatTelemetry = result?.threat_detection;
  const confidenceCalibrated = result?.model_provenance?.a1_confidence_calibrated === true;

  async function copyAnalysisSummary() {
    if (!result) return;
    let suppliedRecordId = "Not supplied";
    let suppliedTimestamp = "Not supplied";
    try {
      const input = JSON.parse(flowJson);
      suppliedRecordId = String(input.record_id ?? "Not supplied");
      suppliedTimestamp = String(input.timestamp ?? input.Timestamp ?? "Not supplied");
    } catch { /* The analysis request already validated JSON. */ }
    const report = [
      "# CyberSentinel single-flow analysis",
      "Execution: offline A1–A3 model inference; no live capture or enforcement",
      `Input record ID: ${suppliedRecordId}`,
      `Input timestamp: ${suppliedTimestamp}`,
      `Predicted class: ${result.final_class ?? "Unavailable"}`,
      `A1 confidence: ${typeof threatTelemetry?.confidence === "number" ? threatTelemetry.confidence.toFixed(5) : "Unavailable"} (${confidenceCalibrated ? "held-out calibrated" : "uncalibrated; do not interpret as probability"})`,
      `A2 anomaly index: ${typeof anomalyTelemetry?.anomaly_score === "number" ? anomalyTelemetry.anomaly_score.toFixed(5) : "Unavailable"} (not a probability)`,
      `A2 flagged: ${anomalyTelemetry?.is_anomaly == null ? "Unknown" : String(anomalyTelemetry.is_anomaly)}`,
      `A3 evidence status: ${result.evidence_status}`,
      `A3 recommendation: ${result.action}`,
      `Inference latency: ${result.latency_ms == null ? "Unavailable" : result.latency_ms.toFixed(2) + " ms"}`,
      "",
      "## Model rationale",
      ...(result.rationale ?? []).map(item => `- ${item}`),
      "",
      "## Agent 2 observed deviations",
      ...(anomalyEvidence.length ? anomalyEvidence.map(item => `- ${item.feature}: observed ${item.observed_value}; baseline q01 ${item.baseline_q01}; median ${item.baseline_median}; q99 ${item.baseline_q99}; ${item.interpretation}`) : ["- No structured deviation evidence returned."]),
    ].join("\n");
    try {
      await navigator.clipboard.writeText(report);
      setCopiedReport(true);
      window.setTimeout(() => setCopiedReport(false), 2500);
    } catch {
      setError("Clipboard access is unavailable in this browser.");
    }
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 24 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">
            <span className="pulse-dot" style={{ width: 6, height: 6 }} />
            LOCAL MODEL INFERENCE · OBSERVED INPUT ONLY
          </div>
          <h3>Single Flow Analysis</h3>
          <p>Analyze one flow record supplied from an authorized source. This is offline inference, not live packet capture or network monitoring.</p>
        </div>
        <span className="panel-icon"><Network size={18} /></span>
      </div>

      <div style={{ fontSize: 11, color: "var(--muted)", margin: "14px 0" }}>Paste one observed flow record as JSON. No sample incidents or synthetic attack presets are preloaded.</div>

      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 16, marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: "var(--muted)", marginBottom: 6, display: "flex", justifyContent: "space-between" }}>
            <span>OBSERVED FLOW RECORD · JSON:</span>
            <span>MODEL FEATURE SCHEMA + OPTIONAL OBSERVED ENDPOINT METADATA</span>
          </div>
          <textarea
            aria-label="Network flow JSON"
            value={flowJson}
            onChange={event => setFlowJson(event.target.value)}
            spellCheck={false}
            style={{
              width: "100%",
              minHeight: 200,
              resize: "vertical",
              padding: 14,
              borderRadius: 10,
              border: "1px solid var(--line)",
              background: "rgba(10, 16, 30, 0.75)",
              color: "#38bdf8",
              fontFamily: "'DM Mono', monospace",
              fontSize: 11,
              lineHeight: 1.6,
              boxShadow: "inset 0 2px 10px rgba(0,0,0,0.5)"
            }}
          />
        </div>

        {/* Evidence is rendered only from the trained anomaly agent's returned payload. */}
        <div style={{ background: "rgba(12, 19, 35, 0.7)", padding: 14, borderRadius: 10, border: "1px solid var(--line)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <BarChart3 size={16} color="#38bdf8" />
            <b style={{ fontSize: 12, letterSpacing: "0.5px" }}>Agent 2 · Observed Deviation Evidence</b>
          </div>
          {!result && <p style={{ fontSize: 10, color: "var(--muted)" }}>Run inference to inspect the actual anomaly score and any deviations returned by the trained Agent 2 model.</p>}
          {result && <div style={{ fontSize: 11, marginBottom: 10 }}>
            <span style={{ color: "var(--muted)" }}>Anomaly index: </span>
            <b>{anomalyTelemetry?.anomaly_score == null ? "Unavailable" : anomalyTelemetry.anomaly_score.toFixed(4)}</b>
            <span style={{ color: "var(--muted)", marginLeft: 10 }}>Flagged: </span>
            <b>{anomalyTelemetry?.is_anomaly == null ? "Unknown" : anomalyTelemetry.is_anomaly ? "Yes" : "No"}</b>
          </div>}
          {result && anomalyEvidence.length === 0 && <div className="empty-inline" style={{ fontSize: 10 }}>
            {anomalyTelemetry?.status === "success" && anomalyTelemetry?.is_anomaly === false
              ? "Agent 2 did not flag this flow; no deviation evidence was emitted."
              : "No structured deviation evidence was returned by Agent 2."}
          </div>}
          {anomalyEvidence.length > 0 && <div style={{ display: "grid", gap: 10 }}>
            {anomalyEvidence.map((item, index) => <div key={item.feature + index} style={{ padding: 10, borderRadius: 7, background: "var(--panel)", border: "1px solid var(--line)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                <b style={{ fontSize: 11 }}>{item.feature}</b>
                <span className="tag">{item.evidence_code}</span>
              </div>
              <div style={{ fontSize: 10, color: "var(--muted)", lineHeight: 1.6 }}>
                Observed: <b style={{ color: "var(--text)" }}>{Number(item.observed_value).toLocaleString()}</b>
                {" · "}Training q01: {Number(item.baseline_q01).toLocaleString()}
                {" · "}Median: {Number(item.baseline_median).toLocaleString()}
                {" · "}q99: {Number(item.baseline_q99).toLocaleString()}
              </div>
              <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 4 }}>
                Deviation: {Number(item.deviation_strength_iqr).toFixed(2)} IQR · {item.interpretation}
              </div>
            </div>)}
          </div>}
          <p style={{ fontSize: 9, color: "var(--muted)", margin: "12px 0 0" }}>
            Statistical deviations are supporting evidence, not proof of malicious activity. No heuristic feature-impact scores are displayed.
          </p>
        </div>
      </div>

      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Offline replay only · Simulated mitigation boundaries</span>
        <button className="primary-btn" disabled={!modelReady || busy} onClick={analyze}>
          {busy ? "Running A1–A3 model inference…" : "Analyze observed flow"} <ArrowRight size={14} />
        </button>
      </div>

      {!modelReady && (
        <div className="empty-inline" style={{ marginTop: 12 }}>
          Inference is disabled until both trained model artifacts are installed and verified. The API remains fail-closed.
        </div>
      )}

      {error && <div className="parse-warning" role="alert" style={{ marginTop: 12 }}>{error}</div>}

      {/* Analysis results derived only from model outputs */}
      {result && (
        <div className="dataset-loaded" style={{ marginTop: 18, borderTop: "1px solid var(--line)", paddingTop: 16 }}>
          <div className="dataset-facts" style={{ margin: "0 0 16px 0" }}>
            <div>
              <small>FINAL CLASS</small>
              <b style={{ color: result.final_class === "BENIGN" ? "#34d399" : "#f43f5e" }}>
                {result.final_class ?? "Unconfirmed"}
              </b>
            </div>
            <div>
              <small>A3 RECOMMENDATION</small>
              <b style={{ color: result.action === "BLOCK" ? "#f43f5e" : "#34d399" }}>
                {result.action}
              </b>
            </div>
            <div>
              <small>EVIDENCE STATUS</small>
              <b style={{ color: "#38bdf8" }}>{result.evidence_status}</b>
            </div>
            <div>
              <small>INFERENCE LATENCY</small>
              <b style={{ color: "#a855f7" }}>{result.latency_ms == null ? "—" : result.latency_ms.toFixed(2) + " ms"}</b>
            </div>
          </div>

          <div style={{ background: "rgba(15, 23, 42, 0.75)", border: "1px solid rgba(56, 189, 248, 0.25)", borderRadius: 10, padding: 16, marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>Model output provenance</b>
              <button onClick={copyAnalysisSummary} className="secondary-btn" style={{ padding: "4px 8px", fontSize: 10 }}>
                {copiedReport ? <><Check size={12} color="#34d399" /> Copied</> : <><Copy size={12} /> Copy analysis summary</>}
              </button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 10, marginTop: 12 }}>
              <div><small style={{ color: "var(--muted)", fontSize: 9 }}>A1 CLASSIFIER CONFIDENCE</small><div style={{ fontWeight: 700 }}>{typeof threatTelemetry?.confidence === "number" ? threatTelemetry.confidence.toFixed(4) : "Unavailable"}</div><small style={{ color: "var(--muted)" }}>{confidenceCalibrated ? "Calibrated on a separate held-out set" : "Uncalibrated; not a probability"}</small></div>
              <div><small style={{ color: "var(--muted)", fontSize: 9 }}>A2 ANOMALY INDEX</small><div style={{ fontWeight: 700 }}>{typeof anomalyTelemetry?.anomaly_score === "number" ? anomalyTelemetry.anomaly_score.toFixed(4) : "Unavailable"}</div><small style={{ color: "var(--muted)" }}>Bounded index; not a probability</small></div>
            </div>
            <p style={{ fontSize: 10, color: "var(--muted)", margin: "12px 0 0", lineHeight: 1.6 }}>
              ATT&CK techniques are not inferred from a five-class flow label. Verify the underlying evidence and environment before assigning an adversary technique or taking response action.
            </p>
          </div>

          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>A3 Fusion Rationale:</div>
          <ul style={{ margin: "0 0 14px 0", paddingLeft: 18, color: "var(--text)", fontSize: 11, lineHeight: 1.7 }}>
            {(result.rationale ?? []).map((line, index) => <li key={index}>{line}</li>)}
          </ul>

          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: "pointer", fontSize: 11, color: "var(--muted)" }}>View raw Agent 1 & Agent 2 telemetry payload</summary>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: 8, fontSize: 11, background: "rgba(8, 14, 26, 0.8)", padding: 12, borderRadius: 8, border: "1px solid var(--line)" }}>
              {JSON.stringify({ threat_detection: result.threat_detection, anomaly_detection: result.anomaly_detection }, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </section>
  );
}

export function AgentReadiness({ health }: { health: { model_ready: boolean; agents?: Record<string, boolean> } | null }) {
  const agents = [
    ["Agent 1 · Threat Detection (Random Forest)", Boolean(health?.agents?.agent_1_threat_detection)],
    ["Agent 2 · Anomaly Detection (Isolation Forest)", Boolean(health?.agents?.agent_2_anomaly_detection)],
    ["Agent 3 · Evidence Fusion Matrix", Boolean(health?.agents?.agent_3_evidence_fusion)],
    ["Agent 4 · Temporal Correlation (150-Flow Window)", Boolean(health?.agents?.agent_4_temporal_correlation)],
    ["Agent 5 · Adaptive Defense Engine", Boolean(health?.agents?.agent_5_adaptive_defense)],
  ];
  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">SYSTEM CAPABILITIES</div>
          <h3>Model & Agent Operational Health</h3>
          <p>Real-time backend readiness contracts across all five defense agents.</p>
        </div>
        <span className="panel-icon"><Cpu size={18} /></span>
      </div>
      <div className="agent-list">
        {agents.map(([name, ready]) => (
          <div className="agent-row" key={String(name)}>
            <div className="agent-icon"><Cpu size={17} /></div>
            <div className="agent-copy">
              <b>{String(name)}</b>
              <span>{ready ? "Active & Verified" : "Awaiting Model Artifact"}</span>
            </div>
            <span className={"agent-status " + (ready ? "ready" : "pending")}>
              {ready ? "Ready" : "Pending"}
            </span>
          </div>
        ))}
      </div>
      <div className="fusion-note" style={{ marginTop: 12 }}>
        Overall Inference Status: <strong>{health?.model_ready ? "Operational (Models loaded & verified)" : "Not ready — API fails closed"}</strong>.
      </div>
    </section>
  );
}

type AnomalyResult = {
  anomaly_score: number | null;
  is_anomaly: boolean | null;
  evidence: (string | Record<string, unknown>)[];
  status: string;
  message?: string | null;
};

export function Agent2Console({ ready }: { ready: boolean }) {
  const [flowJson, setFlowJson] = useState("");
  const [result, setResult] = useState<AnomalyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function score() {
    let flow: Record<string, unknown>;
    try {
      flow = JSON.parse(flowJson);
      if (!flow || Array.isArray(flow) || typeof flow !== "object" || !Object.keys(flow).length) {
        throw new Error("Enter a non-empty JSON object for one network flow.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invalid JSON.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/agents/anomaly/score", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Agent 2 scoring failed."));
      setResult(payload as AnomalyResult);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Agent 2 could not score this flow.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
      <div className="panel-head">
        <div>
          <div className="panel-kicker">AGENT 02 · INDEPENDENT ANOMALY DETECTION</div>
          <h3>Agent 2 Unsupervised Isolation Forest</h3>
          <p>Score one network flow against the benign-only baseline. This runs Agent 2 independently of Agent 1 and fusion.</p>
        </div>
        <span className="panel-icon"><Activity size={18} /></span>
      </div>
      <textarea
        aria-label="Network flow JSON for Agent 2"
        value={flowJson}
        onChange={event => setFlowJson(event.target.value)}
        spellCheck={false}
        placeholder='Paste one captured flow JSON object using the trained model feature names.'
        style={{
          width: "100%",
          minHeight: 170,
          resize: "vertical",
          padding: 14,
          borderRadius: 9,
          border: "1px solid var(--line)",
          background: "var(--panel2)",
          color: "var(--text)",
          fontFamily: "'DM Mono', monospace",
          fontSize: 12,
          lineHeight: 1.6
        }}
      />
      <div className="panel-foot">
        <span><LockKeyhole size={13} /> Offline scoring only · No live network changes</span>
        <button className="primary-btn" disabled={!ready || busy} onClick={score}>
          {busy ? "Scoring…" : "Run Agent 2"} <ArrowRight size={14} />
        </button>
      </div>
      {!ready && <div className="empty-inline">Agent 2 is not ready yet. Install the trained anomaly model and refresh API status.</div>}
      {error && <div className="parse-warning" role="alert">{error}</div>}
      {result && (
        <div className="dataset-loaded" style={{ marginTop: 18 }}>
          <div className="dataset-facts">
            <div><small>ANOMALY RESULT</small><b>{result.is_anomaly == null ? "Unknown" : result.is_anomaly ? "Anomaly Flagged" : "Baseline-like"}</b></div>
            <div><small>ANOMALY INDEX · NOT A PROBABILITY</small><b>{result.anomaly_score == null ? "—" : result.anomaly_score.toFixed(5)}</b></div>
            <div><small>STATUS</small><b>{result.status}</b></div>
          </div>
          <b>Feature evidence</b>
          {result.evidence.length ? (
            <ul>{result.evidence.map((item, index) => <li key={index}>{typeof item === "string" ? item.replaceAll("_", " ") : JSON.stringify(item)}</li>)}</ul>
          ) : (
            <div className="empty-inline">No out-of-range feature evidence was returned for this flow.</div>
          )}
          <small className="muted">The 0–1 anomaly index is higher for more anomalous traffic; it is a bounded score, not a probability. Agent 2 applies its learned threshold to the underlying Isolation Forest decision function.</small>
        </div>
      )}
    </section>
  );
}

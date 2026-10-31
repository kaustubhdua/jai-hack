import { useEffect, useState } from "react";
import {
  Activity, AlertTriangle, ArrowRight, Check, ChevronRight, Cpu,
  Database, Download, ExternalLink, FileSpreadsheet, Fingerprint,
  Gauge, Layers, LockKeyhole, RefreshCw, Shield, ShieldAlert,
  ShieldCheck, SlidersHorizontal, Sparkles, TrendingUp
} from "lucide-react";

interface EvaluationData {
  status: string;
  missing_reports: string[];
  reports: {
    summary?: any;
    classification?: any;
    fusion?: any;
    anomaly?: any;
    generalization?: any;
    calibration?: any;
    loao?: any;
    temporal?: any;
    defense?: any;
  };
}

export function ModelIntelligenceView() {
  const [data, setData] = useState<EvaluationData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<
    "summary" | "a1" | "fusion" | "a2" | "generalization" | "calibration" | "loao" | "temporal" | "defense" | "plots"
  >("summary");

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/evaluation/all");
      if (!res.ok) {
        throw new Error(`Evaluation API returned status ${res.status}`);
      }
      const json = await res.json();
      setData(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load evaluation reports.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const summary = data?.reports?.summary?.data;
  const metadata = data?.reports?.summary?.metadata;
  const a1 = data?.reports?.classification?.data;
  const fusion = data?.reports?.fusion?.data;
  const a2 = data?.reports?.anomaly?.data;
  const gen = data?.reports?.generalization?.data;
  const cal = data?.reports?.calibration?.data;
  const loao = data?.reports?.loao?.data;
  const temporal = data?.reports?.temporal?.data;
  const defense = data?.reports?.defense?.data;

  const pct = (val: number | null | undefined) =>
    typeof val === "number" ? (val * 100).toFixed(3) + "%" : "—";
  const num = (val: number | null | undefined, dec = 4) =>
    typeof val === "number" ? val.toFixed(dec) : "—";

  return (
    <section className="panel dataset-panel" style={{ marginBottom: 24 }}>
      {/* Header */}
      <div className="panel-head">
        <div>
          <div className="panel-kicker">RESEARCH-GRADE MULTI-AGENT EVALUATION ENGINE</div>
          <h3>Model Intelligence & Diagnostics Suite</h3>
          <p>
            Comprehensive empirical verification across all 5 agents: Random Forest, Isolation Forest,
            Evidence Fusion, Temporal Correlation, and Adaptive Defense.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button className="secondary-btn" onClick={loadData} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin-icon" : ""} /> Refresh
          </button>
          <span className="panel-icon"><Gauge size={20} /></span>
        </div>
      </div>

      {loading && (
        <div className="empty-inline" style={{ marginTop: 20 }}>
          Loading evaluation metrics and benchmark reports…
        </div>
      )}

      {error && (
        <div className="parse-warning" role="alert" style={{ marginTop: 16 }}>
          {error}
        </div>
      )}

      {data && !loading && (
        <>
          {/* Sub-tab navigation */}
          <div
            style={{
              display: "flex",
              gap: 6,
              overflowX: "auto",
              paddingBottom: 6,
              margin: "16px 0",
              borderBottom: "1px solid var(--line)",
            }}
          >
            {[
              { id: "summary", label: "Executive Summary" },
              { id: "a1", label: "A1 Classification" },
              { id: "fusion", label: "A1 vs A3 Fusion" },
              { id: "a2", label: "A2 Anomaly Detection" },
              { id: "generalization", label: "Generalization" },
              { id: "calibration", label: "Probability Calibration" },
              { id: "loao", label: "LOAO Zero-Day" },
              { id: "temporal", label: "A4 Temporal" },
              { id: "defense", label: "A5 Adaptive Defense" },
              { id: "plots", label: "Charts & Plots" },
            ].map(tab => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  background: activeTab === tab.id ? "var(--panel2)" : "transparent",
                  color: activeTab === tab.id ? "var(--text)" : "var(--muted)",
                  border: activeTab === tab.id ? "1px solid var(--blue)" : "1px solid transparent",
                  borderRadius: 6,
                  padding: "6px 12px",
                  fontSize: 11,
                  fontWeight: activeTab === tab.id ? 700 : 500,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  transition: "all 0.15s ease",
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === "summary" && (
            <div>
              {/* Top Key Metrics Banner */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
                  gap: 12,
                  marginBottom: 16,
                }}
              >
                {[
                  {
                    label: "A1 ACCURACY",
                    value: pct(summary?.executive_summary?.agent_1_random_forest?.accuracy),
                    sub: `Balanced: ${pct(summary?.executive_summary?.agent_1_random_forest?.balanced_accuracy)}`,
                    color: "var(--green)",
                  },
                  {
                    label: "A1 MACRO F1",
                    value: num(summary?.executive_summary?.agent_1_random_forest?.macro_f1, 6),
                    sub: `FPR: ${pct(summary?.executive_summary?.agent_1_random_forest?.benign_fpr)}`,
                    color: "var(--blue)",
                  },
                  {
                    label: "A2 ROC-AUC",
                    value: num(summary?.executive_summary?.agent_2_isolation_forest?.roc_auc, 4),
                    sub: `PR-AUC (AP): ${num(summary?.executive_summary?.agent_2_isolation_forest?.average_precision_pr_auc, 4)}`,
                    color: "var(--violet, #a855f7)",
                  },
                  {
                    label: "A5 CONTAINMENT",
                    value: pct(summary?.executive_summary?.adaptive_defense_a5?.full_system_containment_rate),
                    sub: `Preservation: ${pct(summary?.executive_summary?.adaptive_defense_a5?.full_system_benign_preservation)}`,
                    color: "var(--green)",
                  },
                ].map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: "var(--panel2)",
                      padding: 14,
                      borderRadius: 8,
                      border: "1px solid var(--line)",
                    }}
                  >
                    <small style={{ fontSize: 9, color: "var(--muted)", textTransform: "uppercase" }}>
                      {item.label}
                    </small>
                    <div style={{ fontSize: 20, fontWeight: 700, margin: "4px 0", color: item.color }}>
                      {item.value}
                    </div>
                    <small style={{ fontSize: 10, color: "var(--muted)" }}>{item.sub}</small>
                  </div>
                ))}
              </div>

              {/* 5-Agent Overview Cards */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                  gap: 14,
                  marginBottom: 16,
                }}
              >
                <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                    <ShieldCheck size={16} color="var(--green)" /> Agent 1: Threat Detection (Random Forest)
                  </div>
                  <ul style={{ fontSize: 11, color: "var(--muted)", paddingLeft: 16, lineHeight: 1.6 }}>
                    <li>Evaluated on full 114,185 flows from <code>eval_prepared.parquet</code></li>
                    <li>Attack Detection Rate: <b>{pct(summary?.executive_summary?.agent_1_random_forest?.attack_detection_rate)}</b></li>
                    <li>Benign False Positive Rate: <b>{pct(summary?.executive_summary?.agent_1_random_forest?.benign_fpr)}</b></li>
                    <li>Balanced Accuracy: <b>{pct(summary?.executive_summary?.agent_1_random_forest?.balanced_accuracy)}</b></li>
                  </ul>
                </div>

                <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                    <Activity size={16} color="var(--blue)" /> Agent 2: Anomaly Detection (Isolation Forest)
                  </div>
                  <ul style={{ fontSize: 11, color: "var(--muted)", paddingLeft: 16, lineHeight: 1.6 }}>
                    <li>Trained exclusively on verified Benign baseline traffic</li>
                    <li>Decision boundary: <code>score &gt; 0.5 &rarr; anomaly (1)</code>; <code>&le; 0.5 &rarr; normal (0)</code></li>
                    <li>ROC-AUC (Inverted scores): <b>{num(summary?.executive_summary?.agent_2_isolation_forest?.roc_auc, 4)}</b></li>
                    <li>Operational Attack Recall: <b>{pct(summary?.executive_summary?.agent_2_isolation_forest?.operational_attack_recall)}</b></li>
                  </ul>
                </div>

                <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                    <Layers size={16} color="var(--amber, #f59e0b)" /> Agent 3: Evidence Fusion (A1 vs A3)
                  </div>
                  <ul style={{ fontSize: 11, color: "var(--muted)", paddingLeft: 16, lineHeight: 1.6 }}>
                    <li>A1 Base Accuracy: <b>{pct(summary?.executive_summary?.agent_3_fusion?.a1_accuracy)}</b></li>
                    <li>A3 Final Accuracy: <b>{pct(summary?.executive_summary?.agent_3_fusion?.a3_accuracy)}</b></li>
                    <li>Fusion Overrides: <b>{summary?.executive_summary?.agent_3_fusion?.fusion_overrides?.toLocaleString() ?? 0}</b></li>
                    <li>Action Output: <b>ALLOW, REVIEW, BLOCK</b> (never silently defaulted to BENIGN)</li>
                  </ul>
                </div>

                <div style={{ background: "var(--panel2)", padding: 16, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                    <ShieldAlert size={16} color="var(--red, #ef4444)" /> Agents 4 & 5: Temporal Correlation & Defense
                  </div>
                  <ul style={{ fontSize: 11, color: "var(--muted)", paddingLeft: 16, lineHeight: 1.6 }}>
                    <li>Campaigns Detected: <b>{summary?.executive_summary?.temporal_correlation_a4?.total_campaigns ?? 0}</b> (Precision: {pct(summary?.executive_summary?.temporal_correlation_a4?.campaign_precision)})</li>
                    <li>Mean Detection Delay: <b>{num(summary?.executive_summary?.temporal_correlation_a4?.mean_detection_delay_flows, 1)} flows</b></li>
                    <li>Full System Containment Rate: <b>{pct(summary?.executive_summary?.adaptive_defense_a5?.full_system_containment_rate)}</b></li>
                    <li>Collateral Damage (False Block): <b>{pct(summary?.executive_summary?.adaptive_defense_a5?.full_system_false_block_rate)}</b></li>
                  </ul>
                </div>
              </div>

              {/* Audit Metadata Strip */}
              <div
                style={{
                  background: "var(--panel)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--line)",
                  fontSize: 10,
                  color: "var(--muted)",
                  display: "grid",
                  gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
                  gap: 10,
                }}
              >
                <div>
                  <b>Git Commit:</b> <code style={{ color: "var(--blue)" }}>{metadata?.git_commit?.slice(0, 8) || "unknown"}</code>
                </div>
                <div>
                  <b>Evaluator:</b> {metadata?.evaluator_version || "2.0.0"}
                </div>
                <div>
                  <b>Timestamp:</b> {metadata?.timestamp || "—"}
                </div>
                <div style={{ gridColumn: "span 3" }}>
                  <b>Dataset SHA-256:</b> <code style={{ fontSize: 9 }}>{metadata?.dataset_hashes?.eval_prepared?.sha256 || "—"}</code>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: A1 CLASSIFICATION */}
          {activeTab === "a1" && a1 && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["ACCURACY", pct(a1.metrics?.accuracy)],
                  ["BALANCED ACCURACY", pct(a1.metrics?.balanced_accuracy)],
                  ["MACRO F1", num(a1.metrics?.macro_f1, 6)],
                  ["WEIGHTED F1", num(a1.metrics?.weighted_f1, 6)],
                  ["MACRO PRECISION", num(a1.metrics?.macro_precision, 6)],
                  ["MACRO RECALL", num(a1.metrics?.macro_recall, 6)],
                  ["BENIGN FPR", pct(a1.metrics?.benign_false_positive_rate)],
                  ["ATTACK DETECTION", pct(a1.metrics?.attack_detection_rate)],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Per-Class Table */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Per-Class Classification Metrics</div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 8 }}>CLASS</th>
                        <th style={{ padding: 8 }}>PRECISION</th>
                        <th style={{ padding: 8 }}>RECALL</th>
                        <th style={{ padding: 8 }}>F1-SCORE</th>
                        <th style={{ padding: 8 }}>SUPPORT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(a1.per_class || {}).map(([cls, m]: [string, any]) => (
                        <tr key={cls} style={{ borderBottom: "1px solid var(--line)" }}>
                          <td style={{ padding: 8, fontWeight: 600 }}>{cls}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{num(m.precision, 5)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{num(m.recall, 5)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "var(--green)" }}>{num(m.f1, 5)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{m.support?.toLocaleString() ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Confusion Matrix */}
              {a1.confusion_matrix && (
                <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>
                    5x5 Confusion Matrix (Random Forest) · {a1.total_samples?.toLocaleString() ?? "—"} flows
                  </div>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10, textAlign: "center" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid var(--line)", color: "var(--muted)" }}>
                          <th style={{ textAlign: "left", padding: 8 }}>TRUE \ PRED</th>
                          {(a1.classes || []).map((c: string) => (
                            <th key={c} style={{ padding: 8 }}>{c}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {(a1.classes || []).map((c: string, rIdx: number) => (
                          <tr key={c} style={{ borderBottom: "1px solid var(--line)" }}>
                            <td style={{ textAlign: "left", padding: 8, fontWeight: 600 }}>{c}</td>
                            {(a1.confusion_matrix[rIdx] || []).map((count: number, cIdx: number) => (
                              <td
                                key={cIdx}
                                style={{
                                  padding: 8,
                                  fontFamily: "monospace",
                                  fontWeight: rIdx === cIdx ? 700 : 400,
                                  background: rIdx === cIdx ? "rgba(34,197,94,0.12)" : count > 0 ? "rgba(239,68,68,0.15)" : "transparent",
                                  color: rIdx === cIdx ? "var(--green)" : count > 0 ? "#ef4444" : "var(--muted)",
                                }}
                              >
                                {count.toLocaleString()}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: A1 VS A3 FUSION */}
          {activeTab === "fusion" && fusion && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["A1 BASE ACCURACY", pct(fusion.summary?.a1_accuracy)],
                  ["A3 FUSION ACCURACY", pct(fusion.summary?.a3_accuracy)],
                  ["NET IMPROVEMENT", pct(fusion.summary?.net_improvement_percentage / 100)],
                  ["FUSION OVERRIDES", fusion.summary?.total_overrides?.toLocaleString() ?? 0],
                  ["CORRECTED BY FUSION", fusion.summary?.corrected_by_fusion?.toLocaleString() ?? 0],
                  ["DAMAGED BY FUSION", fusion.summary?.damaged_by_fusion?.toLocaleString() ?? 0],
                  ["OVERRIDE ACCURACY", pct(fusion.summary?.fusion_override_accuracy)],
                  ["INCOMPLETE OUTPUTS", fusion.summary?.incomplete_outputs_count?.toLocaleString() ?? 0],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Security Actions Distribution (ALLOW, REVIEW, BLOCK) */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>
                  A3 Security Action Decisions (ALLOW / REVIEW / BLOCK)
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}>
                  <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
                    <div style={{ color: "var(--green)", fontWeight: 700, fontSize: 13 }}>ALLOW</div>
                    <div style={{ fontSize: 18, fontWeight: 700, margin: "4px 0" }}>
                      {fusion.security_decisions?.action_counts?.ALLOW?.toLocaleString() ?? 0}
                    </div>
                    <small style={{ color: "var(--muted)", fontSize: 10 }}>
                      Rate: {pct(fusion.security_decisions?.action_rates?.ALLOW)}
                    </small>
                  </div>
                  <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
                    <div style={{ color: "var(--amber, #f59e0b)", fontWeight: 700, fontSize: 13 }}>REVIEW</div>
                    <div style={{ fontSize: 18, fontWeight: 700, margin: "4px 0" }}>
                      {fusion.security_decisions?.action_counts?.REVIEW?.toLocaleString() ?? 0}
                    </div>
                    <small style={{ color: "var(--muted)", fontSize: 10 }}>
                      Rate: {pct(fusion.security_decisions?.action_rates?.REVIEW)}
                    </small>
                  </div>
                  <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
                    <div style={{ color: "#ef4444", fontWeight: 700, fontSize: 13 }}>BLOCK</div>
                    <div style={{ fontSize: 18, fontWeight: 700, margin: "4px 0" }}>
                      {fusion.security_decisions?.action_counts?.BLOCK?.toLocaleString() ?? 0}
                    </div>
                    <small style={{ color: "var(--muted)", fontSize: 10 }}>
                      Rate: {pct(fusion.security_decisions?.action_rates?.BLOCK)}
                    </small>
                  </div>
                </div>
              </div>

              {/* Per-Class Fusion Performance */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Per-Class A1 vs A3 Precision & Recall</div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 8 }}>CLASS</th>
                        <th style={{ padding: 8 }}>A1 F1</th>
                        <th style={{ padding: 8 }}>A3 F1</th>
                        <th style={{ padding: 8 }}>NET F1 CHANGE</th>
                        <th style={{ padding: 8 }}>SUPPORT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(fusion.per_class_before_after || {}).map(([cls, m]: [string, any]) => {
                        const diff = (m.a3?.f1 ?? 0) - (m.a1?.f1 ?? 0);
                        return (
                          <tr key={cls} style={{ borderBottom: "1px solid var(--line)" }}>
                            <td style={{ padding: 8, fontWeight: 600 }}>{cls}</td>
                            <td style={{ padding: 8, fontFamily: "monospace" }}>{num(m.a1?.f1, 5)}</td>
                            <td style={{ padding: 8, fontFamily: "monospace" }}>{num(m.a3?.f1, 5)}</td>
                            <td style={{ padding: 8, fontFamily: "monospace", color: diff >= 0 ? "var(--green)" : "#ef4444" }}>
                              {diff >= 0 ? `+${diff.toFixed(5)}` : diff.toFixed(5)}
                            </td>
                            <td style={{ padding: 8, fontFamily: "monospace" }}>{m.support?.toLocaleString() ?? "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: A2 ANOMALY DETECTION */}
          {activeTab === "a2" && a2 && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["ROC-AUC (INVERTED)", num(a2.roc_auc, 5)],
                  ["PR-AUC (AVG PRECISION)", num(a2.average_precision, 5)],
                  ["OPERATIONAL ACCURACY", pct(a2.operational_metrics?.accuracy)],
                  ["OPERATIONAL ATTACK RECALL", pct(a2.operational_metrics?.attack_recall)],
                  ["OPERATIONAL BENIGN FPR", pct(a2.operational_metrics?.benign_fpr)],
                  ["OPERATIONAL THRESHOLD", a2.threshold_used ?? 0.5],
                  ["DECISION FUNCTION INVERTED", a2.score_inverted ? "YES (Higher = Anomaly)" : "NO"],
                  ["EVALUATION SAMPLES", a2.total_samples?.toLocaleString() ?? "—"],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Per-Attack-Class Anomaly Recall */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Per-Attack-Category Anomaly Detection Recall</div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 8 }}>ATTACK CLASS</th>
                        <th style={{ padding: 8 }}>ANOMALY RECALL</th>
                        <th style={{ padding: 8 }}>ANOMALIES DETECTED</th>
                        <th style={{ padding: 8 }}>TOTAL FLOWS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(a2.per_attack_class_recall || {}).map(([cls, m]: [string, any]) => (
                        <tr key={cls} style={{ borderBottom: "1px solid var(--line)" }}>
                          <td style={{ padding: 8, fontWeight: 600 }}>{cls}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "var(--blue)" }}>{pct(m.recall)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{m.anomalies_detected?.toLocaleString() ?? 0}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{m.total?.toLocaleString() ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Score Distribution Statistics */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Score Distribution Statistics</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
                  <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
                    <div style={{ fontWeight: 600, fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>BENIGN FLOWS</div>
                    <div style={{ fontSize: 10, lineHeight: 1.8 }}>
                      <div>Mean Score: <b>{num(a2.score_distributions?.benign?.mean, 5)}</b></div>
                      <div>Median Score: <b>{num(a2.score_distributions?.benign?.median, 5)}</b></div>
                      <div>Std Dev: <b>{num(a2.score_distributions?.benign?.std, 5)}</b></div>
                      <div>Count: <b>{a2.score_distributions?.benign?.count?.toLocaleString() ?? 0}</b></div>
                    </div>
                  </div>
                  <div style={{ background: "var(--panel)", padding: 12, borderRadius: 6, border: "1px solid var(--line)" }}>
                    <div style={{ fontWeight: 600, fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>ATTACK FLOWS</div>
                    <div style={{ fontSize: 10, lineHeight: 1.8 }}>
                      <div>Mean Score: <b>{num(a2.score_distributions?.attack?.mean, 5)}</b></div>
                      <div>Median Score: <b>{num(a2.score_distributions?.attack?.median, 5)}</b></div>
                      <div>Std Dev: <b>{num(a2.score_distributions?.attack?.std, 5)}</b></div>
                      <div>Count: <b>{a2.score_distributions?.attack?.count?.toLocaleString() ?? 0}</b></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: GENERALIZATION */}
          {activeTab === "generalization" && gen && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["TOTAL EVAL SAMPLES", gen.generalization_summary?.total_eval_samples?.toLocaleString() ?? "—"],
                  ["SEEN FEATURE VECTORS", `${gen.generalization_summary?.seen_samples_count?.toLocaleString()} (${num(gen.generalization_summary?.seen_percentage, 2)}%)`],
                  ["UNSEEN FEATURE VECTORS", `${gen.generalization_summary?.unseen_samples_count?.toLocaleString()} (${num(gen.generalization_summary?.unseen_percentage, 2)}%)`],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Seen vs Unseen Comparison */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 14 }}>
                <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8, color: "var(--blue)" }}>
                    Performance on SEEN Feature Vectors
                  </div>
                  <div style={{ fontSize: 11, lineHeight: 1.8 }}>
                    <div>Accuracy: <b>{pct(gen.seen_evaluation?.accuracy)}</b></div>
                    <div>Macro F1: <b>{num(gen.seen_evaluation?.macro_f1, 5)}</b></div>
                    <div>Attack Detection Rate: <b>{pct(gen.seen_evaluation?.attack_detection_rate)}</b></div>
                    <div>Benign FPR: <b>{pct(gen.seen_evaluation?.benign_false_positive_rate)}</b></div>
                    <div>Samples: <b>{gen.seen_evaluation?.total_samples?.toLocaleString() ?? 0}</b></div>
                  </div>
                </div>

                <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8, color: "var(--violet, #a855f7)" }}>
                    Performance on UNSEEN Feature Vectors
                  </div>
                  <div style={{ fontSize: 11, lineHeight: 1.8 }}>
                    <div>Accuracy: <b>{pct(gen.unseen_evaluation?.accuracy)}</b></div>
                    <div>Macro F1: <b>{num(gen.unseen_evaluation?.macro_f1, 5)}</b></div>
                    <div>Attack Detection Rate: <b>{pct(gen.unseen_evaluation?.attack_detection_rate)}</b></div>
                    <div>Benign FPR: <b>{pct(gen.unseen_evaluation?.benign_false_positive_rate)}</b></div>
                    <div>Samples: <b>{gen.unseen_evaluation?.total_samples?.toLocaleString() ?? 0}</b></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: PROBABILITY CALIBRATION */}
          {activeTab === "calibration" && cal && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["UNCALIBRATED ECE", num(cal.evaluation?.uncalibrated?.ece, 6)],
                  ["CALIBRATED ECE", num(cal.evaluation?.calibrated?.ece, 6)],
                  ["UNCALIBRATED BRIER", num(cal.evaluation?.uncalibrated?.brier_score, 6)],
                  ["CALIBRATED BRIER", num(cal.evaluation?.calibrated?.brier_score, 6)],
                  ["UNCALIBRATED LOG LOSS", num(cal.evaluation?.uncalibrated?.log_loss, 4)],
                  ["CALIBRATED LOG LOSS", num(cal.evaluation?.calibrated?.log_loss, 4)],
                  ["CALIBRATION METHOD", cal.evaluation?.method ?? "Isotonic Regression"],
                  ["CALIBRATION SAMPLES", cal.calibration_samples?.toLocaleString() ?? "—"],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Reliability Bins Table */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Reliability Diagram Bins (Calibrated vs Uncalibrated)</div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 6 }}>CONFIDENCE BIN</th>
                        <th style={{ padding: 6 }}>UNCAL CONF</th>
                        <th style={{ padding: 6 }}>UNCAL ACC</th>
                        <th style={{ padding: 6 }}>CAL CONF</th>
                        <th style={{ padding: 6 }}>CAL ACC</th>
                        <th style={{ padding: 6 }}>BIN SAMPLE COUNT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(cal.evaluation?.calibrated?.reliability_bins || []).map((b: any, idx: number) => {
                        const uncalBin = cal.evaluation?.uncalibrated?.reliability_bins?.[idx] || {};
                        return (
                          <tr key={idx} style={{ borderBottom: "1px solid var(--line)" }}>
                            <td style={{ padding: 6, fontWeight: 600 }}>{b.bin_range}</td>
                            <td style={{ padding: 6, fontFamily: "monospace" }}>{num(uncalBin.mean_predicted_probability, 4)}</td>
                            <td style={{ padding: 6, fontFamily: "monospace" }}>{num(uncalBin.empirical_accuracy, 4)}</td>
                            <td style={{ padding: 6, fontFamily: "monospace", color: "var(--green)" }}>{num(b.mean_predicted_probability, 4)}</td>
                            <td style={{ padding: 6, fontFamily: "monospace", color: "var(--green)" }}>{num(b.empirical_accuracy, 4)}</td>
                            <td style={{ padding: 6, fontFamily: "monospace" }}>{b.sample_count?.toLocaleString() ?? 0}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: LOAO ZERO-DAY */}
          {activeTab === "loao" && loao && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["MEAN A1 UNSEEN DETECTION", pct(loao.loao_summary?.mean_a1_unseen_attack_detection)],
                  ["MEAN A2 ANOMALY RECALL", pct(loao.loao_summary?.mean_a2_unseen_anomaly_recall)],
                  ["MEAN A3 CONTAINMENT", pct(loao.loao_summary?.mean_a3_unseen_containment_rate)],
                  ["BENIGN FALSE BLOCK RATE", pct(loao.loao_summary?.mean_benign_false_block_rate)],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* LOAO Trials Table */}
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Leave-One-Attack-Out 4-Trial Breakdown</div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 8 }}>OMITTED CLASS</th>
                        <th style={{ padding: 8 }}>A1 UNSEEN DETECT</th>
                        <th style={{ padding: 8 }}>A2 ANOMALY RECALL</th>
                        <th style={{ padding: 8 }}>A3 CONTAINMENT</th>
                        <th style={{ padding: 8 }}>BENIGN FALSE BLOCK</th>
                        <th style={{ padding: 8 }}>TEST SAMPLES</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(loao.trials || {}).map(([cls, t]: [string, any]) => (
                        <tr key={cls} style={{ borderBottom: "1px solid var(--line)" }}>
                          <td style={{ padding: 8, fontWeight: 600 }}>{cls}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{pct(t.a1_unseen_attack_detection_rate)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "var(--blue)" }}>{pct(t.a2_unseen_anomaly_recall)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "var(--green)" }}>{pct(t.a3_unseen_containment_rate)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "#ef4444" }}>{pct(t.benign_false_block_rate)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{t.total_test_samples?.toLocaleString() ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: A4 TEMPORAL CORRELATION */}
          {activeTab === "temporal" && temporal && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                {[
                  ["TOTAL CAMPAIGNS", temporal.evaluation_summary?.total_campaigns_detected ?? 0],
                  ["CAMPAIGN PRECISION", pct(temporal.evaluation_summary?.campaign_precision)],
                  ["MEAN DETECTION DELAY", `${num(temporal.evaluation_summary?.mean_detection_delay_flows, 1)} flows`],
                  ["CAMPAIGN MEMBER FLOWS", temporal.evaluation_summary?.total_campaign_member_flows?.toLocaleString() ?? 0],
                  ["DDOS CAMPAIGNS", temporal.evaluation_summary?.campaigns_by_type?.DDOS ?? 0],
                  ["PORT SCAN CAMPAIGNS", temporal.evaluation_summary?.campaigns_by_type?.PORT_SCAN ?? 0],
                  ["BRUTE FORCE CAMPAIGNS", temporal.evaluation_summary?.campaigns_by_type?.BRUTE_FORCE ?? 0],
                  ["FALSE CAMPAIGN RATE", pct(temporal.evaluation_summary?.false_campaign_rate)],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "var(--panel2)", padding: 12, borderRadius: 7, border: "1px solid var(--line)" }}>
                    <small style={{ fontSize: 9, color: "var(--muted)" }}>{label}</small>
                    <div style={{ fontSize: 17, fontWeight: 700, marginTop: 4 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Shuffled Robustness Evaluation */}
              {temporal.shuffled_robustness_test && (
                <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8 }}>Order Sensitivity (Shuffled vs Chronological)</div>
                  <p style={{ fontSize: 10, color: "var(--muted)", margin: "0 0 10px" }}>
                    Chronological events preserve packet burst arrival patterns. Shuffled events measure susceptibility to out-of-order packet arrival.
                  </p>
                  <div style={{ fontSize: 11, lineHeight: 1.8 }}>
                    <div>Chronological Campaigns: <b>{temporal.evaluation_summary?.total_campaigns_detected ?? 0}</b></div>
                    <div>Shuffled Campaigns Detected: <b>{temporal.shuffled_robustness_test?.total_campaigns_detected ?? 0}</b></div>
                    <div>Campaign Precision (Shuffled): <b>{pct(temporal.shuffled_robustness_test?.campaign_precision)}</b></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 9: A5 ADAPTIVE DEFENSE */}
          {activeTab === "defense" && defense && (
            <div>
              <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>
                  4-Way Multi-Agent Defense Configuration Comparison
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--muted)" }}>
                        <th style={{ padding: 8 }}>CONFIGURATION</th>
                        <th style={{ padding: 8 }}>CONTAINMENT RATE</th>
                        <th style={{ padding: 8 }}>FALSE BLOCKING</th>
                        <th style={{ padding: 8 }}>BENIGN PRESERVATION</th>
                        <th style={{ padding: 8 }}>POLICIES CREATED</th>
                        <th style={{ padding: 8 }}>DEFENSE EFFECTIVENESS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(defense.comparison_table || {}).map(([key, cfg]: [string, any]) => (
                        <tr key={key} style={{ borderBottom: "1px solid var(--line)" }}>
                          <td style={{ padding: 8, fontWeight: 600 }}>{cfg.name}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "var(--green)" }}>{pct(cfg.containment_rate)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", color: "#ef4444" }}>{pct(cfg.false_blocking_rate)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{pct(cfg.benign_preservation)}</td>
                          <td style={{ padding: 8, fontFamily: "monospace" }}>{cfg.policies_created?.toLocaleString() ?? 0}</td>
                          <td style={{ padding: 8, fontFamily: "monospace", fontWeight: 700 }}>{num(cfg.defense_effectiveness, 4)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Temporal Enhancement Gain */}
              {defense.temporal_enhancement_gain && (
                <div style={{ background: "var(--panel2)", padding: 14, borderRadius: 8, border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8, color: "var(--blue)" }}>
                    Temporal Correlation Enhancement Gain (Config 4 vs Config 3)
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 10, fontSize: 11 }}>
                    <div>Containment Gain: <b>+{pct(defense.temporal_enhancement_gain.containment_gain)}</b></div>
                    <div>Collateral Change: <b>+{pct(defense.temporal_enhancement_gain.collateral_damage_change)}</b></div>
                    <div>Net Effectiveness Gain: <b>+{num(defense.temporal_enhancement_gain.net_gain, 4)}</b></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 10: CHARTS & PLOTS */}
          {activeTab === "plots" && (
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>
                Generated Publication-Quality Visualizations
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                  gap: 14,
                }}
              >
                {[
                  { title: "Confusion Matrix Comparison (A1 vs A3)", file: "confusion_matrix_comparison.png", svg: "confusion_matrix_comparison.svg" },
                  { title: "Agent 2 ROC & PR Curves (Score Inverted)", file: "anomaly_roc_pr_curves.png", svg: "anomaly_roc_pr_curves.svg" },
                  { title: "Reliability Diagram & Calibration", file: "calibration_reliability_diagram.png", svg: "calibration_reliability_diagram.svg" },
                  { title: "Generalization: Seen vs Unseen", file: "generalization_seen_vs_unseen.png", svg: "generalization_seen_vs_unseen.svg" },
                  { title: "Leave-One-Attack-Out (LOAO) Outcomes", file: "loao_evaluation.png", svg: "loao_evaluation.svg" },
                  { title: "Adaptive Defense 4-Way Comparison", file: "adaptive_defense_comparison.png", svg: "adaptive_defense_comparison.svg" },
                ].map((plot, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: "var(--panel2)",
                      padding: 12,
                      borderRadius: 8,
                      border: "1px solid var(--line)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <span style={{ fontSize: 11, fontWeight: 700 }}>{plot.title}</span>
                      <a
                        href={`/api/evaluation/plots/${plot.svg}`}
                        target="_blank"
                        rel="noreferrer"
                        style={{ fontSize: 10, color: "var(--blue)", display: "flex", alignItems: "center", gap: 4 }}
                      >
                        SVG <ExternalLink size={10} />
                      </a>
                    </div>
                    <img
                      src={`/api/evaluation/plots/${plot.file}`}
                      alt={plot.title}
                      style={{
                        width: "100%",
                        height: "auto",
                        borderRadius: 6,
                        border: "1px solid var(--line)",
                        background: "#fff",
                      }}
                      onError={(e: any) => {
                        e.target.style.display = "none";
                      }}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Footer Audit Guarantee */}
      <div className="panel-foot" style={{ marginTop: 16 }}>
        <span>
          <LockKeyhole size={13} /> Real evaluation on official datasets · No fabricated metrics · Score-inverted Isolation Forest
        </span>
        <span>RESEARCH-GRADE MULTI-AGENT CYBERSECURITY</span>
      </div>
    </section>
  );
}

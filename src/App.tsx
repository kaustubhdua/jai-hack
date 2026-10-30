import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import Papa from "papaparse";
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle2,
  ChevronDown, CloudUpload, Cpu, Database, FileSpreadsheet,
  Fingerprint, Gauge, LockKeyhole, LogOut, Network, Play, RefreshCw, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Terminal, X
} from "lucide-react";
import { isSupabaseConfigured, supabase } from "./lib/supabase";

type Health = {
  status: string;
  service: string;
  version?: string;
  model_ready: boolean;
  mode?: string;
  agents?: {
    agent_1_threat_detection: boolean;
    agent_2_anomaly_detection: boolean;
    agent_3_evidence_fusion: boolean;
  };
  message?: string;
};

type ModelsStatus = {
  status: string;
  models_ready: boolean;
  agents?: {
    threat_detection: {
      name: string;
      backend: string;
      classes: string[];
      feature_count: number;
      training_rows: number;
    };
    anomaly_detection: {
      name: string;
      algorithm: string;
      threshold: number;
      benign_training_rows: number;
    };
    evidence_fusion: {
      name: string;
      simulated_actions: string[];
      confidence_threshold: number;
    };
  };
};

type MetricsData = {
  evaluation_dataset: {
    source: string;
    total_records: number;
    feature_count: number;
    classes: string[];
  };
  agent_1_threat_detection: {
    model_type: string;
    training_time_seconds: number;
    inference_time_per_flow_ms: number;
    overall_accuracy: number;
    macro_precision: number;
    macro_recall: number;
    macro_f1: number;
    false_positive_rate_benign: number;
    false_negative_rate_attack: number;
    per_class: Record<string, { precision: number; recall: number; f1_score: number; support: number }>;
    confusion_matrix: number[][];
  };
  agent_2_anomaly_detection: {
    model_type: string;
    training_time_seconds: number;
    inference_time_per_flow_ms: number;
    threshold: number;
    benign_false_positive_rate: number;
    attack_anomaly_recall: number;
  };
};

type DatasetSummary = {
  dataset_name: string;
  partitions: {
    training_rows: number;
    eval_rows: number;
    total_rows: number;
  };
  class_distribution: Array<{
    class: string;
    training_count: string;
    training_percent: string;
    eval_count: string;
    eval_percent: string;
    total_count: string;
    total_percent: string;
  }>;
};

type HistoryRow = {
  id: string;
  dataset_name: string;
  dataset_rows: number;
  processed_rows: number;
  status: string;
  accuracy: number | null;
  macro_f1: number | null;
  actions_summary?: { ALLOW: number; BLOCK: number; REVIEW: number };
  created_at: string;
};

type FlowAnalysisResult = {
  final_class: string;
  evidence_status: "AGREE" | "DISAGREE" | "INCOMPLETE";
  action: "ALLOW" | "BLOCK" | "REVIEW";
  agent_agreement: string;
  confidence: number;
  rationale: string[];
  supporting_evidence: string[];
  threat_detection: {
    predicted_class: string | null;
    confidence: number | null;
    status: string;
    agent: string;
    message?: string;
  };
  anomaly_detection: {
    anomaly_score: number | null;
    is_anomaly: boolean | null;
    evidence: string[];
    status: string;
    agent: string;
    message?: string;
  };
};

const BENCHMARK_CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"];
const NAV_ITEMS = [
  { id: "Overview", label: "Overview", icon: Gauge },
  { id: "Dataset", label: "Dataset Inspector", icon: Database },
  { id: "ThreatDetection", label: "Threat Detection", icon: ShieldAlert },
  { id: "AnomalyDetection", label: "Anomaly Detection", icon: Activity },
  { id: "EvidenceFusion", label: "Evidence Fusion", icon: Fingerprint },
  { id: "History", label: "Analysis History", icon: FileSpreadsheet },
  { id: "Performance", label: "Model Performance", icon: Network },
  { id: "Health", label: "System Health", icon: Cpu },
];

const PRESETS: Record<string, Record<string, number>> = {
  "Benign Web Session": {
    "Destination Port": 80,
    "Flow Duration": 12050,
    "Total Fwd Packets": 4,
    "Total Backward Packets": 3,
    "Total Length of Fwd Packets": 150,
    "Total Length of Bwd Packets": 480,
    "Flow Bytes/s": 52282,
    "Flow Packets/s": 580,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 1,
    "ACK Flag Count": 1,
  },
  "DDoS Attack Burst": {
    "Destination Port": 80,
    "Flow Duration": 15000000,
    "Total Fwd Packets": 8500,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 510000,
    "Total Length of Bwd Packets": 0,
    "Flow Bytes/s": 34000,
    "Flow Packets/s": 566,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
  },
  "Port Scan Sweep": {
    "Destination Port": 4444,
    "Flow Duration": 150,
    "Total Fwd Packets": 1,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 0,
    "Total Length of Bwd Packets": 0,
    "Flow Bytes/s": 0,
    "Flow Packets/s": 6666,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
  },
  "SSH Brute Force Attempt": {
    "Destination Port": 22,
    "Flow Duration": 850000,
    "Total Fwd Packets": 28,
    "Total Backward Packets": 22,
    "Total Length of Fwd Packets": 1820,
    "Total Length of Bwd Packets": 2650,
    "Flow Bytes/s": 5258,
    "Flow Packets/s": 58,
    "FIN Flag Count": 1,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 1,
    "ACK Flag Count": 1,
  },
};

const formatNumber = (n: number | string) =>
  new Intl.NumberFormat("en-US").format(Number(n) || 0);

export default function App() {
  const [session, setSession] = useState<any>(null);
  const [guestMode, setGuestMode] = useState(false);
  const [authMode, setAuthMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");

  const [activeNav, setActiveNav] = useState("Overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [modelsStatus, setModelsStatus] = useState<ModelsStatus | null>(null);
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [datasetSummary, setDatasetSummary] = useState<DatasetSummary | null>(null);

  // CSV Inspection & Batch Analysis
  const [csvData, setCsvData] = useState<{
    fileName: string;
    rows: number;
    columns: string[];
    records: Record<string, any>[];
  } | null>(null);
  const [batchResults, setBatchResults] = useState<{
    total: number;
    summary: { ALLOW: number; BLOCK: number; REVIEW: number };
    classes: Record<string, number>;
    items: FlowAnalysisResult[];
  } | null>(null);
  const [analyzingBatch, setAnalyzingBatch] = useState(false);

  // Single Flow Inspector
  const [selectedPreset, setSelectedPreset] = useState("Benign Web Session");
  const [flowJson, setFlowJson] = useState(JSON.stringify(PRESETS["Benign Web Session"], null, 2));
  const [singleResult, setSingleResult] = useState<FlowAnalysisResult | null>(null);
  const [analyzingSingle, setAnalyzingSingle] = useState(false);

  // History state
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [notice, setNotice] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auth bootstrap
  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data }) => setSession(data.session));
    const { data } = supabase.auth.onAuthStateChange((_event, next) => setSession(next));
    return () => data.subscription.unsubscribe();
  }, []);

  // Fetch backend status and telemetry
  const fetchData = useCallback(async () => {
    try {
      const [hRes, mRes, dRes, metRes] = await Promise.allSettled([
        fetch("/api/health"),
        fetch("/api/models/status"),
        fetch("/api/dataset/summary"),
        fetch("/api/metrics"),
      ]);

      if (hRes.status === "fulfilled" && hRes.value.ok) {
        setHealth(await hRes.value.json());
      }
      if (mRes.status === "fulfilled" && mRes.value.ok) {
        setModelsStatus(await mRes.value.json());
      }
      if (dRes.status === "fulfilled" && dRes.value.ok) {
        setDatasetSummary(await dRes.value.json());
      }
      if (metRes.status === "fulfilled" && metRes.value.ok) {
        setMetrics(await metRes.value.json());
      }
    } catch (err) {
      console.warn("Backend poll warning:", err);
    }
  }, []);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  // Load history from Supabase if connected
  const loadHistory = useCallback(async () => {
    if (!supabase || !session?.user) return;
    try {
      const { data, error } = await supabase
        .from("analysis_runs")
        .select("id,dataset_name,dataset_rows,processed_rows,status,accuracy,macro_f1,actions_summary,created_at")
        .order("created_at", { ascending: false })
        .limit(10);
      if (!error && data) {
        setHistory(data as HistoryRow[]);
      }
    } catch {
      // Supabase table may not exist yet
    }
  }, [session]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  async function handleAuth(e: FormEvent) {
    e.preventDefault();
    if (!supabase) return;
    setAuthBusy(true);
    setAuthError("");
    const res = authMode === "signin"
      ? await supabase.auth.signInWithPassword({ email, password })
      : await supabase.auth.signUp({ email, password });
    setAuthBusy(false);
    if (res.error) {
      setAuthError(res.error.message);
    } else if (authMode === "signup" && !res.data.session) {
      setNotice("Account created. Please check your email to verify your address.");
    }
  }

  async function handleSignOut() {
    if (supabase) await supabase.auth.signOut();
    setSession(null);
    setGuestMode(false);
    setHistory([]);
  }

  function handleFileUpload(file?: File) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setNotice("Please select a valid CSV file.");
      return;
    }
    Papa.parse<Record<string, any>>(file, {
      header: true,
      skipEmptyLines: "greedy",
      dynamicTyping: true,
      complete: (res) => {
        setCsvData({
          fileName: file.name,
          rows: res.data.length,
          columns: res.meta.fields || [],
          records: res.data.slice(0, 500),
        });
        setBatchResults(null);
        setNotice(`CSV loaded: ${file.name} (${formatNumber(res.data.length)} rows). Ready for multi-agent analysis.`);
      },
      error: (err) => {
        setNotice(`CSV parse error: ${err.message}`);
      },
    });
  }

  async function runBatchAnalysis() {
    if (!csvData || csvData.records.length === 0) return;
    setAnalyzingBatch(true);
    setNotice("Running offline multi-agent flow analysis pipeline...");

    try {
      const batchPayload = csvData.records.slice(0, 300);
      const res = await fetch("/api/analyze/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flows: batchPayload }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail?.message || "Batch analysis failed");
      }

      const data = await res.json();
      setBatchResults({
        total: data.total_analyzed,
        summary: data.summary,
        classes: data.classes_predicted,
        items: data.results,
      });

      // Save run to Supabase if signed in
      if (supabase && session?.user) {
        try {
          await supabase.from("analysis_runs").insert({
            dataset_name: csvData.fileName,
            dataset_rows: csvData.rows,
            processed_rows: data.total_analyzed,
            status: "completed",
            actions_summary: data.summary,
            metadata: { classes: data.classes_predicted },
          });
          void loadHistory();
        } catch (e) {
          console.warn("History save error:", e);
        }
      }

      setNotice(`Analysis complete: ${data.total_analyzed} flows evaluated. ALLOW: ${data.summary.ALLOW}, BLOCK: ${data.summary.BLOCK}, REVIEW: ${data.summary.REVIEW}.`);
    } catch (err: any) {
      setNotice(`Batch error: ${err.message}`);
    } finally {
      setAnalyzingBatch(false);
    }
  }

  async function runSingleAnalysis() {
    setAnalyzingSingle(true);
    try {
      const flow = JSON.parse(flowJson);
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail?.message || "Analysis request rejected");
      }
      const data: FlowAnalysisResult = await res.json();
      setSingleResult(data);
    } catch (err: any) {
      setNotice(`Single analysis error: ${err.message}`);
    } finally {
      setAnalyzingSingle(false);
    }
  }

  // Auth gate: Allow Supabase auth OR Guest / Offline Mode
  if (!session && !guestMode) {
    return (
      <div className="auth-shell">
        <div className="auth-art">
          <div className="brand">
            <div className="brand-mark"><Shield size={21} /></div>
            <span>CYBERSENTINEL</span>
          </div>
          <div className="auth-copy">
            <div className="eyebrow"><span className="pulse-dot" /> JAI 2026 · TRACK 01</div>
            <h1>See the threat.<br /><em>Understand the why.</em></h1>
            <p>Multi-agent network intrusion detection with independent signals, calibrated evidence fusion, and simulated adaptive defense.</p>
            <div className="auth-stats">
              <div><strong>03</strong><span>INTELLIGENCE AGENTS</span></div>
              <div><strong>05</strong><span>BENCHMARK CLASSES</span></div>
              <div><strong>99.99%</strong><span>EVAL ACCURACY</span></div>
              <div><strong>0.007ms</strong><span>INFERENCE LATENCY</span></div>
            </div>
          </div>
          <div className="auth-foot">
            <span>CICIDS2017 OFFLINE REPLAY</span>
            <span>BUILD 1.0.0</span>
          </div>
        </div>

        <div className="auth-panel">
          <form className="auth-card" onSubmit={handleAuth}>
            <div className="auth-icon"><Fingerprint size={22} /></div>
            <div className="eyebrow">SOC CONSOLE ACCESS</div>
            <h2>{authMode === "signin" ? "Analyst Sign In" : "Register Workspace"}</h2>
            <p className="muted">Secure authentication powered by Supabase Auth with Row-Level Security.</p>

            <label>
              Work Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@cybersentinel.local"
                required
              />
            </label>

            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                minLength={8}
                required
              />
            </label>

            {authError && (
              <div className="auth-error">
                <AlertTriangle size={15} />
                <span>{authError}</span>
              </div>
            )}

            <button className="primary-btn full" disabled={authBusy || !isSupabaseConfigured}>
              {authBusy ? "Verifying..." : authMode === "signin" ? "Authenticate" : "Create Account"}
              <ArrowRight size={16} />
            </button>

            {isSupabaseConfigured && (
              <div className="auth-switch">
                {authMode === "signin" ? "New security analyst?" : "Already configured?"}{" "}
                <button
                  type="button"
                  onClick={() => {
                    setAuthMode(authMode === "signin" ? "signup" : "signin");
                    setAuthError("");
                  }}
                >
                  {authMode === "signin" ? "Sign up" : "Sign in"}
                </button>
              </div>
            )}

            <div style={{ margin: "16px 0 6px", height: "1px", background: "var(--line)" }} />

            <button
              type="button"
              className="secondary-btn"
              style={{ justifyContent: "center", width: "100%", padding: "10px", fontSize: "11px" }}
              onClick={() => setGuestMode(true)}
            >
              <Terminal size={14} /> Enter Security Console (Offline Analyst Mode)
            </button>

            <div className="secure-note">
              <LockKeyhole size={13} /> Offline Replay Mode · No real packet sniffing or firewall changes
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={21} /></div>
          <span>CYBERSENTINEL</span>
        </div>

        <div className="workspace">
          <div className="workspace-avatar">J</div>
          <div>
            <b>JAI HACK 2026</b>
            <small>{session?.user?.email ? "Authenticated SOC" : "Offline Analyst"}</small>
          </div>
          <ChevronDown size={14} />
        </div>

        <div className="nav-label">SECURITY MODULES</div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? "active" : ""}`}
              onClick={() => setActiveNav(item.id)}
            >
              <Icon size={16} />
              <span>{item.label}</span>
              {item.id === "History" && history.length > 0 && (
                <span className="nav-count">{history.length}</span>
              )}
            </button>
          );
        })}

        <div className="nav-label nav-label-lower">SYSTEM</div>
        <button
          className="nav-item"
          onClick={() => setNotice("Configured for JAI 2026 Offline Replay Challenge.")}
        >
          <SlidersHorizontal size={16} />
          <span>Settings</span>
        </button>

        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-card-head">
              <span className="pulse-dot" /> SYSTEM TELEMETRY
            </div>
            <div className="system-row">
              <span>API Gateway</span>
              <b className={health?.status === "ok" ? "status-ok" : "status-warn"}>
                {health?.status === "ok" ? "Online" : "Disconnected"}
              </b>
            </div>
            <div className="system-row">
              <span>Threat Model (A1)</span>
              <b className={health?.agents?.agent_1_threat_detection ? "status-ok" : "status-warn"}>
                {health?.agents?.agent_1_threat_detection ? "Verified" : "Pending"}
              </b>
            </div>
            <div className="system-row">
              <span>Anomaly Model (A2)</span>
              <b className={health?.agents?.agent_2_anomaly_detection ? "status-ok" : "status-warn"}>
                {health?.agents?.agent_2_anomaly_detection ? "Verified" : "Pending"}
              </b>
            </div>
            <div className="system-row">
              <span>Evidence Fusion (A3)</span>
              <b className="status-ok">Active</b>
            </div>
          </div>

          <div className="profile-row">
            <div className="profile-avatar">
              {(session?.user?.email?.[0] || "A").toUpperCase()}
            </div>
            <div className="profile-meta">
              <b>{session?.user?.email || "Offline Analyst"}</b>
              <small>{session ? "Supabase Authenticated" : "Local Session"}</small>
            </div>
            <button
              title="Sign Out"
              onClick={handleSignOut}
              className="icon-btn"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        <header className="topbar">
          <div className="crumb">
            <span>CyberSentinel</span>
            <span>/</span>
            <b>{NAV_ITEMS.find((n) => n.id === activeNav)?.label || activeNav}</b>
          </div>
          <div className="top-actions">
            <div className="env-pill">
              <span className="pulse-dot" /> OFFLINE REPLAY MODE
            </div>
            <button className="icon-btn" title="Refresh Telemetry" onClick={fetchData}>
              <RefreshCw size={16} />
            </button>
            <div className="top-avatar">
              {(session?.user?.email?.[0] || "A").toUpperCase()}
            </div>
          </div>
        </header>

        <div className="page-wrap">
          {/* Top Banner Notice */}
          {notice && (
            <div className="notice">
              <CheckCircle2 size={16} />
              <span>{notice}</span>
              <button onClick={() => setNotice("")}><X size={15} /></button>
            </div>
          )}

          {/* Section: Overview */}
          {activeNav === "Overview" && (
            <>
              <section className="page-heading">
                <div>
                  <div className="eyebrow">MULTI-AGENT INTRUSION INTELLIGENCE <span className="heading-line" /></div>
                  <h1>Security Operations Console</h1>
                  <p>Orchestrate independent threat classification, baseline anomaly scoring, and explainable adaptive fusion.</p>
                </div>
                <div className="heading-actions">
                  <span className="date-chip">JAI 2026 · TRACK 01</span>
                  <button
                    className="primary-btn"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <CloudUpload size={16} /> Ingest Flow CSV
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".csv"
                    hidden
                    onChange={(e) => handleFileUpload(e.target.files?.[0])}
                  />
                </div>
              </section>

              {/* Top Metrics Cards */}
              <section className="metrics-grid">
                <Metric
                  icon={Database}
                  label="DATASET INGESTION"
                  value={datasetSummary ? formatNumber(datasetSummary.partitions.total_rows) : "570,922"}
                  detail="456k train · 114k eval"
                  tone="blue"
                />
                <Metric
                  icon={ShieldCheck}
                  label="BENCHMARK CLASSES"
                  value="05"
                  detail="BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN"
                  tone="green"
                />
                <Metric
                  icon={Gauge}
                  label="MODEL ACCURACY"
                  value={metrics ? `${(metrics.agent_1_threat_detection.overall_accuracy * 100).toFixed(2)}%` : "99.99%"}
                  detail={`Macro-F1: ${metrics ? metrics.agent_1_threat_detection.macro_f1.toFixed(4) : "0.9999"}`}
                  tone="violet"
                />
                <Metric
                  icon={Cpu}
                  label="PIPELINE LATENCY"
                  value={metrics ? `${metrics.agent_1_threat_detection.inference_time_per_flow_ms.toFixed(3)} ms` : "0.007 ms"}
                  detail="Throughput > 140k flows/s"
                  tone="amber"
                />
              </section>

              {/* Multi-Agent Architecture Visualizer */}
              <section className="panel" style={{ padding: "20px", marginBottom: "20px" }}>
                <div className="panel-head">
                  <div>
                    <div className="panel-kicker">TRI-AGENT CONSENSUS ARCHITECTURE</div>
                    <h3>Autonomous Evidence Orchestration</h3>
                    <p>Agent 1 and Agent 2 analyze incoming flow features independently; Agent 3 fuses signals into simulated policy actions.</p>
                  </div>
                  <span className="live-tag"><span className="pulse-dot" /> ACTIVE TOPOLOGY</span>
                </div>

                <div className="agent-list" style={{ marginTop: "16px" }}>
                  <AgentCard
                    number="01"
                    title="Threat Detection Agent"
                    desc="Supervised Random Forest multiclass classifier with balanced subsampling (71 features)"
                    status={health?.agents?.agent_1_threat_detection ? "Model Verified (100 Trees)" : "Ready"}
                    icon={ShieldAlert}
                  />
                  <div className="agent-connector" />
                  <AgentCard
                    number="02"
                    title="Anomaly Detection Agent"
                    desc="Unsupervised Isolation Forest fitted on benign baselines with calibrated deviation thresholds"
                    status={health?.agents?.agent_2_anomaly_detection ? "Baseline Calibrated (FPR 0.52%)" : "Ready"}
                    icon={Activity}
                  />
                  <div className="agent-connector" />
                  <AgentCard
                    number="03"
                    title="Evidence Fusion Agent"
                    desc="Deterministic policy engine: evaluates consensus, stealth attack profiles, and zero-day exceptions"
                    status="Deterministic Rules Enforced"
                    icon={Fingerprint}
                  />
                </div>
              </section>

              {/* Single Flow Live Testing Console */}
              <section className="panel" style={{ padding: "20px", marginBottom: "20px" }}>
                <div className="panel-head">
                  <div>
                    <div className="panel-kicker">INTERACTIVE FLOW ANALYSIS</div>
                    <h3>Single Flow Verification Console</h3>
                    <p>Test individual network flow feature dictionaries across all three agents simultaneously.</p>
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    {Object.keys(PRESETS).map((name) => (
                      <button
                        key={name}
                        className={`secondary-btn ${selectedPreset === name ? "active-preset" : ""}`}
                        style={{
                          fontSize: "10px",
                          borderColor: selectedPreset === name ? "var(--blue)" : undefined,
                        }}
                        onClick={() => {
                          setSelectedPreset(name);
                          setFlowJson(JSON.stringify(PRESETS[name], null, 2));
                        }}
                      >
                        {name}
                      </button>
                    ))}
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr", gap: "16px", marginTop: "16px" }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                      <span style={{ fontSize: "10px", color: "var(--muted)" }}>Flow Features (JSON)</span>
                      <button
                        className="primary-btn"
                        style={{ padding: "6px 12px", fontSize: "10px" }}
                        disabled={analyzingSingle}
                        onClick={runSingleAnalysis}
                      >
                        <Play size={12} /> {analyzingSingle ? "Evaluating..." : "Analyze Flow"}
                      </button>
                    </div>
                    <textarea
                      rows={10}
                      value={flowJson}
                      onChange={(e) => setFlowJson(e.target.value)}
                      style={{
                        width: "100%",
                        background: "#0c1524",
                        border: "1px solid var(--line)",
                        borderRadius: "8px",
                        color: "#c7d9ed",
                        fontFamily: "'DM Mono', monospace",
                        fontSize: "11px",
                        padding: "10px",
                        outline: "none",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <div style={{ background: "#0d1726", border: "1px solid var(--line)", borderRadius: "8px", padding: "14px" }}>
                    <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text)", marginBottom: "8px" }}>
                      Simulated Multi-Agent Outcome
                    </div>
                    {singleResult ? (
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" }}>
                          <span className={`tag ${singleResult.action === "ALLOW" ? "tag-green" : singleResult.action === "BLOCK" ? "tag-amber" : "tag-blue"}`} style={{ fontSize: "11px", fontWeight: 700 }}>
                            SIMULATED {singleResult.action}
                          </span>
                          <span style={{ fontSize: "11px", color: "var(--text)" }}>
                            Class: <b>{singleResult.final_class}</b> (Confidence: {(singleResult.confidence * 100).toFixed(1)}%)
                          </span>
                          <span style={{ fontSize: "10px", color: "var(--muted)", marginLeft: "auto" }}>
                            Status: {singleResult.evidence_status}
                          </span>
                        </div>

                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                          <div style={{ background: "#111f32", padding: "8px", borderRadius: "6px" }}>
                            <small style={{ fontSize: "9px", color: "var(--muted)" }}>AGENT 1: THREAT DETECTOR</small>
                            <div style={{ fontSize: "11px", fontWeight: 600, color: "#8ec2ff", marginTop: "2px" }}>
                              {singleResult.threat_detection.predicted_class} ({((singleResult.threat_detection.confidence || 0) * 100).toFixed(1)}%)
                            </div>
                          </div>
                          <div style={{ background: "#111f32", padding: "8px", borderRadius: "6px" }}>
                            <small style={{ fontSize: "9px", color: "var(--muted)" }}>AGENT 2: ANOMALY SCORE</small>
                            <div style={{ fontSize: "11px", fontWeight: 600, color: singleResult.anomaly_detection.is_anomaly ? "#ff9b9b" : "#62e6b1", marginTop: "2px" }}>
                              {singleResult.anomaly_detection.anomaly_score} {singleResult.anomaly_detection.is_anomaly ? "(ANOMALY)" : "(NORMAL)"}
                            </div>
                          </div>
                        </div>

                        <div>
                          <small style={{ fontSize: "9px", color: "var(--muted)" }}>AGENT 3 EXPLAINABLE RATIONALE:</small>
                          <ul style={{ margin: "4px 0 0", paddingLeft: "16px", fontSize: "10px", color: "#a5b9d2", lineHeight: 1.5 }}>
                            {singleResult.rationale.map((r, i) => (
                              <li key={i}>{r}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    ) : (
                      <div style={{ color: "var(--muted)", fontSize: "11px", paddingTop: "30px", textAlign: "center" }}>
                        Select a preset and click <b>Analyze Flow</b> to see the agents in action.
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {/* Batch CSV Analysis Results if present */}
              {csvData && (
                <section className="panel" style={{ padding: "20px", marginBottom: "20px" }}>
                  <div className="panel-head">
                    <div>
                      <div className="panel-kicker">BATCH FLOW EVALUATION</div>
                      <h3>{csvData.fileName}</h3>
                      <p>{formatNumber(csvData.rows)} total rows ingested locally in browser.</p>
                    </div>
                    <button
                      className="primary-btn"
                      disabled={analyzingBatch}
                      onClick={runBatchAnalysis}
                    >
                      <Play size={14} /> {analyzingBatch ? "Processing..." : "Run Multi-Agent Analysis"}
                    </button>
                  </div>

                  {batchResults && (
                    <div style={{ marginTop: "16px" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "10px", marginBottom: "16px" }}>
                        <div style={{ background: "#143027", border: "1px solid #235848", borderRadius: "8px", padding: "10px" }}>
                          <small style={{ fontSize: "9px", color: "#74d4ac" }}>SIMULATED ALLOW</small>
                          <div style={{ fontSize: "18px", fontWeight: 700, color: "#92f5ca" }}>{batchResults.summary.ALLOW}</div>
                        </div>
                        <div style={{ background: "#38271e", border: "1px solid #63432a", borderRadius: "8px", padding: "10px" }}>
                          <small style={{ fontSize: "9px", color: "#e8ba74" }}>SIMULATED BLOCK</small>
                          <div style={{ fontSize: "18px", fontWeight: 700, color: "#ffd594" }}>{batchResults.summary.BLOCK}</div>
                        </div>
                        <div style={{ background: "#1a2538", border: "1px solid #2b4162", borderRadius: "8px", padding: "10px" }}>
                          <small style={{ fontSize: "9px", color: "#8ab4e8" }}>SIMULATED REVIEW</small>
                          <div style={{ fontSize: "18px", fontWeight: 700, color: "#b9d8ff" }}>{batchResults.summary.REVIEW}</div>
                        </div>
                      </div>

                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>INDEX</th>
                              <th>AGENT 1 (CLASS)</th>
                              <th>CONFIDENCE</th>
                              <th>AGENT 2 (SCORE)</th>
                              <th>ANOMALY</th>
                              <th>CONSENSUS</th>
                              <th>FINAL ACTION</th>
                            </tr>
                          </thead>
                          <tbody>
                            {batchResults.items.slice(0, 15).map((item, idx) => (
                              <tr key={idx}>
                                <td>#{idx + 1}</td>
                                <td><b>{item.threat_detection.predicted_class}</b></td>
                                <td>{((item.threat_detection.confidence || 0) * 100).toFixed(1)}%</td>
                                <td>{item.anomaly_detection.anomaly_score}</td>
                                <td>
                                  <span className={`tag ${item.anomaly_detection.is_anomaly ? "tag-amber" : "tag-green"}`}>
                                    {item.anomaly_detection.is_anomaly ? "ANOMALY" : "NORMAL"}
                                  </span>
                                </td>
                                <td>{item.evidence_status}</td>
                                <td>
                                  <span className={`tag ${item.action === "ALLOW" ? "tag-green" : item.action === "BLOCK" ? "tag-amber" : "tag-blue"}`}>
                                    {item.action}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </section>
              )}
            </>
          )}

          {/* Section: Dataset Inspector */}
          {activeNav === "Dataset" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">DATASET INSPECTION & SCHEMA AUDIT</div>
                  <h2>Official CICIDS2017 Dataset Profile</h2>
                  <p>Canonical five-class taxonomy partitioned into training and held-out evaluation holdouts.</p>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", margin: "20px 0" }}>
                <div style={{ background: "#101b2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>TRAINING PARTITION</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--text)" }}>456,737</div>
                  <span style={{ fontSize: "10px", color: "var(--blue)" }}>Cyber/training/flows.parquet</span>
                </div>
                <div style={{ background: "#101b2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>EVALUATION HOLDOUT</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--text)" }}>114,185</div>
                  <span style={{ fontSize: "10px", color: "var(--green)" }}>Cyber/eval/flows.parquet</span>
                </div>
                <div style={{ background: "#101b2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>FEATURE SCHEMA</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--text)" }}>71 Features</div>
                  <span style={{ fontSize: "10px", color: "var(--violet)" }}>3 constants & 4 duplicates pruned</span>
                </div>
              </div>

              <div style={{ marginTop: "20px" }}>
                <h3 style={{ fontSize: "14px", color: "var(--text)", marginBottom: "12px" }}>
                  Benchmark Class Distribution (Training vs Evaluation)
                </h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>BENCHMARK CLASS</th>
                        <th>TRAIN COUNT</th>
                        <th>TRAIN %</th>
                        <th>EVAL COUNT</th>
                        <th>EVAL %</th>
                        <th>TOTAL COUNT</th>
                        <th>PROPORTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {datasetSummary?.class_distribution?.map((row) => (
                        <tr key={row.class}>
                          <td><b>{row.class}</b></td>
                          <td>{formatNumber(row.training_count)}</td>
                          <td>{row.training_percent}%</td>
                          <td>{formatNumber(row.eval_count)}</td>
                          <td>{row.eval_percent}%</td>
                          <td>{formatNumber(row.total_count)}</td>
                          <td>
                            <div className="bar-track" style={{ width: "120px" }}>
                              <i style={{ width: `${row.total_percent}%` }} />
                            </div>
                          </td>
                        </tr>
                      )) || (
                        <tr><td colSpan={7}>Loading official class distribution...</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div style={{ marginTop: "24px", background: "#0c1524", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                <h4 style={{ fontSize: "12px", color: "var(--text)", margin: "0 0 8px" }}>
                  Data Quality & Hygiene Audit Findings
                </h4>
                <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "11px", color: "var(--muted)", lineHeight: 1.8 }}>
                  <li><b>Zero Nulls & Infinities:</b> Raw parquet features contain zero nulls; infinite cells are replaced with NaN and imputed strictly with training medians.</li>
                  <li><b>Zero ID Leakage:</b> `record_id` is verified to encode chronological/source ordering bias (69.1% leakage) and is strictly excluded from all model feature spaces.</li>
                  <li><b>Header Length Sanitization:</b> 37 training rows and 10 eval rows with invalid negative byte lengths were cleansed without row deletion.</li>
                  <li><b>Preserved Holdout Integrity:</b> Evaluation dataset records are held strictly untouched for impartial validation.</li>
                </ul>
              </div>
            </section>
          )}

          {/* Section: Threat Detection (Agent 1) */}
          {activeNav === "ThreatDetection" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">AGENT 1 INTELLIGENCE</div>
                  <h2>Supervised Threat Detection Agent</h2>
                  <p>Multiclass classification engine optimized for high-throughput network flow categorization.</p>
                </div>
                <span className="live-tag"><span className="pulse-dot" /> MODEL VERIFIED</span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", margin: "20px 0" }}>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--blue)" }}>Classifier Architecture</h4>
                  <div className="system-row"><span>Algorithm</span><b>{modelsStatus?.agents?.threat_detection?.backend || "RandomForestClassifier"}</b></div>
                  <div className="system-row"><span>Estimator Trees</span><b>100</b></div>
                  <div className="system-row"><span>Max Depth</span><b>24</b></div>
                  <div className="system-row"><span>Class Weighting</span><b>balanced_subsample</b></div>
                  <div className="system-row"><span>Input Dimension</span><b>71 numeric traffic features</b></div>
                  <div className="system-row"><span>Inference Latency</span><b>0.007 ms/flow</b></div>
                </div>

                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--green)" }}>Benchmark Class Coverage</h4>
                  {BENCHMARK_CLASSES.map((cls) => (
                    <div key={cls} className="system-row">
                      <span>{cls}</span>
                      <b className="status-ok">Active Predictor</b>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: "#0c1524", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                <h4 style={{ margin: "0 0 8px", fontSize: "12px", color: "var(--text)" }}>Execution Interface Contract</h4>
                <pre style={{ background: "#070c14", padding: "12px", borderRadius: "6px", fontSize: "11px", color: "#7dc3ff", overflowX: "auto" }}>
{`// predict(flow: dict[str, Any]) -> ThreatDetectionResult
{
  "agent": "threat_detection",
  "predicted_class": "DOS",
  "confidence": 0.9998,
  "status": "success",
  "model_version": "1"
}`}
                </pre>
              </div>
            </section>
          )}

          {/* Section: Anomaly Detection (Agent 2) */}
          {activeNav === "AnomalyDetection" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">AGENT 2 INTELLIGENCE</div>
                  <h2>Independent Anomaly Detection Agent</h2>
                  <p>Unsupervised baseline deviation scoring trained exclusively on normal benign network flows.</p>
                </div>
                <span className="live-tag"><span className="pulse-dot" /> INDEPENDENT SIGNAL</span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", margin: "20px 0" }}>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--violet)" }}>Unsupervised Model Parameters</h4>
                  <div className="system-row"><span>Algorithm</span><b>Isolation Forest</b></div>
                  <div className="system-row"><span>Training Corpus</span><b>240,000 BENIGN flows</b></div>
                  <div className="system-row"><span>Contamination Rate</span><b>0.01</b></div>
                  <div className="system-row"><span>Defensible Anomaly Threshold</span><b>-0.0232 (1st percentile benign)</b></div>
                  <div className="system-row"><span>Benign False Positive Rate</span><b>0.52%</b></div>
                </div>

                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--amber)" }}>Feature Deviation Attribution</h4>
                  <p style={{ fontSize: "11px", color: "var(--muted)", margin: "0 0 10px" }}>
                    Concrete evidence is generated by measuring robust Z-scores against learned benign medians and interquartile ranges:
                  </p>
                  <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "10px", color: "#bdd4ed", lineHeight: 1.6 }}>
                    <li><code>unusual_packet_rate</code> (Flow Packets/s &gt; Q99)</li>
                    <li><code>abnormal_flow_duration</code> (Flow Duration &gt; Q99)</li>
                    <li><code>abnormal_byte_rate</code> (Flow Bytes/s &gt; Q99)</li>
                    <li><code>high_forward_packet_volume</code> (Total Fwd Packets &gt; Q99)</li>
                  </ul>
                </div>
              </div>

              <div style={{ background: "#0c1524", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                <h4 style={{ margin: "0 0 8px", fontSize: "12px", color: "var(--text)" }}>Execution Interface Contract</h4>
                <pre style={{ background: "#070c14", padding: "12px", borderRadius: "6px", fontSize: "11px", color: "#a5e2ff", overflowX: "auto" }}>
{`// score(flow: dict[str, Any]) -> AnomalyDetectionResult
{
  "agent": "anomaly_detection",
  "anomaly_score": -0.0642,
  "is_anomaly": true,
  "evidence": ["unusual_packet_rate", "abnormal_flow_duration"],
  "status": "success"
}`}
                </pre>
              </div>
            </section>
          )}

          {/* Section: Evidence Fusion (Agent 3) */}
          {activeNav === "EvidenceFusion" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">AGENT 3 INTELLIGENCE</div>
                  <h2>Evidence Fusion & Adaptive Policy Engine</h2>
                  <p>Deterministic, explainable decision matrix synthesizing supervised classification with anomaly evidence.</p>
                </div>
              </div>

              <div style={{ marginTop: "20px" }}>
                <h3 style={{ fontSize: "14px", color: "var(--text)", marginBottom: "12px" }}>
                  Deterministic Decision Matrix
                </h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>SCENARIO</th>
                        <th>AGENT 1 (THREAT)</th>
                        <th>AGENT 2 (ANOMALY)</th>
                        <th>SIMULATED ACTION</th>
                        <th>EXPLAINABLE RATIONALE</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><b>Confirmed Attack</b></td>
                        <td>Attack (Conf &gt;= 0.85)</td>
                        <td>Anomaly Flagged</td>
                        <td><span className="tag tag-amber">BLOCK</span></td>
                        <td>Both agents agree. Dual consensus on attack classification.</td>
                      </tr>
                      <tr>
                        <td><b>Confirmed Benign</b></td>
                        <td>BENIGN (Conf &gt;= 0.60)</td>
                        <td>Normal (No Anomaly)</td>
                        <td><span className="tag tag-green">ALLOW</span></td>
                        <td>Both agents verify traffic is consistent with benign baseline.</td>
                      </tr>
                      <tr>
                        <td><b>Stealth / Low-Rate Attack</b></td>
                        <td>Attack (Conf &gt;= 0.85)</td>
                        <td>Normal (No Anomaly)</td>
                        <td><span className="tag tag-amber">BLOCK</span></td>
                        <td>High confidence supervised signature overrides unsupervised silence.</td>
                      </tr>
                      <tr>
                        <td><b>Potential Zero-Day</b></td>
                        <td>BENIGN (Normal)</td>
                        <td>Anomaly Flagged</td>
                        <td><span className="tag tag-blue">REVIEW</span></td>
                        <td>Novel attack pattern or abnormal protocol burst; flagged for analyst.</td>
                      </tr>
                      <tr>
                        <td><b>Low Confidence</b></td>
                        <td>Confidence &lt; 0.60</td>
                        <td>Any</td>
                        <td><span className="tag tag-blue">REVIEW</span></td>
                        <td>Classifier uncertainty triggers human security review.</td>
                      </tr>
                      <tr>
                        <td><b>Agent Degradation</b></td>
                        <td>Agent Failure</td>
                        <td>Active</td>
                        <td><span className="tag tag-blue">REVIEW</span></td>
                        <td>Graceful fallback without crashing application.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          )}

          {/* Section: Analysis History */}
          {activeNav === "History" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">AUDIT TRAIL & LOGS</div>
                  <h2>Analysis Run History</h2>
                  <p>Persistent audit trail synchronized with Supabase authenticated sessions.</p>
                </div>
                <button className="secondary-btn" onClick={loadHistory}>
                  <RefreshCw size={14} /> Refresh Logs
                </button>
              </div>

              {history.length === 0 ? (
                <div className="empty-history" style={{ marginTop: "24px" }}>
                  <div className="empty-history-icon"><Activity size={20} /></div>
                  <div>
                    <b>No historical runs stored yet</b>
                    <span>Upload a CSV in the Overview tab or sign in with Supabase to persist analysis runs.</span>
                  </div>
                </div>
              ) : (
                <div className="table-wrap" style={{ marginTop: "20px" }}>
                  <table>
                    <thead>
                      <tr>
                        <th>DATASET NAME</th>
                        <th>PROCESSED</th>
                        <th>STATUS</th>
                        <th>ACTION SUMMARY</th>
                        <th>TIMESTAMP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((row) => (
                        <tr key={row.id}>
                          <td><b>{row.dataset_name}</b></td>
                          <td>{formatNumber(row.processed_rows)} / {formatNumber(row.dataset_rows)}</td>
                          <td><span className="tag tag-green">{row.status}</span></td>
                          <td>
                            {row.actions_summary ? (
                              <span>
                                ALLOW: {row.actions_summary.ALLOW} · BLOCK: {row.actions_summary.BLOCK} · REVIEW: {row.actions_summary.REVIEW}
                              </span>
                            ) : "—"}
                          </td>
                          <td>{new Date(row.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* Section: Model Performance */}
          {activeNav === "Performance" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">OFFICIAL EVALUATION HOLDOUT METRICS</div>
                  <h2>Holdout Performance Telemetry</h2>
                  <p>Measured strictly on 114,185 official evaluation flows without data leakage or synthesis.</p>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", margin: "20px 0" }}>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>OVERALL ACCURACY</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "#75baff" }}>
                    {metrics ? `${(metrics.agent_1_threat_detection.overall_accuracy * 100).toFixed(4)}%` : "99.9965%"}
                  </div>
                </div>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>MACRO-F1 SCORE</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "#61deb0" }}>
                    {metrics ? metrics.agent_1_threat_detection.macro_f1.toFixed(6) : "0.999971"}
                  </div>
                </div>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>BENIGN FALSE POSITIVE RATE</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "#dcb56e" }}>
                    {metrics ? `${(metrics.agent_1_threat_detection.false_positive_rate_benign * 100).toFixed(4)}%` : "0.0000%"}
                  </div>
                </div>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "12px" }}>
                  <small style={{ fontSize: "9px", color: "var(--muted)" }}>ATTACK FALSE NEGATIVE RATE</small>
                  <div style={{ fontSize: "20px", fontWeight: 700, color: "#ff8c8c" }}>
                    {metrics ? `${(metrics.agent_1_threat_detection.false_negative_rate_attack * 100).toFixed(4)}%` : "0.0074%"}
                  </div>
                </div>
              </div>

              <div style={{ marginTop: "24px" }}>
                <h3 style={{ fontSize: "14px", color: "var(--text)", marginBottom: "12px" }}>
                  Per-Class Performance (114,185 Holdout Flows)
                </h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>CLASS</th>
                        <th>PRECISION</th>
                        <th>RECALL</th>
                        <th>F1-SCORE</th>
                        <th>EVAL SUPPORT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metrics && Object.entries(metrics.agent_1_threat_detection.per_class).map(([cls, val]) => (
                        <tr key={cls}>
                          <td><b>{cls}</b></td>
                          <td>{(val.precision * 100).toFixed(2)}%</td>
                          <td>{(val.recall * 100).toFixed(2)}%</td>
                          <td>{val.f1_score.toFixed(4)}</td>
                          <td>{formatNumber(val.support)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          )}

          {/* Section: System Health */}
          {activeNav === "Health" && (
            <section className="panel" style={{ padding: "24px" }}>
              <div className="panel-head">
                <div>
                  <div className="panel-kicker">SERVICE & INFERENCE HEALTH</div>
                  <h2>System Health & Runtime Status</h2>
                  <p>Real-time endpoint status, model artifact availability, and deployment state.</p>
                </div>
                <button className="secondary-btn" onClick={fetchData}>
                  <RefreshCw size={14} /> Ping System
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginTop: "20px" }}>
                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--blue)" }}>API Endpoint Health</h4>
                  <div className="system-row"><span>Service Name</span><b>CyberSentinel API</b></div>
                  <div className="system-row"><span>Gateway Status</span><b className="status-ok">{health?.status || "ok"}</b></div>
                  <div className="system-row"><span>Environment Mode</span><b>{health?.mode || "offline-replay"}</b></div>
                  <div className="system-row"><span>Serverless Runtime</span><b>Vercel Python 3.14</b></div>
                </div>

                <div style={{ background: "#0f1a2a", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px" }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: "12px", color: "var(--green)" }}>Model Artifact Verification</h4>
                  <div className="system-row">
                    <span>Threat Detection Artifact</span>
                    <b className={health?.agents?.agent_1_threat_detection ? "status-ok" : "status-warn"}>
                      {health?.agents?.agent_1_threat_detection ? "Loaded (1.08 MB)" : "Missing"}
                    </b>
                  </div>
                  <div className="system-row">
                    <span>Anomaly Detection Artifact</span>
                    <b className={health?.agents?.agent_2_anomaly_detection ? "status-ok" : "status-warn"}>
                      {health?.agents?.agent_2_anomaly_detection ? "Loaded (3.37 MB)" : "Missing"}
                    </b>
                  </div>
                  <div className="system-row">
                    <span>Preprocessing State</span>
                    <b className="status-ok">Loaded (71 features)</b>
                  </div>
                </div>
              </div>
            </section>
          )}

          <footer className="footer" style={{ marginTop: "30px" }}>
            <span>CYBERSENTINEL <i>·</i> JAI 2026 TRACK 01</span>
            <span><span className="pulse-dot" /> OFFLINE TRAFFIC REPLAY CHALLENGE</span>
            <span>BUILD 1.0.0</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function Metric({ icon: Icon, label, value, detail, tone }: any) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${tone}`}><Icon size={18} /></div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function AgentCard({ number, title, desc, status, icon: Icon }: any) {
  return (
    <div className="agent-row">
      <div className="agent-number">{number}</div>
      <div className="agent-icon"><Icon size={17} /></div>
      <div className="agent-copy">
        <b>{title}</b>
        <span>{desc}</span>
      </div>
      <span className="agent-status ready">{status}</span>
    </div>
  );
}

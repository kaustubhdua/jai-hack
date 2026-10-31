import { lazy, Suspense, useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import Papa from "papaparse";
import {
  Activity, ArrowRight, ArrowUpRight, Check,
  ChevronDown, CircleHelp, CloudUpload, Cpu, Database, FileSpreadsheet, Fingerprint,
  Gauge, Layers, LockKeyhole, Menu, X, Network, Play, RefreshCw, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles
} from "lucide-react";
import { ParticleBackdrop } from "./components/ParticleBackdrop";
import { supabase } from "./lib/supabase";
import { apiFetch } from "./lib/api";
const Agent2Console = lazy(() => import("./FlowInspector").then(module => ({ default: module.Agent2Console })));
const FlowInspector = lazy(() => import("./FlowInspector").then(module => ({ default: module.FlowInspector })));
const BatchReplay = lazy(() => import("./BatchReplay").then(module => ({ default: module.BatchReplay })));
const TopologyCommandCentre = lazy(() => import("./Level2Consoles").then(module => ({ default: module.TopologyCommandCentre })));
const FiveAgentArchitectureView = lazy(() => import("./Level2Consoles").then(module => ({ default: module.FiveAgentArchitectureView })));
const EvidenceFusionStudio = lazy(() => import("./Level2Consoles").then(module => ({ default: module.EvidenceFusionStudio })));
const TemporalCorrelationConsole = lazy(() => import("./Level2Consoles").then(module => ({ default: module.TemporalCorrelationConsole })));
const AdaptiveDefenseConsole = lazy(() => import("./Level2Consoles").then(module => ({ default: module.AdaptiveDefenseConsole })));
const ReplayStudio = lazy(() => import("./Level2Consoles").then(module => ({ default: module.ReplayStudio })));
const ModelIntelligenceView = lazy(() => import("./Level2Consoles").then(module => ({ default: module.ModelIntelligenceView })));
const AuditHistoryView = lazy(() => import("./Level2Consoles").then(module => ({ default: module.AuditHistoryView })));
const SystemHealthView = lazy(() => import("./Level2Consoles").then(module => ({ default: module.SystemHealthView })));

type Health = {
  status: string;
  service: string;
  model_ready: boolean;
  message?: string;
  agents?: {
    agent_1_threat_detection?: boolean;
    agent_2_anomaly_detection?: boolean;
    agent_3_evidence_fusion?: boolean;
    agent_4_temporal_correlation?: boolean;
    agent_5_adaptive_defense?: boolean;
  };
};

type HistoryRow = {
  run_id: string;
  dataset_name: string;
  total_records: number;
  blocked_records: number;
  allowed_records: number;
  policies_created: number;
  containment_rate: number | null;
  throughput_fps: number | null;
  status: string;
  created_at: string;
};

type DatasetInfo = {
  name: string;
  rows: number;
  columns: string[];
  labels: Record<string, number>;
  labelColumn: string | null;
  errors: string[];
};

const BENCHMARK = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"];
const formatNumber = (n: number) => new Intl.NumberFormat("en-IN").format(n);

export default function App() {
  const [authSession, setAuthSession] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState(Boolean(supabase));
  const session = { user: { display_name: authSession?.user?.email ?? "Local analyst", email: authSession?.user?.email ?? null } };
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    if (!supabase) { setAuthLoading(false); return; }
    let active = true;
    void supabase.auth.getSession().then(({ data }) => {
      if (active) { setAuthSession(data.session); setAuthLoading(false); }
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setAuthSession(nextSession);
      setAuthLoading(false);
    });
    return () => { active = false; subscription.unsubscribe(); };
  }, []);
  const [overview, setOverview] = useState<any>(null);
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [historyMessage, setHistoryMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const loadHistory = useCallback(async () => {
    try {
      const response = await apiFetch("/api/history?limit=8");
      if (!response.ok) throw new Error("Local history API unavailable");
      const data = await response.json();
      setHistory(Array.isArray(data.runs) ? data.runs : []);
      setHistoryMessage(typeof data.message === "string" ? data.message : "");
    } catch {
      setHistory([]);
      setHistoryMessage("Local replay history is unavailable until the Python API is running.");
    }
  }, []);

  useEffect(() => { void loadHistory(); }, [loadHistory]);

  const loadOverview = useCallback(async () => {
    try {
      const response = await apiFetch("/api/overview");
      if (!response.ok) throw new Error("Replay artifacts are not available");
      setOverview(await response.json());
    } catch {
      setOverview(null);
    }
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const response = await apiFetch("/api/health");
      if (!response.ok) throw new Error("API unavailable");
      setHealth(await response.json());
    } catch {
      setHealth({ status: "unavailable", service: "CyberSentinel API", model_ready: false });
    }
  }, []);
  useEffect(() => { void checkHealth(); void loadOverview(); }, [checkHealth, loadOverview]);

  function inspectFile(file?: File) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) { setNotice("Please choose a CSV file."); return; }
    setBusy(true); setNotice("");
    Papa.parse<Record<string, string>>(file, {
      header: true, skipEmptyLines: "greedy", dynamicTyping: false,
      complete: (result) => {
        const columns = result.meta.fields ?? [];
        const normalized = columns.map(c => c.trim().toLowerCase());
        const labelIndex = normalized.findIndex(c => ["label", "class", "attack", "target"].includes(c));
        const labelColumn = labelIndex >= 0 ? columns[labelIndex] : null;
        const labels: Record<string, number> = {};
        if (labelColumn) {
          for (const row of result.data) {
            const label = String(row[labelColumn] ?? "").trim().toUpperCase();
            if (label) labels[label] = (labels[label] ?? 0) + 1;
          }
        }
        const errors = result.errors.slice(0, 4).map(e => e.message);
        setDataset({ name: file.name, rows: result.data.length, columns, labels, labelColumn, errors });
        setBusy(false);
        setNotice("CSV inspected locally in your browser. The file was not uploaded.");
      },
      error: (error) => { setBusy(false); setNotice("Could not parse CSV: " + error.message); }
    });
  }

  const knownLabels = dataset ? Object.keys(dataset.labels).filter(l => BENCHMARK.includes(l)) : [];
  const totalLabels = dataset ? Object.values(dataset.labels).reduce((a, b) => a + b, 0) : 0;
  const labelCoverage = totalLabels ? Math.round(knownLabels.reduce((n, l) => n + dataset!.labels[l], 0) / totalLabels * 100) : 0;

  if (supabase && authLoading) return <div className="app-shell"><main className="main-content"><div className="page-wrap"><div className="panel empty-inline">Checking secure Supabase session…</div></div></main></div>;
  if (supabase && !authSession) return <AuthScreen />;

  return <div className="app-shell">
    <ParticleBackdrop />
    {mobileNavOpen && <button type="button" className="mobile-nav-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <aside className={"sidebar" + (mobileNavOpen ? " mobile-open" : "")}>
      <div className="brand"><div className="brand-mark"><Shield size={21} /></div><span>CYBERSENTINEL</span></div>
      <div className="workspace"><div className="workspace-avatar">{session.user.display_name.slice(0,1).toUpperCase()}</div><div><b>{authSession ? session.user.display_name : "LOCAL ANALYST"}</b><small>{authSession ? "Secure workspace" : "Offline workspace"}</small></div><ChevronDown size={14} /></div>
      <div className="nav-label">COMMAND WORKSPACE</div>
      {[
        ["Overview", Gauge],
        ["Five-Agent Architecture", Layers],
        ["Flow Inspector", Network],
        ["Evidence Fusion", Fingerprint],
        ["Temporal Investigations", Activity],
        ["Adaptive Defense", ShieldAlert],
        ["Replay Studio", Play],
        ["Model Intelligence", Cpu],
        ["Audit & Local History", Database],
        ["Settings & Health", SlidersHorizontal],
      ].map(([name, Icon]: any) => (
        <button
          key={name}
          className={"nav-item " + (activeNav === name ? "active" : "")}
          aria-label={String(name)}
          title={String(name)}
          onClick={() => { setActiveNav(name); setMobileNavOpen(false); }}
        >
          <Icon size={16} />
          {name}
        </button>
      ))}
      <div className="nav-label nav-label-lower">DOCUMENTATION & REPO</div>
      <a className="nav-item" href="https://github.com/kaustubhdua/jai-hack/tree/feat/cybersentinel-release-hardening/docs" target="_blank" rel="noreferrer"><CircleHelp size={16}/>Product documentation<ArrowUpRight size={13} className="nav-external"/></a>
      <div className="sidebar-bottom">
        <div className="system-card">
          <div className="system-card-head"><span className="pulse-dot" /> SYSTEM STATUS</div>
          <div className="system-row"><span>Web console</span><b className="status-ok">Operational</b></div>
          <div className="system-row"><span>Inference API</span><b className={health?.status === "ok" ? "status-ok" : "status-warn"}>{health?.status === "ok" ? "Online" : "Not ready"}</b></div>
          <div className="system-row"><span>ML models</span><b className={health?.model_ready ? "status-ok" : "status-warn"}>{health?.model_ready ? "Active" : "Pending"}</b></div>
        </div>
        <div className="profile-row">
          <div className="profile-avatar">{session.user.display_name.slice(0,1).toUpperCase()}</div>
          <div className="profile-meta"><b>{session.user.display_name}</b><small>{authSession ? "Authenticated Supabase user" : "Local analyst session"}</small></div>
          {authSession && <button className="secondary-btn" onClick={() => { void supabase?.auth.signOut(); }} style={{ padding: "5px 8px", fontSize: 10 }}>Sign out</button>}
        </div>
      </div>
    </aside>
    <Suspense fallback={<div className="main-content"><div className="page-wrap"><div className="panel empty-inline" role="status" aria-live="polite">Loading security console…</div></div></div>}>
    <main className="main-content">
      <header className="topbar">
        <button type="button" className="mobile-menu-btn" aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileNavOpen} onClick={() => setMobileNavOpen(v => !v)}>{mobileNavOpen ? <X size={18}/> : <Menu size={18}/>}</button>
        <div className="crumb"><span>Workspace</span><span>/</span><b>{activeNav}</b></div>
        <div className="top-actions">
          <div className="env-pill"><span className="pulse-dot" /> OFFLINE REPLAY MODE</div>
          <button className="icon-btn" title="Refresh API and replay status" onClick={() => { void checkHealth(); void loadOverview(); }}><RefreshCw size={16} /></button>
          <div className="top-avatar">L</div>
        </div>
      </header>
      <div className="page-wrap">
        <section className="page-heading">
          <div>
            <div className="eyebrow">NETWORK FLOW ANALYSIS <span className="heading-line" /></div>
            <h1>{activeNav === "Overview" ? "Security overview" : activeNav}</h1>
            <p>Inspect captured flow records, review model evidence, and run causal offline replay. No live traffic is captured.</p>
          </div>
          <div className="heading-actions">
            <span className="date-chip">LOCAL WORKSPACE <span>·</span> OFFLINE</span>
            <button className="primary-btn" onClick={() => inputRef.current?.click()}><CloudUpload size={16} /> Inspect CSV</button>
          </div>
        </section>
        {notice && <div className="notice" role="status" aria-live="polite"><Check size={15} />{notice}<button onClick={() => setNotice("")}><X size={15} /></button></div>}

        {activeNav === "Overview" && (
          <>
            <TopologyCommandCentre />
            <section className="metrics-grid">
              <Metric icon={Database} label="DATASET FLOWS" value={dataset ? formatNumber(dataset.rows) : (overview ? formatNumber(overview.metrics.total_records) : "—")} detail={dataset ? "Inspected in browser" : (overview ? "Verified replay artifact" : "Awaiting local replay artifacts") } tone="blue"/>
              <Metric icon={ShieldAlert} label="POLICIES CREATED" value={overview ? formatNumber(overview.metrics.policies_created) : "—"} detail={overview ? "Generated by completed replay" : "No generated policy file detected"} tone="amber"/>
              <Metric icon={ShieldCheck} label="ATTACK CONTAINMENT" value={typeof overview?.metrics?.attack_containment_rate === "number" ? overview.metrics.attack_containment_rate.toFixed(2) + "%" : "Not measured"} detail={typeof overview?.metrics?.attack_containment_rate === "number" ? formatNumber(overview.metrics.attacks_contained) + " labelled attack flows blocked" : "Hidden replay has no ground-truth labels"} tone="green"/>
              <Metric icon={Cpu} label="BENIGN PRESERVED" value={typeof overview?.metrics?.benign_preservation_rate === "number" ? overview.metrics.benign_preservation_rate.toFixed(2) + "%" : "Not measured"} detail={typeof overview?.metrics?.benign_preservation_rate === "number" ? formatNumber(overview.metrics.benign_preserved) + " labelled benign flows preserved" : "Hidden replay has no ground-truth labels"} tone="violet"/>
            </section>

            <section className="content-grid">
              <div className="panel dataset-panel">
                <div className="panel-head">
                  <div>
                    <div className="panel-kicker">LOCAL CSV INSPECTION</div>
                    <h3>Inspect a flow dataset</h3>
                    <p>Review CSV columns and label distribution in this browser. This control does not train a model or run inference.</p>
                  </div>
                  <span className="panel-icon"><FileSpreadsheet size={18}/></span>
                </div>
                <input ref={inputRef} type="file" accept=".csv,text/csv" hidden onChange={e=>inspectFile(e.target.files?.[0])}/>
                {!dataset ? (
                  <button className="dropzone" onClick={()=>inputRef.current?.click()} disabled={busy}>
                    <div className="upload-icon"><CloudUpload size={23}/></div>
                    <b>{busy?"Inspecting CSV…":"Choose a CSV to inspect"}</b>
                    <span>or <u>browse files</u> · CSV format</span>
                    <small>Browser-only schema inspection · File is not uploaded to the backend</small>
                  </button>
                ) : (
                  <div className="dataset-loaded">
                    <div className="file-line">
                      <div className="file-icon"><FileSpreadsheet size={19}/></div>
                      <div className="file-info"><b>{dataset.name}</b><span>{formatNumber(dataset.rows)} rows · {dataset.columns.length} columns</span></div>
                      <span className="tag tag-green"><Check size={12}/> Inspected</span>
                    </div>
                    <div className="dataset-facts">
                      <div><small>ROWS</small><b>{formatNumber(dataset.rows)}</b></div>
                      <div><small>COLUMNS</small><b>{dataset.columns.length}</b></div>
                      <div><small>LABEL FIELD</small><b>{dataset.labelColumn??"Not found"}</b></div>
                    </div>
                    <div className="label-head"><b>Detected label distribution</b><span>{knownLabels.length}/5 benchmark classes · {labelCoverage}% mapped</span></div>
                    {Object.keys(dataset.labels).length ? Object.entries(dataset.labels).sort((a,b)=>b[1]-a[1]).slice(0,7).map(([label,count])=>(
                      <div className="label-bar" key={label}>
                        <span>{label}</span>
                        <div className="bar-track"><i style={{width:(count/totalLabels*100)+"%"}}/></div>
                        <b>{formatNumber(count)}</b>
                      </div>
                    )) : <div className="empty-inline">No recognised label column detected. Confirm the organiser's schema and label mapping.</div>}
                    {dataset.errors.length>0&&<div className="parse-warning">{dataset.errors.join(" · ")}</div>}
                    <button className="text-btn" onClick={()=>{setDataset(null);setNotice("");}}>Choose another file <ArrowRight size={14}/></button>
                  </div>
                )}
                <div className="panel-foot">
                  <span><LockKeyhole size={13}/> Data stays in this browser</span>
                  <span>LOCAL BROWSER INSPECTION</span>
                </div>
              </div>

              <div className="panel pipeline-panel">
                <div className="panel-head">
                  <div>
                    <div className="panel-kicker">MULTI-AGENT SYSTEM</div>
                    <h3>Detection pipeline</h3>
                    <p>Independent signals, explainable decisions.</p>
                  </div>
                  <span className="live-tag">COMPONENT READINESS</span>
                </div>
                <div className="agent-list">
                  <Agent number="01" title="Threat detection" desc="Supervised five-class classification" status={health?.agents?.agent_1_threat_detection ? "Active" : "Awaiting model"} icon={ShieldAlert}/>
                  <div className="agent-connector"/>
                  <Agent number="02" title="Anomaly detection" desc="Independent unsupervised outlier scoring" status={health?.agents?.agent_2_anomaly_detection ? "Active" : "Awaiting model"} icon={Activity}/>
                  <div className="agent-connector"/>
                  <Agent number="03" title="Evidence fusion" desc="Combines A1 and A2 evidence and disagreement" status={health?.agents?.agent_3_evidence_fusion ? "Ready" : "Waiting for model pipeline"} icon={Fingerprint}/>
                  <div className="agent-connector"/>
                  <Agent number="04" title="Temporal correlation" desc="Groups suspicious flows in observed time windows" status={health?.agents?.agent_4_temporal_correlation ? "Ready" : "Waiting for model pipeline"} icon={Network}/>
                  <div className="agent-connector"/>
                  <Agent number="05" title="Adaptive defense" desc="Creates temporary simulated ALLOW/BLOCK policies" status={health?.agents?.agent_5_adaptive_defense ? "Ready" : "Waiting for model pipeline"} icon={ShieldCheck}/>
                </div>
                <div className="fusion-note">
                  <Sparkles size={15}/>
                  <span>A3 preserves both model outputs and rationale. A4/A5 run only in chronological replay, where earlier active policies are checked first.</span>
                </div>
              </div>
            </section>

            <section className="panel history-panel">
              <div className="panel-head history-head">
                <div>
                  <div className="panel-kicker">SUPABASE REPLAY AUDIT TRAIL</div>
                  <h3>Recent Cloud Replay Runs</h3>
                  <p>Only your authenticated replay summaries appear here. Unlabelled replay data does not provide accuracy or false-block metrics.</p>
                </div>
                <button className="secondary-btn" onClick={loadHistory}><RefreshCw size={14}/> Refresh</button>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>REPLAY RUN</th>
                      <th>RECORDS</th>
                      <th>STATUS</th>
                      <th>BLOCKED</th>
                      <th>ALLOWED</th>
                      <th>POLICIES</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.length === 0 && <tr><td colSpan={6} className="empty-inline">{historyMessage || "No local replay runs recorded yet."}</td></tr>}
                    {history.map(row=>(
                      <tr key={row.run_id}>
                        <td>{row.dataset_name}</td>
                        <td>{formatNumber(row.total_records)}</td>
                        <td><span className={"tag "+(row.status==="COMPLETED"?"tag-green":"tag-amber")}>{row.status}</span></td>
                        <td>{formatNumber(row.blocked_records)}</td>
                        <td>{formatNumber(row.allowed_records)}</td>
                        <td>{formatNumber(row.policies_created)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        {activeNav === "Five-Agent Architecture" && <FiveAgentArchitectureView />}
        {activeNav === "Flow Inspector" && (
          <>
            <FlowInspector modelReady={Boolean(health?.model_ready)} />
            <Agent2Console ready={Boolean(health?.agents?.agent_2_anomaly_detection)} />
            <BatchReplay modelReady={Boolean(health?.model_ready)} />
          </>
        )}
        {activeNav === "Evidence Fusion" && <EvidenceFusionStudio />}
        {activeNav === "Temporal Investigations" && <TemporalCorrelationConsole />}
        {activeNav === "Adaptive Defense" && <AdaptiveDefenseConsole />}
        {activeNav === "Replay Studio" && <ReplayStudio modelReady={Boolean(health?.model_ready)} />}
        {activeNav === "Model Intelligence" && <ModelIntelligenceView />}
        {activeNav === "Audit & Local History" && <AuditHistoryView />}
        {activeNav === "Settings & Health" && <SystemHealthView health={health} />}

        <footer className="footer">
          <span>CYBERSENTINEL <i>·</i> NETWORK FLOW ANALYSIS</span>
          <span><span className="pulse-dot" /> OFFLINE ANALYSIS ONLY</span>
          <span>BUILD 1.0.0</span>
        </footer>
      </div>
    </main>
    </Suspense>
  </div>;
}

function AuthScreen() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase) return;
    setBusy(true); setError(""); setMessage("");
    try {
      if (mode === "signin") {
        const { error: authError } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
        if (authError) throw authError;
      } else {
        const { data, error: authError } = await supabase.auth.signUp({ email: email.trim(), password });
        if (authError) throw authError;
        if (!data.session) setMessage("Account created. Check your email to confirm the address, then sign in.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  return <div className="app-shell" style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
    <section className="panel dataset-panel" style={{ width: "min(460px, 100%)", padding: 28 }}>
      <div className="panel-kicker">CYBERSENTINEL · SECURE WORKSPACE</div>
      <h2 style={{ margin: "10px 0" }}>{mode === "signin" ? "Sign in to your workspace" : "Create your analyst account"}</h2>
      <p style={{ color: "var(--muted)", fontSize: 12, lineHeight: 1.6 }}>Sign in with Supabase Auth to access your private replay history and inference audit trail. Network-flow files remain local and are not uploaded.</p>
      <form onSubmit={submit} style={{ display: "grid", gap: 12, marginTop: 20 }}>
        <label style={{ display: "grid", gap: 6, fontSize: 11 }}>Email<input type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)} style={{ padding: 12, borderRadius: 8, border: "1px solid var(--line)", background: "var(--panel2)", color: "var(--text)" }} /></label>
        <label style={{ display: "grid", gap: 6, fontSize: 11 }}>Password<input type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={8} required value={password} onChange={e => setPassword(e.target.value)} style={{ padding: 12, borderRadius: 8, border: "1px solid var(--line)", background: "var(--panel2)", color: "var(--text)" }} /></label>
        {error && <div className="parse-warning" role="alert">{error}</div>}
        {message && <div className="empty-inline" role="status">{message}</div>}
        <button className="primary-btn" type="submit" disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}</button>
      </form>
      <button className="text-btn" style={{ marginTop: 14 }} onClick={() => { setMode(mode === "signin" ? "signup" : "signin"); setError(""); setMessage(""); }}>
        {mode === "signin" ? "New here? Create an account" : "Already registered? Sign in"}
      </button>
    </section>
  </div>;
}

function Metric({ icon: Icon, label, value, detail, tone }: { icon: any; label: string; value: string; detail: string; tone: string }) {
  return <div className="metric-card">
    <div className={"metric-icon " + tone}><Icon size={18} /></div>
    <div className="metric-label">{label}</div>
    <div className="metric-value">{value}</div>
    <div className="metric-detail">{detail}</div>
  </div>;
}

function Agent({ number, title, desc, status, icon: Icon }: { number: string; title: string; desc: string; status: string; icon: any }) {
  return <div className="agent-row">
    <div className="agent-number">{number}</div>
    <div className="agent-icon"><Icon size={17} /></div>
    <div className="agent-copy"><b>{title}</b><span>{desc}</span></div>
    <span className={"agent-status " + (status === "Active" ? "ready" : "pending")}>{status}</span>
  </div>;
}

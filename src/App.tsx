import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import Papa from "papaparse";
import {
  Activity, ArrowRight, ArrowUpRight, Check,
  ChevronDown, CircleHelp, CloudUpload, Cpu, Database, FileSpreadsheet, Fingerprint,
  Gauge, Layers, LockKeyhole, Menu, X, Network, Play, RefreshCw, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles
} from "lucide-react";
import { ParticleBackdrop } from "./components/ParticleBackdrop";
import "./components/DashboardStates.css";
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
  const session = { user: { display_name: "Local analyst" } };

  useEffect(() => {
    // Clear any legacy account token left by older versions of the app.
    localStorage.removeItem("cybersentinel_access_token");
  }, []);
  const [overview, setOverview] = useState<any>(null);
  const [overviewState, setOverviewState] = useState<"idle" | "loading" | "ready" | "empty" | "error">("loading");
  const [overviewMessage, setOverviewMessage] = useState("");
  const [dataset, setDataset] = useState<DatasetInfo | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [historyMessage, setHistoryMessage] = useState("");
  const [historyLoading, setHistoryLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [parsedRows, setParsedRows] = useState<number | null>(null);
  const [notice, setNotice] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const response = await apiFetch("/api/history?limit=8");
      if (!response.ok) throw new Error("Local history API unavailable");
      const data = await response.json();
      setHistory(Array.isArray(data.runs) ? data.runs : []);
      setHistoryMessage(typeof data.message === "string" ? data.message : "");
    } catch {
      setHistory([]);
      setHistoryMessage("Local replay history is unavailable. Check that the local API is running.");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const loadOverview = useCallback(async () => {
    setOverviewState("loading");
    setOverviewMessage("");
    try {
      const response = await apiFetch("/api/overview");
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        if (response.status === 503 && payload?.detail?.code === "REPLAY_ARTIFACTS_NOT_READY") {
          setOverview(null);
          setOverviewState("empty");
          setOverviewMessage("No generated replay artifacts are available in this runtime. Official replay uses local organizer files; results generated on your computer do not automatically appear in the hosted deployment.");
          return;
        }
        throw new Error("The replay summary could not be loaded. Check the API connection and try again.");
      }
      if (!payload || typeof payload.metrics?.total_records !== "number" || typeof payload.metrics?.policies_created !== "number") {
        throw new Error("The API returned an incomplete replay summary. Refresh and try again.");
      }
      setOverview(payload);
      setOverviewState("ready");
    } catch (error) {
      setOverview(null);
      setOverviewState("error");
      setOverviewMessage(error instanceof Error ? error.message : "The replay summary is unavailable. Try again.");
    }
  }, []);

  const checkHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const response = await apiFetch("/api/health");
      if (!response.ok) throw new Error("API unavailable");
      setHealth(await response.json());
    } catch {
      setHealth({ status: "unavailable", service: "CyberSentinel API", model_ready: false });
    } finally {
      setHealthLoading(false);
    }
  }, []);
  useEffect(() => {
    void checkHealth();
    void loadOverview();
  }, [checkHealth, loadOverview]);

  function inspectFile(file?: File) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) { setNotice("Please choose a CSV file."); return; }
    if (file.size > 100 * 1024 * 1024) { setNotice("CSV exceeds the 100 MB browser inspection limit."); return; }
    setBusy(true);
    setParsedRows(null);
    setNotice("");
    let columns: string[] = [];
    let labelColumn: string | null = null;
    let rowCount = 0;
    const labels: Record<string, number> = {};
    const errors: string[] = [];
    Papa.parse<Record<string, string>>(file, {
      header: true,
      skipEmptyLines: "greedy",
      dynamicTyping: false,
      worker: true,
      chunk: (result) => {
        if (!columns.length) {
          columns = result.meta.fields ?? [];
          const normalized = columns.map(column => column.trim().toLowerCase());
          const labelIndex = normalized.findIndex(column => ["label", "class", "attack", "target"].includes(column));
          labelColumn = labelIndex >= 0 ? columns[labelIndex] : null;
        }
        rowCount += result.data.length;
        if (labelColumn) {
          for (const row of result.data) {
            const label = String(row[labelColumn] ?? "").trim().toUpperCase();
            if (label) labels[label] = (labels[label] ?? 0) + 1;
          }
        }
        if (errors.length < 4) errors.push(...result.errors.slice(0, 4 - errors.length).map(issue => issue.message));
        setParsedRows(rowCount);
      },
      complete: () => {
        if (!columns.length || rowCount === 0) {
          setDataset(null);
          setBusy(false);
          setParsedRows(null);
          setNotice("The CSV must contain a header row and at least one non-empty data row.");
          return;
        }
        setDataset({ name: file.name, rows: rowCount, columns, labels, labelColumn, errors });
        setBusy(false);
        setParsedRows(null);
        setNotice("CSV inspected locally in your browser. The file was not uploaded.");
      },
      error: error => {
        setBusy(false);
        setParsedRows(null);
        setNotice("Could not parse CSV: " + error.message);
      }
    });
  }

  const knownLabels = dataset ? Object.keys(dataset.labels).filter(l => BENCHMARK.includes(l)) : [];
  const totalLabels = dataset ? Object.values(dataset.labels).reduce((a, b) => a + b, 0) : 0;
  const labelCoverage = totalLabels ? Math.round(knownLabels.reduce((n, l) => n + dataset!.labels[l], 0) / totalLabels * 100) : 0;

  return <div className="app-shell">
    <ParticleBackdrop />
    {mobileNavOpen && <button type="button" className="mobile-nav-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <aside className={"sidebar" + (mobileNavOpen ? " mobile-open" : "")}>
      <div className="brand"><div className="brand-mark"><Shield size={21} /></div><span>CYBERSENTINEL</span></div>
      <div className="workspace"><div className="workspace-avatar">{session.user.display_name.slice(0,1).toUpperCase()}</div><div><b>LOCAL ANALYST</b><small>Public · no account required</small></div><ChevronDown size={14} /></div>
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
      <a className="nav-item" href="https://github.com/kaustubhdua/jai-hack/tree/main/docs" target="_blank" rel="noreferrer"><CircleHelp size={16}/>Product documentation<ArrowUpRight size={13} className="nav-external"/></a>
      <div className="sidebar-bottom">
        <div className="system-card">
          <div className="system-card-head"><span className="pulse-dot" /> SYSTEM STATUS</div>
          <div className="system-row"><span>Web console</span><b className="status-ok">Operational</b></div>
          <div className="system-row"><span>Inference API</span><b className={healthLoading ? "" : health?.status === "ok" ? "status-ok" : "status-warn"}>{healthLoading ? "Checking…" : health?.status === "ok" ? "Online" : "Unavailable"}</b></div>
          <div className="system-row"><span>ML models</span><b className={healthLoading || !health ? "" : health.status !== "ok" ? "status-warn" : health.model_ready ? "status-ok" : "status-warn"}>{healthLoading ? "Checking…" : !health || health.status !== "ok" ? "Unknown" : health.model_ready ? "Active" : "Pending"}</b></div>
        </div>
        <div className="profile-row">
          <div className="profile-avatar">{session.user.display_name.slice(0,1).toUpperCase()}</div>
          <div className="profile-meta"><b>{session.user.display_name}</b><small>Account-free workspace · local data</small></div>}
        </div>
      </div>
    </aside>
    <Suspense fallback={<div className="main-content"><div className="page-wrap"><div className="workspace-loading" role="status" aria-live="polite"><span className="workspace-loading-spinner" aria-hidden="true" />Loading selected workspace…</div><div className="workspace-loading-skeleton" aria-hidden="true"><i /><i /><i /></div></div></div>}>
    <main className="main-content">
      <header className="topbar">
        <button type="button" className="mobile-menu-btn" aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileNavOpen} onClick={() => setMobileNavOpen(v => !v)}>{mobileNavOpen ? <X size={18}/> : <Menu size={18}/>}</button>
        <div className="crumb"><span>Workspace</span><span>/</span><b>{activeNav}</b></div>
        <div className="top-actions">
          <div className="env-pill"><span className="pulse-dot" /> OFFLINE REPLAY MODE</div>
          <button className="icon-btn" title="Refresh API, local history and overview" onClick={() => { void checkHealth(); void loadOverview(); void loadHistory(); }}><RefreshCw size={16} /></button>
          <div className="top-avatar">{session.user.display_name.slice(0,1).toUpperCase()}</div>
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
            {overviewState === "empty" && <div className="overview-state" role="status">{overviewMessage}</div>}
            {overviewState === "error" && <div className="overview-state overview-state-error" role="alert"><span>{overviewMessage}</span><button className="secondary-btn" onClick={() => { void loadOverview(); }}><RefreshCw size={14}/> Retry</button></div>}
            <section className="metrics-grid" aria-busy={overviewState === "loading"}>
              {overviewState === "loading" ? (
                <>
                  <MetricSkeleton icon={Database} label="DATASET FLOWS" tone="blue"/>
                  <MetricSkeleton icon={ShieldAlert} label="POLICIES CREATED" tone="amber"/>
                  <MetricSkeleton icon={ShieldCheck} label="ATTACK CONTAINMENT" tone="green"/>
                  <MetricSkeleton icon={Cpu} label="BENIGN PRESERVED" tone="violet"/>
                </>
              ) : (
                <>
                  <Metric icon={Database} label="DATASET FLOWS" value={dataset ? formatNumber(dataset.rows) : (overview ? formatNumber(overview.metrics.total_records) : "—")} detail={dataset ? "Inspected in browser" : (overview ? "Verified replay artifact" : "Awaiting local replay artifacts")} tone="blue"/>
                  <Metric icon={ShieldAlert} label="POLICIES CREATED" value={overview ? formatNumber(overview.metrics.policies_created) : "—"} detail={overview ? "Generated by completed replay" : "No generated policy file detected"} tone="amber"/>
                  <Metric icon={ShieldCheck} label="ATTACK CONTAINMENT" value={typeof overview?.metrics?.attack_containment_rate === "number" ? overview.metrics.attack_containment_rate.toFixed(2) + "%" : "Not measured"} detail={typeof overview?.metrics?.attack_containment_rate === "number" ? formatNumber(overview.metrics.attacks_contained) + " labelled attack flows blocked" : "Hidden replay has no ground-truth labels"} tone="green"/>
                  <Metric icon={Cpu} label="BENIGN PRESERVED" value={typeof overview?.metrics?.benign_preservation_rate === "number" ? overview.metrics.benign_preservation_rate.toFixed(2) + "%" : "Not measured"} detail={typeof overview?.metrics?.benign_preservation_rate === "number" ? formatNumber(overview.metrics.benign_preserved) + " labelled benign flows preserved" : "Hidden replay has no ground-truth labels"} tone="violet"/>
                </>
              )}
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
                <input ref={inputRef} type="file" accept=".csv,text/csv" hidden onChange={e=>{inspectFile(e.target.files?.[0]); e.currentTarget.value="";}}/>
                {!dataset ? (
                  <>
                    <button className="dropzone" onClick={()=>inputRef.current?.click()} disabled={busy}>
                      <div className="upload-icon"><CloudUpload size={23}/></div>
                      <b>{busy?"Inspecting CSV…":"Choose a CSV to inspect"}</b>
                      <span>or <u>browse files</u> · CSV format</span>
                      <small>Browser-only schema inspection · File is not uploaded to the backend</small>
                    </button>
                    {busy && <div className="csv-processing" role="status" aria-live="polite" aria-atomic="true">
                      <span className="csv-processing-spinner" aria-hidden="true" />
                      <div><b>Inspecting CSV locally</b><span>{parsedRows === null ? "Starting background parser…" : parsedRows.toLocaleString() + " rows inspected so far · Counting labels in your browser"}</span></div>
                      <div className="csv-processing-track indeterminate" aria-hidden="true"><i /></div>
                    </div>}
                  </>
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
                  <div className="panel-kicker">LOCAL SQLITE REPLAY HISTORY</div>
                  <h3>Recent Replay Runs</h3>
                  <p>Run summaries are saved locally when the backend is running on your computer. The hosted demo is stateless and does not send data to a cloud database.</p>
                </div>
                <button className="secondary-btn" onClick={loadHistory}><RefreshCw size={14}/> Refresh</button>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>REPLAY RUN</th><th>RECORDS</th><th>STATUS</th><th>BLOCKED</th><th>ALLOWED</th><th>POLICIES</th></tr></thead>
                  <tbody>
                    {historyLoading && <tr><td colSpan={6} className="history-loading" role="status">Loading local replay history…</td></tr>}
                    {!historyLoading && history.length === 0 && <tr><td colSpan={6} className="empty-inline">{historyMessage || "No local replay runs recorded yet."}</td></tr>}
                    {history.map(row=>(
                      <tr key={row.run_id}>
                        <td>{row.dataset_name}</td><td>{formatNumber(row.total_records)}</td>
                        <td><span className={"tag "+(row.status==="COMPLETED"?"tag-green":"tag-amber")}>{row.status}</span></td>
                        <td>{formatNumber(row.blocked_records)}</td><td>{formatNumber(row.allowed_records)}</td><td>{formatNumber(row.policies_created)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section></>
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

function MetricSkeleton({ icon: Icon, label, tone }: { icon: any; label: string; tone: string }) {
  return <div className="metric-card" aria-hidden="true">
    <div className={"metric-icon " + tone}><Icon size={18} /></div>
    <div className="metric-label">{label}</div>
    <div className="dashboard-skeleton dashboard-skeleton-value" />
    <div className="dashboard-skeleton dashboard-skeleton-detail" />
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
    <span className={"agent-status " + (status === "Active" || status === "Ready" ? "ready" : "pending")}>{status}</span>
  </div>;
}

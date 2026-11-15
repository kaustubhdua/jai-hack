import "./UniversalWorkspace.css";
import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowDownToLine, Database, FileUp, FlaskConical, RefreshCw, ShieldCheck } from "lucide-react";
import { apiFetch } from "./lib/api";

type Dataset = { dataset_id: string; original_filename: string; profile?: any };
type Experiment = { id: number; name: string; status: string; created_at: string; manifest: any };

async function payload(response: Response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : data.detail?.message ?? "Workspace request failed.");
  return data;
}

export default function UniversalWorkspace() {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [experiments, setExperiments] = useState<Experiment[]>([]);
  const [selected, setSelected] = useState("");
  const [target, setTarget] = useState("");
  const [experiment, setExperiment] = useState("");
  const [label, setLabel] = useState("label");
  const [datasetType, setDatasetType] = useState("auto");
  const [sourceUrl, setSourceUrl] = useState("");
  const [licence, setLicence] = useState("");
  const [retrievalDate, setRetrievalDate] = useState("");
  const [citation, setCitation] = useState("");
  const [nEstimators, setNEstimators] = useState(300);
  const [randomState, setRandomState] = useState(42);
  const [features, setFeatures] = useState("");
  const [dropColumns, setDropColumns] = useState("");
  const [model, setModel] = useState("random_forest");
  const [mapping, setMapping] = useState("");
  const [integration, setIntegration] = useState("zeek");
  const [profile, setProfile] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [d, e] = await Promise.all([
        payload(await apiFetch("/api/workspace/datasets")),
        payload(await apiFetch("/api/workspace/experiments")),
      ]);
      setDatasets(d.datasets ?? []);
      setExperiments(e.experiments ?? []);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not load local workspace."); }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function upload(file?: File) {
    if (!file) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const body = new FormData(); body.append("file", file);
      const query = new URLSearchParams({
        dataset_type: datasetType, source_url: sourceUrl, licence,
        retrieval_date: retrievalDate, citation,
      });
      const data = await payload(await apiFetch(`/api/workspace/datasets?${query.toString()}`, { method: "POST", body }));
      await refresh();
      setSelected(data.dataset_id); setTarget(data.dataset_id); setProfile(data);
    } catch (err) { setError(err instanceof Error ? err.message : "Upload failed."); }
    finally { setBusy(false); }
  }

  async function inspect() {
    if (!selected) return;
    setBusy(true); setError("");
    try { setProfile(await payload(await apiFetch(`/api/workspace/datasets/${selected}/profile`))); }
    catch (err) { setError(err instanceof Error ? err.message : "Inspection failed."); }
    finally { setBusy(false); }
  }

  async function train() {
    if (!selected) return;
    setBusy(true); setError(""); setResult(null);
    try {
      let label_mapping;
      if (mapping.trim()) label_mapping = JSON.parse(mapping);
      const data = await payload(await apiFetch("/api/workspace/train", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dataset_id: selected, label_column: label, model, label_mapping,
          feature_columns: features.trim() ? features.split(",").map(x => x.trim()).filter(Boolean) : null,
          drop_columns: dropColumns.trim() ? dropColumns.split(",").map(x => x.trim()).filter(Boolean) : null,
          n_estimators: nEstimators, random_state: randomState,
        }),
      }));
      setResult(data); setExperiment(String(data.experiment_id)); await refresh();
    } catch (err) { setError(err instanceof Error ? err.message : "Training failed."); }
    finally { setBusy(false); }
  }

  async function evaluate() {
    if (!experiment || !target) return;
    setBusy(true); setError(""); setResult(null);
    try {
      let label_mapping;
      if (mapping.trim()) label_mapping = JSON.parse(mapping);
      setResult(await payload(await apiFetch("/api/workspace/evaluate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ experiment_id: Number(experiment), dataset_id: target, label_column: label, label_mapping }),
      })));
    } catch (err) { setError(err instanceof Error ? err.message : "Evaluation failed."); }
    finally { setBusy(false); }
  }

  async function detect() {
    if (!experiment || !target) return;
    setBusy(true); setError(""); setResult(null);
    try { setResult(await payload(await apiFetch(`/api/workspace/detect/${experiment}?dataset_id=${target}`, { method: "POST" }))); }
    catch (err) { setError(err instanceof Error ? err.message : "Detection failed."); }
    finally { setBusy(false); }
  }

  async function ingest(file?: File) {
    if (!file) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const body = new FormData(); body.append("file", file);
      const data = await payload(await apiFetch(`/api/workspace/integrations/${integration}`, { method: "POST", body }));
      setResult(data);
      if (data.dataset_id) { setSelected(data.dataset_id); setTarget(data.dataset_id); await refresh(); }
    } catch (err) { setError(err instanceof Error ? err.message : "Integration import failed."); }
    finally { setBusy(false); }
  }

  return <div className="universal-workspace">
    <div className="uw-intro">
      <div><span className="uw-kicker">OPEN DATA · EXPERIMENT LAB</span><h2>Universal analyst workspace</h2>
        <p>Import public datasets, inspect schema and labels, train local models, test across datasets and export reproducible results.</p></div>
      <button className="secondary-btn" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button>
    </div>
    {error && <div className="uw-error" role="alert"><AlertTriangle size={16}/>{error}</div>}
    <div className="uw-grid">
      <section className="panel uw-panel">
        <div className="panel-head"><div><div className="panel-kicker">01 · DATA INGESTION</div><h3>Datasets</h3><p>CSV, Parquet or Feather · up to 100 MB per file</p></div><Database size={19}/></div>
        <label className="uw-upload"><FileUp size={20}/><b>{busy ? "Working…" : "Choose dataset file"}</b><span>Files are stored in the local workspace</span>
          <input type="file" accept=".csv,.parquet,.pq,.feather,.arrow" disabled={busy} onChange={e => { void upload(e.target.files?.[0]); e.currentTarget.value = ""; }}/>
        </label>
        <label className="uw-label">Dataset family</label>
        <select value={datasetType} onChange={e => setDatasetType(e.target.value)}>
          <option value="auto">Auto-detect</option><option value="cic-ids2017">CIC-IDS2017</option>
          <option value="unsw-nb15">UNSW-NB15</option><option value="ton-iot">ToN-IoT</option>
          <option value="bot-iot">Bot-IoT</option><option value="cse-cic-ids2018">CSE-CIC-IDS2018</option>
          <option value="ciciot2023">CICIoT2023</option><option value="generic">Generic</option>
        </select>
        <label className="uw-label">Source URL (optional)</label><input value={sourceUrl} onChange={e => setSourceUrl(e.target.value)} placeholder="https://dataset-provider.example/source"/>
        <label className="uw-label">Dataset licence (optional)</label><input value={licence} onChange={e => setLicence(e.target.value)} placeholder="CC BY 4.0 / provider terms"/>
        <label className="uw-label">Retrieval date (optional)</label><input value={retrievalDate} onChange={e => setRetrievalDate(e.target.value)} placeholder="YYYY-MM-DD"/>
        <label className="uw-label">Citation (optional)</label><input value={citation} onChange={e => setCitation(e.target.value)} placeholder="Dataset paper or DOI"/>
        <label className="uw-label">Training dataset</label>
        <select value={selected} onChange={e => setSelected(e.target.value)}><option value="">Select dataset</option>{datasets.map(d=><option key={d.dataset_id} value={d.dataset_id}>{d.original_filename}</option>)}</select>
        <button className="secondary-btn" disabled={!selected || busy} onClick={() => void inspect()}>Inspect selected dataset</button>
        {profile && <div className="uw-profile">
          <div className="uw-stat-row"><span>Rows</span><b>{Number(profile.rows ?? 0).toLocaleString()}</b><span>Numeric features</span><b>{profile.numeric_columns ?? "—"}</b></div>
          <div className="uw-stat-row"><span>Label field</span><b>{profile.label_column ?? "None"}</b><span>Duplicate rows</span><b>{profile.duplicate_rows ?? "—"}</b></div>
          <small>SHA-256: {profile.sha256 ?? "available in dataset manifest"}</small>
          {profile.label_distribution && <div className="uw-labels">{Object.entries(profile.label_distribution).slice(0,12).map(([name,count])=><span key={name}>{name}<b>{Number(count).toLocaleString()}</b></span>)}</div>}
          {Array.isArray(profile.schema) && <div className="uw-schema"><b>Schema preview</b><div className="uw-schema-scroll"><table><thead><tr><th>Feature</th><th>Type</th><th>Missing</th><th>Unique</th></tr></thead><tbody>{profile.schema.slice(0,20).map((column:any)=><tr key={column.name}><td>{column.name}</td><td>{column.dtype}</td><td>{column.missing}</td><td>{column.unique}</td></tr>)}</tbody></table></div></div>}
        </div>}
      </section>

      <section className="panel uw-panel">
        <div className="panel-head"><div><div className="panel-kicker">02 · MODEL EXPERIMENT</div><h3>Train a model</h3><p>Configurable target taxonomy and feature selection</p></div><FlaskConical size={19}/></div>
        <label className="uw-label">Model family</label>
        <select value={model} onChange={e => setModel(e.target.value)}>
          <option value="random_forest">Random Forest</option><option value="xgboost">XGBoost · optional</option>
          <option value="isolation_forest">Isolation Forest · unsupervised</option><option value="pytorch_mlp">PyTorch MLP · optional</option>
        </select>
        <label className="uw-label">Label column</label><input value={label} onChange={e => setLabel(e.target.value)} placeholder="label"/>
        <label className="uw-label">Number of estimators</label><input type="number" min={10} max={2000} value={nEstimators} onChange={e => setNEstimators(Number(e.target.value))}/>
        <label className="uw-label">Random seed</label><input type="number" value={randomState} onChange={e => setRandomState(Number(e.target.value))}/>
        <label className="uw-label">Feature allow-list (comma-separated, optional)</label>
        <input value={features} onChange={e => setFeatures(e.target.value)} placeholder="Flow Duration, Protocol, Destination Port"/>
        <label className="uw-label">Drop columns (comma-separated, optional)</label>
        <input value={dropColumns} onChange={e => setDropColumns(e.target.value)} placeholder="Flow ID, Timestamp, Source IP"/>
        <label className="uw-label">Explicit label mapping (JSON, optional)</label>
        <textarea value={mapping} onChange={e => setMapping(e.target.value)} placeholder={'{"Normal":"BENIGN","DoS":"DOS"}'} rows={3}/>
        <button className="primary-btn" disabled={!selected || busy} onClick={() => void train()}><FlaskConical size={15}/> Train experiment</button>
        <p className="uw-hint">Mapping is never inferred. Unknown labels fail validation rather than being silently discarded.</p>
      </section>

      <section className="panel uw-panel">
        <div className="panel-head"><div><div className="panel-kicker">03 · DOMAIN SHIFT</div><h3>Cross-dataset evaluation</h3><p>Evaluate a trained model on a separate dataset</p></div><Activity size={19}/></div>
        <label className="uw-label">Trained experiment</label>
        <select value={experiment} onChange={e => setExperiment(e.target.value)}><option value="">Select experiment</option>{experiments.filter(e=>e.status==="COMPLETED" && !e.name.startsWith("cross-eval:") && !e.name.startsWith("detection:")).map(e=><option key={e.id} value={e.id}>#{e.id} · {e.name}</option>)}</select>
        <label className="uw-label">Target dataset</label>
        <select value={target} onChange={e => setTarget(e.target.value)}><option value="">Select target dataset</option>{datasets.map(d=><option key={d.dataset_id} value={d.dataset_id}>{d.original_filename}</option>)}</select>
        <div className="uw-actions"><button className="secondary-btn" disabled={!experiment || !target || busy} onClick={() => void evaluate()}>Evaluate transfer</button><button className="secondary-btn" disabled={!experiment || !target || busy} onClick={() => void detect()}><ShieldCheck size={14}/> Run detection</button></div>
      </section>

      <section className="panel uw-panel">
        <div className="panel-head"><div><div className="panel-kicker">04 · EXPERIMENT REGISTRY</div><h3>Local experiment history</h3><p>Model hashes, configuration and dataset provenance</p></div><Database size={19}/></div>
        {experiments.length ? experiments.slice(0,8).map(item=><button className="uw-experiment" key={item.id} onClick={()=>setExperiment(String(item.id))}><span><b>#{item.id} · {item.name}</b><small>{item.created_at}</small></span><em>{item.status}</em></button>) : <p className="uw-hint">No experiments yet. Train a model to create a reproducible record.</p>}
      </section>
      <section className="panel uw-panel">
        <div className="panel-head"><div><div className="panel-kicker">05 · OPEN-SOURCE TELEMETRY</div><h3>Security integrations</h3><p>Import event logs and Sigma rule metadata</p></div><ShieldCheck size={19}/></div>
        <label className="uw-label">Source format</label>
        <select value={integration} onChange={e => setIntegration(e.target.value)}>
          <option value="zeek">Zeek conn.log</option><option value="suricata">Suricata EVE JSONL</option>
          <option value="wazuh">Wazuh alerts JSON</option><option value="sigma">Sigma YAML rule</option>
        </select>
        <label className="uw-upload"><FileUp size={20}/><b>Import {integration} file</b><span>Converted telemetry becomes a local dataset; Sigma is imported as rule metadata</span>
          <input type="file" accept={integration === "sigma" ? ".yml,.yaml" : integration === "zeek" ? ".log,.txt" : ".json,.jsonl"} disabled={busy} onChange={e => { void ingest(e.target.files?.[0]); e.currentTarget.value = ""; }}/>
        </label>
        <p className="uw-hint">Import does not execute Sigma rules, capture live packets, or change firewall settings.</p>
      </section>
    </div>
    {result && <section className="panel uw-result">
      <div className="panel-head"><div><div className="panel-kicker">LATEST RESULT</div><h3>Experiment output</h3></div>
        {result.export && <a className="secondary-btn" href={result.export}><ArrowDownToLine size={14}/> Export CSV</a>}
        {result.alerts_export && <a className="secondary-btn" href={result.alerts_export}><ArrowDownToLine size={14}/> Export alerts</a>}
      </div>
      <pre>{JSON.stringify(result, null, 2)}</pre>
    </section>}
    <p className="uw-footnote">Privacy boundary: this workspace stores files, models and experiment history on the machine running the API. Hosted serverless storage is ephemeral. Do not upload private telemetry to a public deployment.</p>
  </div>;
}

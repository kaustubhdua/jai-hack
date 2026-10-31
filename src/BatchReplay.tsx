import { useState } from "react";
import { apiFetch } from "./lib/api";
import Papa from "papaparse";
import { Activity, FileSpreadsheet, Play, UploadCloud } from "lucide-react";

type ReplayRow = {
  final_class: string | null;
  action: "ALLOW" | "BLOCK" | "REVIEW";
  evidence_status: string;
  rationale: string[];
};

type BatchResponse = {
  total_analyzed: number;
  actions: Record<"ALLOW" | "BLOCK" | "REVIEW", number>;
  results: ReplayRow[];
  class_counts: Record<string, number>;
  supabase_persistence?: { stored: boolean; rows?: number; reason?: string; flow_events?: { stored: boolean; rows?: number; reason?: string }; agent2_rows?: number };
};

export function BatchReplay({ modelReady }: { modelReady: boolean }) {
  const [fileName, setFileName] = useState("");
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<BatchResponse | null>(null);

  function selectFile(file?: File) {
    if (!file) return;
    setError("");
    setSummary(null);
    setRows([]);
    setProgress(0);
    setFileName(file.name);
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setError("Choose a CSV file containing one network-flow record per row.");
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      setError("CSV exceeds the 100 MB browser replay limit.");
      return;
    }
    Papa.parse<Record<string, unknown>>(file, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: "greedy",
      complete: result => {
        const data = result.data.filter(row => row && Object.keys(row).length > 0);
        if (!data.length) {
          setError("The CSV contains no usable data rows.");
          return;
        }
        if (result.errors.length) {
          setError("CSV parser reported " + result.errors.length + " issue(s). Inspect the file before replay.");
          return;
        }
        setRows(data);
      },
      error: reason => setError(reason.message || "Could not parse the CSV file."),
    });
  }

  async function replay() {
    if (!rows.length || !modelReady) return;
    setBusy(true);
    setError("");
    setSummary(null);
    setProgress(0);
    const aggregate: BatchResponse = {
      total_analyzed: 0,
      actions: { ALLOW: 0, BLOCK: 0, REVIEW: 0 },
      results: [],
      class_counts: {},
      supabase_persistence: { stored: true, rows: 0 },
    };
    try {
      const chunkSize = 1000;
      for (let offset = 0; offset < rows.length; offset += chunkSize) {
        const chunk = rows.slice(offset, offset + chunkSize);
        const response = await apiFetch("/api/analyze/batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flows: chunk }),
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(String(payload?.detail?.message ?? payload?.detail ?? "Batch replay failed."));
        }
        aggregate.total_analyzed += Number(payload.total_analyzed || 0);
        const persistence = payload.supabase_persistence;
        if (!persistence?.stored) {
          aggregate.supabase_persistence = { stored: false, reason: persistence?.reason || "not_confirmed" };
        } else if (aggregate.supabase_persistence?.stored) {
          aggregate.supabase_persistence.rows = Number(aggregate.supabase_persistence.rows || 0) + Number(persistence.flow_events?.rows || 0) + Number(persistence.agent2_rows || 0);
        }
        for (const action of ["ALLOW", "BLOCK", "REVIEW"] as const) {
          aggregate.actions[action] += Number(payload.actions?.[action] || 0);
        }
        for (const row of (payload.results || []) as ReplayRow[]) {
          const className = row.final_class ?? "UNCONFIRMED";
          aggregate.class_counts[className] = (aggregate.class_counts[className] || 0) + 1;
          if (aggregate.results.length < 20) aggregate.results.push(row);
        }
        setProgress(Math.min(rows.length, offset + chunk.length));
        setSummary({ ...aggregate, results: [...aggregate.results], class_counts: { ...aggregate.class_counts } });
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Batch replay stopped unexpectedly.");
    } finally {
      setBusy(false);
    }
  }

  const classes = summary?.class_counts ?? {};

  return <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
    <div className="panel-head">
      <div><div className="panel-kicker">OFFLINE DATASET REPLAY</div><h3>Batch flow analysis</h3>
        <p>Load a real CSV and replay it through the trained agents in bounded batches. Flow records are processed in this browser session only.</p></div>
      <span className="panel-icon"><FileSpreadsheet size={18}/></span>
    </div>
    <label className="upload-zone" style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}>
      <UploadCloud size={20}/><span><b>{fileName || "Choose a flow CSV"}</b><small>{rows.length ? rows.length.toLocaleString() + " rows parsed" : "CSV only · up to 100 MB"}</small></span>
      <input type="file" accept=".csv,text/csv" onChange={event => selectFile(event.target.files?.[0])} hidden />
    </label>
    <div className="panel-foot">
      <span><Activity size={13}/> {progress.toLocaleString()} / {rows.length.toLocaleString()} rows processed</span>
      <button className="primary-btn" disabled={!modelReady || !rows.length || busy} onClick={replay}>
        <Play size={14}/>{busy ? "Replaying…" : "Run batch replay"}
      </button>
    </div>
    {rows.length > 0 && <div className="progress-track"><div className="progress-value" style={{ width: (progress / rows.length * 100) + "%" }}/></div>}
    {!modelReady && <div className="empty-inline">Batch inference remains disabled until both trained model artifacts are deployed and verified.</div>}
    {error && <div className="parse-warning" role="alert">{error}</div>}
    {summary && <div className="dataset-loaded" style={{ marginTop: 18 }}>
      <div className="dataset-facts">
        <div><small>PROCESSED</small><b>{summary.total_analyzed.toLocaleString()}</b></div>
        <div><small>ALLOW</small><b>{summary.actions.ALLOW.toLocaleString()}</b></div>
        <div><small>BLOCK</small><b>{summary.actions.BLOCK.toLocaleString()}</b></div>
        <div><small>REVIEW</small><b>{summary.actions.REVIEW.toLocaleString()}</b></div>
      </div>
      <b>Predicted classes</b>
      <div className="class-counts">{Object.entries(classes).map(([label, count]) => <span key={label}>{label}<b>{count.toLocaleString()}</b></span>)}</div>
      <div className="table-scroll"><table><thead><tr><th>#</th><th>Final class</th><th>Action</th><th>Evidence</th></tr></thead>
        <tbody>{summary.results.slice(0, 20).map((row, index) => <tr key={index}><td>{index + 1}</td><td>{row.final_class ?? "Unconfirmed"}</td><td>{row.action}</td><td>{row.evidence_status}</td></tr>)}</tbody>
      </table></div>
      <div className="empty-inline" style={{ marginTop: 12 }}>Supabase audit: {summary.supabase_persistence?.stored ? `${Number(summary.supabase_persistence.rows || 0).toLocaleString()} derived flow events saved to your private account.` : `Cloud persistence was not confirmed (${summary.supabase_persistence?.reason || "not reported"}).`}</div>
      <small>Showing the first 20 of {summary.total_analyzed.toLocaleString()} processed rows. Raw CSV data stays in this browser session; only derived analysis metadata is stored in Supabase.</small>
    </div>}
  </section>;
}

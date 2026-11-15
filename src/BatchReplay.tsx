import { useState } from "react";
import { apiErrorMessage, apiFetch, readApiPayload } from "./lib/api";
import Papa from "papaparse";
import { Activity, FileSpreadsheet, Play, UploadCloud } from "lucide-react";
import { InferenceLoader, holdLoaderForMinimum } from "./components/InferenceLoader";

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
};

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_API_BATCH = 1000;
const PARSE_CHUNK_BYTES = 256 * 1024;

function emptySummary(): BatchResponse {
  return {
    total_analyzed: 0,
    actions: { ALLOW: 0, BLOCK: 0, REVIEW: 0 },
    results: [],
    class_counts: {},
  };
}

export function BatchReplay({ modelReady }: { modelReady: boolean }) {
  const [fileName, setFileName] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileReady, setFileReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [parsing, setParsing] = useState(false);
  const [parsedRows, setParsedRows] = useState(0);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<BatchResponse | null>(null);

  function selectFile(file?: File) {
    if (!file || busy || parsing) return;
    setError("");
    setSummary(null);
    setSelectedFile(null);
    setFileReady(false);
    setProgress(0);
    setParsedRows(0);
    setFileName(file.name);

    if (!file.name.toLowerCase().endsWith(".csv")) {
      setError("Choose a CSV file containing one network-flow record per row.");
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError("CSV exceeds the 100 MB browser replay limit.");
      return;
    }
    if (file.size === 0) {
      setError("The selected CSV file is empty.");
      return;
    }

    setSelectedFile(file);
    setParsing(true);
    let rowCount = 0;
    let parserErrorCount = 0;
    let hasHeader = false;

    // Pass one validates the local file without retaining parsed records.
    Papa.parse<Record<string, unknown>>(file, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: "greedy",
      worker: true,
      chunk: result => {
        if (!hasHeader) hasHeader = Boolean(result.meta.fields?.length);
        for (const row of result.data) {
          if (row && Object.keys(row).length > 0) rowCount += 1;
        }
        parserErrorCount += result.errors.length;
        setParsedRows(rowCount);
      },
      complete: () => {
        setParsing(false);
        if (!hasHeader || rowCount === 0) {
          setSelectedFile(null);
          setError("The CSV must contain a header row and at least one non-empty data row.");
          return;
        }
        if (parserErrorCount > 0) {
          setSelectedFile(null);
          setError("CSV parser reported " + parserErrorCount + " issue(s). Fix the file before replay.");
          return;
        }
        setFileReady(true);
      },
      error: reason => {
        setParsing(false);
        setSelectedFile(null);
        setError(reason.message || "Could not parse the CSV file.");
      },
    });
  }

  async function replay() {
    if (!selectedFile || !fileReady || !modelReady || busy || parsing) return;

    const loadingStartedAt = Date.now();
    const aggregate = emptySummary();
    let finished = false;
    let parsedDuringReplay = 0;

    setBusy(true);
    setError("");
    setSummary(null);
    setProgress(0);

    const publishSummary = () => {
      setSummary({
        ...aggregate,
        actions: { ...aggregate.actions },
        results: [...aggregate.results],
        class_counts: { ...aggregate.class_counts },
      });
    };

    const finish = async (message?: string) => {
      if (finished) return;
      finished = true;
      if (message) {
        setError(message + (aggregate.total_analyzed > 0
          ? " Completed " + aggregate.total_analyzed.toLocaleString() + " of " + parsedRows.toLocaleString() + " validated rows before stopping."
          : ""));
      }
      publishSummary();
      await holdLoaderForMinimum(loadingStartedAt);
      setBusy(false);
    };

    const stop = (parser: Papa.Parser, message: string) => {
      if (finished) return;
      // Mark the operation finished before aborting: Papa may invoke complete
      // immediately for an aborted parse, and the original error must win.
      void finish(message);
      parser.abort();
    };

    async function submitRows(chunkRows: Record<string, unknown>[]) {
      for (let offset = 0; offset < chunkRows.length; offset += MAX_API_BATCH) {
        const batch = chunkRows.slice(offset, offset + MAX_API_BATCH);
        const response = await apiFetch("/api/analyze/batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flows: batch }),
        });
        const payload = await readApiPayload<Partial<BatchResponse> & { detail?: unknown }>(response);
        if (!response.ok) throw new Error(apiErrorMessage(payload, "Batch replay failed."));
        if (
          !payload ||
          payload.total_analyzed !== batch.length ||
          !payload.actions ||
          !Array.isArray(payload.results) ||
          payload.results.length !== batch.length
        ) {
          throw new Error("The batch API returned an incomplete result. No further rows were submitted.");
        }
        const actionCounts = payload.actions;
        const actionTotal = Number(actionCounts.ALLOW) + Number(actionCounts.BLOCK) + Number(actionCounts.REVIEW);
        if (
          ![actionCounts.ALLOW, actionCounts.BLOCK, actionCounts.REVIEW].every(value => Number.isInteger(value) && value >= 0) ||
          actionTotal !== batch.length
        ) {
          throw new Error("The batch API returned inconsistent action totals. No further rows were submitted.");
        }

        aggregate.total_analyzed += payload.total_analyzed;
        for (const action of ["ALLOW", "BLOCK", "REVIEW"] as const) {
          aggregate.actions[action] += actionCounts[action];
        }
        for (const row of payload.results as ReplayRow[]) {
          const className = row.final_class ?? "UNCONFIRMED";
          aggregate.class_counts[className] = (aggregate.class_counts[className] || 0) + 1;
          if (aggregate.results.length < 20) aggregate.results.push(row);
        }
        setProgress(aggregate.total_analyzed);
        publishSummary();
      }
    }

    // Pass two streams bounded file chunks. Parsing pauses while each chunk is
    // submitted, so raw CSV rows are never accumulated into a full-file array.
    Papa.parse<Record<string, unknown>>(selectedFile, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: "greedy",
      worker: false,
      chunkSize: PARSE_CHUNK_BYTES,
      chunk: (result, parser) => {
        parser.pause();
        if (result.errors.length > 0) {
          stop(parser, "CSV parsing reported " + result.errors.length + " issue(s) during replay. Check the file and retry.");
          return;
        }
        const chunkRows = result.data.filter(row => row && Object.keys(row).length > 0);
        parsedDuringReplay += chunkRows.length;
        if (chunkRows.length === 0) {
          parser.resume();
          return;
        }
        void submitRows(chunkRows)
          .then(() => {
            if (!finished) parser.resume();
          })
          .catch(reason => {
            stop(parser, reason instanceof Error ? reason.message : "Batch replay stopped unexpectedly.");
          });
      },
      complete: result => {
        if (finished) return;
        if (result.meta.aborted) {
          void finish("Batch replay was stopped before the file was fully processed.");
          return;
        }
        if (parsedDuringReplay !== parsedRows) {
          void finish("The CSV changed between validation and replay; parsed row counts did not match. Select the file again.");
          return;
        }
        void finish();
      },
      error: reason => {
        void finish(reason.message || "Could not read the CSV during replay.");
      },
    });
  }

  const classes = summary?.class_counts ?? {};

  return <section className="panel dataset-panel" style={{ marginBottom: 22 }}>
    <div className="panel-head">
      <div><div className="panel-kicker">OFFLINE DATASET REPLAY</div><h3>Batch flow analysis</h3>
        <p>Validate a real CSV, then stream its rows to the public inference API in bounded batches. The original CSV file is not uploaded as a single file.</p></div>
      <span className="panel-icon"><FileSpreadsheet size={18}/></span>
    </div>
    <label className="upload-zone" style={{ display: "flex", alignItems: "center", gap: 12, cursor: busy || parsing ? "not-allowed" : "pointer" }}>
      <UploadCloud size={20}/><span><b>{fileName || "Choose a flow CSV"}</b><small>{fileReady ? parsedRows.toLocaleString() + " rows validated · ready to replay" : "CSV only · up to 100 MB"}</small></span>
      <input type="file" accept=".csv,text/csv" disabled={parsing || busy} onChange={event => { selectFile(event.target.files?.[0]); event.currentTarget.value = ""; }} hidden />
    </label>
    {parsing && <div className="csv-processing" role="status" aria-live="polite" aria-atomic="true">
      <span className="csv-processing-spinner" aria-hidden="true" />
      <div><b>Validating CSV locally</b><span>{parsedRows.toLocaleString()} rows checked in a background worker…</span></div>
      <div className="csv-processing-track indeterminate" aria-hidden="true"><i /></div>
    </div>}
    <div className="panel-foot">
      <span><Activity size={13}/> {progress.toLocaleString()} / {parsedRows.toLocaleString()} rows processed</span>
      <button className="primary-btn" disabled={!modelReady || !fileReady || busy || parsing} onClick={replay}>
        <Play size={14}/>{busy ? "Replaying…" : "Run batch replay"}
      </button>
    </div>
    {busy && <InferenceLoader compact title="Streaming chronological batch inference" detail={progress.toLocaleString() + " of " + parsedRows.toLocaleString() + " validated rows completed. Each bounded batch is confirmed by the backend before the next is read."} />}
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
      <div className="empty-inline" style={{ marginTop: 12 }}>Batch inference is stateless. Results are returned to this browser; no cloud database or account is used.</div>
      <small>Showing the first 20 of {summary.total_analyzed.toLocaleString()} processed rows. No cloud audit database is used. Raw CSV rows are streamed from the browser in bounded batches.</small>
    </div>}
  </section>;
}

import { useState } from "react";
import { api, type BaselineRow, type RegressionResult } from "../api";
import { Empty, ErrorState, Loading, SeverityChip } from "../components";
import { useAsync } from "../hooks";
import { scanLabel } from "./scanpick";

export function Regression() {
  const scans = useAsync(() => api.listScans(), []);
  const baselines = useAsync(() => api.listBaselines(), []);
  const completed = (scans.data || []).filter((s) => s.status === "completed");

  const [scanForBaseline, setScanForBaseline] = useState("");
  const [baselineName, setBaselineName] = useState("");
  const [compareScan, setCompareScan] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [failOn, setFailOn] = useState("high");
  const [result, setResult] = useState<RegressionResult | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (scans.loading || baselines.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;

  const defScanForBaseline = scanForBaseline || completed[0]?.id || "";
  const defCompareScan = compareScan || completed[0]?.id || "";
  const rows = baselines.data || [];
  const defBaseline = baselineId || rows[0]?.id || "";

  const create = async () => {
    setErr(null); setMsg(null);
    try {
      const b = await api.createBaseline(defScanForBaseline, baselineName || "baseline");
      setMsg(`Baseline “${b.name}” created (${b.violation_count} recorded violation(s)).`);
      baselines.reload();
    } catch (e) { setErr((e as Error).message); }
  };

  const compare = async () => {
    setErr(null); setResult(null);
    try {
      setResult(await api.regression(defBaseline, defCompareScan, failOn));
    } catch (e) { setErr((e as Error).message); }
  };

  return (
    <>
      <div className="page-head">
        <h1>Regression testing</h1>
        <p>Snapshot a clean scan as a baseline, then compare a later scan against it. A boundary that changes from
          <strong> BLOCKED</strong> to <strong> VIOLATION</strong> is a new authorization regression — the same check a
          CI gate uses to fail a build.</p>
      </div>

      {!completed.length ? (
        <Empty message="Run at least one scan first." />
      ) : (
        <div className="grid cols-2">
          <div className="card">
            <h2>1 · Create baseline</h2>
            <label>From scan (use a clean / fixed run)</label>
            <select value={defScanForBaseline} onChange={(e) => setScanForBaseline(e.target.value)}>
              {completed.map((s) => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
            </select>
            <label style={{ marginTop: 10 }}>Baseline name</label>
            <input type="text" value={baselineName} placeholder="e.g. release-1.4-clean"
              onChange={(e) => setBaselineName(e.target.value)} />
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn-primary" onClick={create}>Create baseline</button>
            </div>
            {msg && <div className="banner" style={{ marginTop: 12 }}>{msg}</div>}
            <div className="divider" />
            <div className="card-label">Existing baselines</div>
            {rows.length ? rows.map((b: BaselineRow) => (
              <div key={b.id} className="row-between" style={{ padding: "4px 0" }}>
                <span>{b.name} <span className="faint">· {b.violation_count} violations</span></span>
                <span className="faint mono" style={{ fontSize: 11 }}>{new Date(b.created_at).toLocaleString()}</span>
              </div>
            )) : <span className="faint">None yet.</span>}
          </div>

          <div className="card">
            <h2>2 · Compare a scan</h2>
            <label>Baseline</label>
            <select value={defBaseline} onChange={(e) => setBaselineId(e.target.value)}>
              {rows.length ? rows.map((b) => <option key={b.id} value={b.id}>{b.name} ({b.violation_count})</option>)
                : <option value="">— create one first —</option>}
            </select>
            <label style={{ marginTop: 10 }}>Candidate scan</label>
            <select value={defCompareScan} onChange={(e) => setCompareScan(e.target.value)}>
              {completed.map((s) => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
            </select>
            <label style={{ marginTop: 10 }}>Fail on severity ≥</label>
            <select value={failOn} onChange={(e) => setFailOn(e.target.value)}>
              {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn-primary" onClick={compare} disabled={!defBaseline}>Compare</button>
            </div>
            {err && <div className="error-state" style={{ padding: "10px 0" }}>⚠ {err}</div>}
          </div>
        </div>
      )}

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="row-between">
            <h2 style={{ margin: 0 }}>Result</h2>
            <span className={`chip ${result.passed ? "confirmed" : "sev-high"}`}>
              {result.passed ? "GATE PASS" : `GATE FAIL · ${result.gating_regressions.length} regression(s) ≥ ${result.fail_on}`}
            </span>
          </div>
          <RegList title="New regressions" tone="high" rows={result.regressions} />
          <RegList title="Fixed since baseline" tone="low" rows={result.fixed} />
          {!result.regressions.length && !result.fixed.length &&
            <Empty message="No authorization changes versus the baseline." />}
        </div>
      )}
    </>
  );
}

function RegList({ title, tone, rows }: { title: string; tone: string; rows: any[] }) {
  if (!rows.length) return null;
  return (
    <>
      <h3 style={{ marginTop: 16 }}>{title} <span className={`chip sev-${tone}`}>{rows.length}</span></h3>
      <table>
        <thead><tr><th>Severity</th><th>Check</th><th>Endpoint</th><th>Identity</th><th>Change</th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td><SeverityChip severity={r.severity} /></td>
              <td>{r.check_id}</td>
              <td className="mono faint">{r.method} {r.route}</td>
              <td className="mono">{r.identity}</td>
              <td><span className="faint">{r.previous_status}</span> → <strong>{r.current_status}</strong></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

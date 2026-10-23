import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type Compare, type Finding } from "../api";
import { Empty, ErrorState, Loading, SeverityChip } from "../components";
import { useAsync } from "../hooks";

export function Baseline() {
  const navigate = useNavigate();
  const scans = useAsync(() => api.listScans(), []);
  const completed = (scans.data || []).filter((s) => s.status === "completed");
  const [baseline, setBaseline] = useState("");
  const [candidate, setCandidate] = useState("");
  const [cmp, setCmp] = useState<Compare | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Default: newest vulnerable scan vs newest fixed scan.
  const defBaseline = baseline || completed.find((s) => s.configuration === "vulnerable")?.id || completed[0]?.id || "";
  const defCandidate = candidate || completed.find((s) => s.configuration === "fixed")?.id || completed[1]?.id || "";

  const compare = async () => {
    setBusy(true); setError(null); setCmp(null);
    try {
      setCmp(await api.compare(defBaseline, defCandidate));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (scans.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;

  return (
    <>
      <div className="page-head">
        <h1>Baseline comparison</h1>
        <p>Compare a baseline scan (typically the vulnerable configuration) against a candidate scan (the fixed
          configuration) to see which confirmed findings are resolved, which persist, and which are newly observed.</p>
      </div>

      {completed.length < 2 ? (
        <Empty message="Run at least two completed scans (e.g. vulnerable and fixed) to compare." />
      ) : (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="grid cols-2">
              <div>
                <label>Baseline scan</label>
                <select value={defBaseline} onChange={(e) => setBaseline(e.target.value)}>
                  {completed.map((s) => <option key={s.id} value={s.id}>{s.configuration} · {new Date(s.created_at).toLocaleString()}</option>)}
                </select>
              </div>
              <div>
                <label>Candidate scan</label>
                <select value={defCandidate} onChange={(e) => setCandidate(e.target.value)}>
                  {completed.map((s) => <option key={s.id} value={s.id}>{s.configuration} · {new Date(s.created_at).toLocaleString()}</option>)}
                </select>
              </div>
            </div>
            <div className="btn-row" style={{ marginTop: 16 }}>
              <button className="btn-primary" onClick={compare} disabled={busy || defBaseline === defCandidate}>
                {busy ? "Comparing…" : "Compare"}
              </button>
              {defBaseline === defCandidate && <span className="faint">Pick two different scans.</span>}
            </div>
            {error && <div className="error-state" style={{ padding: "12px 0" }}>⚠ {error}</div>}
          </div>

          {cmp && (
            <div className="grid cols-3">
              <DiffColumn title="Resolved" sub="In baseline, gone in candidate" tone="ok" findings={cmp.resolved}
                onOpen={(f) => navigate(`/scans/${cmp.baseline.id}/findings/${f.finding_id}`)} />
              <DiffColumn title="Persisting" sub="Present in both scans" tone="high" findings={cmp.persisting}
                onOpen={(f) => navigate(`/scans/${cmp.candidate.id}/findings/${f.finding_id}`)} />
              <DiffColumn title="Newly observed" sub="Only in candidate" tone="medium" findings={cmp.new}
                onOpen={(f) => navigate(`/scans/${cmp.candidate.id}/findings/${f.finding_id}`)} />
            </div>
          )}
        </>
      )}
    </>
  );
}

function DiffColumn({ title, sub, tone, findings, onOpen }:
  { title: string; sub: string; tone: string; findings: Finding[]; onOpen: (f: Finding) => void }) {
  return (
    <div className="card">
      <div className="row-between">
        <h3 style={{ margin: 0 }}>{title}</h3>
        <span className={`chip sev-${tone}`}>{findings.length}</span>
      </div>
      <div className="faint" style={{ fontSize: 12, marginBottom: 10 }}>{sub}</div>
      {findings.length ? (
        findings.map((f) => (
          <div key={f.finding_id} className="clickable" onClick={() => onOpen(f)}
            style={{ padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
            <div className="row-between"><strong style={{ fontSize: 13 }}>{f.title}</strong><SeverityChip severity={f.severity} /></div>
            <div className="faint mono" style={{ fontSize: 12 }}>{f.method} {f.route} · {f.actor_identity}</div>
          </div>
        ))
      ) : (
        <div className="faint" style={{ fontSize: 13 }}>None.</div>
      )}
    </div>
  );
}

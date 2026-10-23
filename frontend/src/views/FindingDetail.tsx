import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, type Finding, type ReplayResult, type Scan } from "../api";
import { ConfirmationChip, Empty, ErrorState, EvidenceView, Loading, SeverityChip } from "../components";
import { useAsync } from "../hooks";

export function FindingDetail() {
  const { scanId, findingId } = useParams();
  const navigate = useNavigate();
  const scan = useAsync<Scan>(() => api.getScan(scanId!), [scanId]);

  if (scan.loading) return <Loading />;
  if (scan.error) return <ErrorState message={scan.error} />;
  const finding = scan.data?.result?.findings.find((f) => f.finding_id === findingId);
  if (!finding) return <Empty message="Finding not found." />;

  return (
    <>
      <div className="page-head">
        <button className="btn-sm" onClick={() => navigate(-1)}>← Back</button>
        <div className="row-between" style={{ marginTop: 12 }}>
          <h1>{finding.title}</h1>
          <span className="btn-row">
            <SeverityChip severity={finding.severity} />
            <ConfirmationChip confirmation={finding.confirmation} />
          </span>
        </div>
        <p className="mono faint">{finding.finding_id} · {finding.check_id} · {finding.cwe}</p>
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h2>Expected vs. observed</h2>
          <dl className="kv">
            <dt>Endpoint</dt><dd className="mono">{finding.method} {finding.route}</dd>
            <dt>Actor identity</dt><dd className="mono">{finding.actor_identity}</dd>
            <dt>Expected rule</dt><dd>{finding.expected_rule}</dd>
            <dt>Expected behavior</dt><dd>{finding.expected_behavior}</dd>
            <dt>Observed behavior</dt><dd>{finding.observed_behavior}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>Assessment</h2>
          <dl className="kv">
            <dt>Severity</dt><dd>{finding.severity} — {finding.severity_rationale}</dd>
            <dt>Remediation</dt><dd>{finding.remediation}</dd>
            <dt>Limitations</dt><dd>{finding.limitations}</dd>
          </dl>
        </div>
      </div>

      {finding.confirmation === "confirmed" && scan.data!.result && (
        <ReplayPanel scanId={scanId!} finding={finding} localDemo />
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <h2>Primary evidence (sanitized)</h2>
        <EvidenceView evidence={finding.evidence} />
      </div>

      {finding.instances.length > 0 && (
        <div className="card">
          <h2>Affected instances ({finding.instance_count})</h2>
          {finding.instances.map((inst, i) => (
            <details className="evidence" key={i}>
              <summary>
                <span className="mono">{inst.method} {inst.path || inst.observation}</span>
                {inst.status != null && <> → HTTP {inst.status}</>}
                {inst.markers_found?.length ? <> · markers {inst.markers_found.join(", ")}</> : null}
              </summary>
              <div>{inst.evidence ? <EvidenceView evidence={inst.evidence} /> : <p className="faint">No request evidence.</p>}</div>
            </details>
          ))}
        </div>
      )}
    </>
  );
}

function ReplayPanel({ scanId, finding }: { scanId: string; finding: Finding; localDemo: boolean }) {
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const replayable = finding.instances.some((i) => i.path);

  const run = async () => {
    setBusy(true); setError(null);
    try {
      setResult(await api.replay(scanId, finding.finding_id, 0));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="row-between">
        <h2 style={{ margin: 0 }}>Local demo replay</h2>
        <button className="btn-primary btn-sm" onClick={run} disabled={busy || !replayable}>
          {busy ? "Replaying…" : "Replay against local demo"}
        </button>
      </div>
      <p className="muted" style={{ marginTop: 8 }}>
        Re-issues this request against the local demo. Authentication is resolved server-side from the configured
        identity; no credentials appear in the request or result.
      </p>
      {!replayable && <p className="faint">This finding has no replayable request instance.</p>}
      {error && <div className="error-state" style={{ padding: "12px 0" }}>⚠ {error}</div>}
      {result && (
        <>
          <div className="banner" style={{ marginTop: 12 }}>
            Replayed as <strong>{result.identity}</strong> against <strong>{result.configuration}</strong>:
            {" "}<span className="mono">{result.requested.method} {result.requested.path}</span>
            {" → "}<strong>HTTP {result.result.response?.status}</strong>. {result.note}
          </div>
          <EvidenceView evidence={result.result} />
        </>
      )}
    </div>
  );
}

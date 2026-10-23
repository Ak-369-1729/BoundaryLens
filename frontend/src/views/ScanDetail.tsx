import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, type Scan } from "../api";
import { ConfirmationChip, Empty, ErrorState, Loading, SeverityChip, StatusPill, WorkflowSteps } from "../components";
import { usePoll } from "../hooks";

const MANIFEST_CHECKS: Record<string, string> = {
  "BL-CROSS-USER": "Cross-user private-resource access",
  "BL-ADMIN-READ": "Non-admin access to admin-only operation",
  "BL-ANON-API": "Anonymous access to protected API",
  "BL-SESSION-REUSE": "Session not invalidated after logout",
  "BL-SEC-CONFIG": "Security configuration observations",
};
const AUTO_CHECKS: Record<string, string> = {
  "BL-AUTO-BOLA": "Broken Object Level Authorization (BOLA/IDOR)",
  "BL-AUTO-BFLA": "Broken Function Level Authorization",
  "BL-AUTO-ANON": "Unauthenticated access to a protected resource",
};

export function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [active, setActive] = useState(true);
  const { data, error } = usePoll<Scan>(
    () => api.getScan(scanId!),
    1200,
    active
  );

  if (error) return <ErrorState message={error} />;
  if (!data) return <Loading label="Loading scan…" />;

  const running = data.status === "running" || data.status === "queued";
  if (!running && active) setActive(false);

  const result = data.result;
  const live = data.live;
  const requests = running ? live?.requests_sent ?? data.requests_sent : data.requests_sent;
  const budget = result?.request_budget ?? 150;
  const activity = (running ? live?.activity : result?.activity) || [];
  const coverage = result?.check_coverage || {};

  const cancel = async () => { await api.cancelScan(scanId!); };

  return (
    <>
      <div className="page-head">
        <div className="row-between">
          <h1>Scan · {data.configuration}</h1>
          <StatusPill status={data.status} />
        </div>
        <p className="mono faint">{data.id}</p>
      </div>

      {data.error && <div className="banner" style={{ borderLeftColor: "var(--critical)" }}>⚠ {data.error}</div>}

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-label">Progress</div>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${Math.min(100, (requests / budget) * 100)}%` }} />
          </div>
          <div className="stat-sub">{requests} / {budget} requests · origin <span className="mono">{data.origin}</span></div>
          {running && (
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn-danger" onClick={cancel}>Cancel scan</button>
              <span className="faint">Cancellation stops further requests.</span>
            </div>
          )}
          {!running && (
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn-sm" onClick={() => navigate(`/findings?scan=${data.id}`)}>View findings</button>
              <a className="btn btn-sm" href={api.reportHtmlUrl(data.id)} target="_blank" rel="noreferrer">HTML</a>
              <a className="btn btn-sm" href={api.reportJsonUrl(data.id)} target="_blank" rel="noreferrer">JSON</a>
              <a className="btn btn-sm" href={api.reportSarifUrl(data.id)} target="_blank" rel="noreferrer">SARIF</a>
              {data.kind === "autoscan" && <>
                <button className="btn-sm" onClick={() => navigate("/matrix")}>Matrix</button>
                <button className="btn-sm" onClick={() => navigate("/graph")}>Graph</button>
              </>}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-label">Check outcomes</div>
          {Object.keys(data.kind === "autoscan" ? AUTO_CHECKS : MANIFEST_CHECKS).map((cid) => {
            const CHECK_TITLES = data.kind === "autoscan" ? AUTO_CHECKS : MANIFEST_CHECKS;
            const assessed = coverage[cid] === "assessed" ||
              (data.kind === "autoscan" && !running && data.status === "completed");
            const found = (result?.findings || []).filter((f) => f.check_id === cid && f.confirmation !== "not_assessed");
            return (
              <div key={cid} className="row-between" style={{ padding: "5px 0", borderBottom: "1px solid var(--border)" }}>
                <span style={{ fontSize: 13 }}><span className="tag">{cid}</span> {CHECK_TITLES[cid]}</span>
                {!assessed ? (
                  <span className="chip not_assessed">not assessed</span>
                ) : found.length ? (
                  <span className="chip sev-high">{found.length} finding{found.length > 1 ? "s" : ""}</span>
                ) : (
                  <span className="chip confirmed">clear</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {result?.workflow && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h2>Workflow — {result.workflow.id}</h2>
          <p className="muted">Explicit session lifecycle as identity <span className="mono">{result.workflow.identity}</span>:
            login → fetch own resource → logout → reuse the signed-out session. This is a scripted workflow, not crawling.</p>
          <WorkflowSteps steps={result.workflow.steps} />
        </div>
      )}

      {!running && result && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h2>Findings</h2>
          {result.findings.length ? (
            <table>
              <thead><tr><th>Severity</th><th>Finding</th><th>Identity</th><th>Confirmation</th></tr></thead>
              <tbody>
                {result.findings.map((f) => (
                  <tr key={f.finding_id} className="clickable" onClick={() => navigate(`/scans/${data.id}/findings/${f.finding_id}`)}>
                    <td><SeverityChip severity={f.severity} /></td>
                    <td><strong>{f.title}</strong><div className="faint mono">{f.method} {f.route}</div></td>
                    <td className="mono">{f.actor_identity}</td>
                    <td><ConfirmationChip confirmation={f.confirmation} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No findings for this scan." />
          )}
        </div>
      )}

      <div className="card">
        <h2>Request activity</h2>
        <p className="muted">Sanitized log of every request the scanner sent (bounded to the last {activity.length}).</p>
        {activity.length ? (
          <table>
            <thead><tr><th>#</th><th>Identity</th><th>Request</th><th>Purpose</th><th>Status</th></tr></thead>
            <tbody>
              {activity.slice().reverse().map((a) => (
                <tr key={a.seq}>
                  <td className="faint">{a.seq}</td>
                  <td className="mono">{a.identity}</td>
                  <td className="mono">{a.method} {a.path}</td>
                  <td className="faint">{a.purpose}</td>
                  <td>{a.error ? <span className="chip sev-high">{a.error}</span> : a.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty message="No activity recorded yet." />
        )}
      </div>
    </>
  );
}

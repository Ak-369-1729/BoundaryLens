import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, type Scan } from "../api";
import { ConfirmationChip, Empty, ErrorState, Loading, SeverityChip } from "../components";
import { useAsync } from "../hooks";

export function Findings() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const scans = useAsync(() => api.listScans(), []);
  const completed = (scans.data || []).filter((s) => s.status === "completed");
  const preferred = params.get("scan");
  const [scanId, setScanId] = useState<string>("");
  const effective = scanId || preferred || completed[0]?.id || "";

  const detail = useAsync<Scan | null>(() => (effective ? api.getScan(effective) : Promise.resolve(null)), [effective]);

  const [severity, setSeverity] = useState("");
  const [check, setCheck] = useState("");
  const [identity, setIdentity] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [q, setQ] = useState("");

  const findings = detail.data?.result?.findings || [];
  const identities = useMemo(() => [...new Set(findings.map((f) => f.actor_identity))], [findings]);
  const checks = useMemo(() => [...new Set(findings.map((f) => f.check_id))], [findings]);

  const filtered = findings.filter((f) =>
    (!severity || f.severity === severity) &&
    (!check || f.check_id === check) &&
    (!identity || f.actor_identity === identity) &&
    (!confirmation || f.confirmation === confirmation) &&
    (!q || `${f.title} ${f.route} ${f.observed_behavior}`.toLowerCase().includes(q.toLowerCase()))
  );

  if (scans.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;

  return (
    <>
      <div className="page-head">
        <h1>Findings</h1>
        <p>Search and filter confirmed authorization failures and hardening observations across a scan.</p>
      </div>

      {!completed.length ? (
        <Empty message="No completed scans yet. Start a scan to see findings." />
      ) : (
        <>
          <div className="toolbar">
            <select value={effective} onChange={(e) => setScanId(e.target.value)}>
              {completed.map((s) => (
                <option key={s.id} value={s.id}>{s.configuration} · {new Date(s.created_at).toLocaleString()}</option>
              ))}
            </select>
            <input type="text" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <select value={check} onChange={(e) => setCheck(e.target.value)}>
              <option value="">All checks</option>
              {checks.map((c) => <option key={c}>{c}</option>)}
            </select>
            <select value={identity} onChange={(e) => setIdentity(e.target.value)}>
              <option value="">All identities</option>
              {identities.map((i) => <option key={i}>{i}</option>)}
            </select>
            <select value={confirmation} onChange={(e) => setConfirmation(e.target.value)}>
              <option value="">All statuses</option>
              {["confirmed", "observation"].map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>

          <div className="card">
            {detail.loading ? (
              <Loading />
            ) : filtered.length ? (
              <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Identity</th><th>Status</th><th>Instances</th></tr></thead>
                <tbody>
                  {filtered.map((f) => (
                    <tr key={f.finding_id} className="clickable" onClick={() => navigate(`/scans/${effective}/findings/${f.finding_id}`)}>
                      <td><SeverityChip severity={f.severity} /></td>
                      <td><strong>{f.title}</strong><div className="faint mono">{f.method} {f.route}</div></td>
                      <td className="mono">{f.actor_identity}</td>
                      <td><ConfirmationChip confirmation={f.confirmation} /></td>
                      <td>{f.instance_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty message="No findings match these filters." />
            )}
          </div>
        </>
      )}
    </>
  );
}

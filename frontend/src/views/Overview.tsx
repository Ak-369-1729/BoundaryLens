import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Empty, ErrorState, Loading, SeverityBar, StatusPill } from "../components";
import { useAsync } from "../hooks";

const SEV = ["critical", "high", "medium", "low", "info"] as const;

export function Overview({ recentOnly = false }: { recentOnly?: boolean }) {
  const navigate = useNavigate();
  const cfg = useAsync(() => api.config(), []);
  const scans = useAsync(() => api.listScans(), []);

  if (cfg.loading || scans.loading) return <Loading />;
  if (cfg.error) return <ErrorState message={cfg.error} />;
  if (scans.error) return <ErrorState message={scans.error} />;
  const config = cfg.data!;
  const all = scans.data!;
  const latest = all.find((s) => s.status === "completed") || all[0];

  if (recentOnly) {
    return (
      <>
        <div className="page-head">
          <h1>Scans</h1>
          <p>All scans recorded by this scanner, newest first. Interrupted scans are marked failed on restart.</p>
        </div>
        <ScanTable scans={all} navigate={navigate} />
      </>
    );
  }

  const counts = latest?.severity_counts || {};
  return (
    <>
      <div className="page-head">
        <h1>Overview</h1>
        <p>{config.manifest_name}. The scanner tests the authorization rules declared in the manifest across
          configured identities. Confirmed findings are proven with sanitized request/response evidence.</p>
      </div>

      <div className="banner">
        <strong>Authorization:</strong> {config.authorization_statement}
      </div>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-label">Target configurations</div>
          {config.targets.map((t) => (
            <div key={t.id} className="row-between" style={{ padding: "4px 0" }}>
              <span><strong>{t.configuration}</strong> <span className="faint mono">{t.origin}</span></span>
              {t.local_demo && <span className="chip">local demo</span>}
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-label">Configured identities</div>
          {config.identities.map((i) => (
            <div key={i.id} className="row-between" style={{ padding: "4px 0" }}>
              <span className="mono">{i.id}</span>
              <span className="chip">{i.role}</span>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-label">Latest scan</div>
          {latest ? (
            <>
              <div className="stat-value" style={{ fontSize: 20 }}>{latest.configuration}
                <span className="chip" style={{ marginLeft: 8, fontSize: 11 }}>{latest.kind || "manifest"}</span></div>
              <div style={{ margin: "8px 0" }}><StatusPill status={latest.status} /></div>
              <div className="stat-sub">{latest.requests_sent} requests · {new Date(latest.created_at).toLocaleString()}</div>
              <button className="btn-sm" style={{ marginTop: 10 }} onClick={() => navigate(`/scans/${latest.id}`)}>
                Open scan
              </button>
            </>
          ) : (
            <Empty message="No scans yet." />
          )}
        </div>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Metric label="Endpoints discovered" value={latest?.metrics?.endpoints ?? "—"} />
        <Metric label="Resources discovered" value={latest?.metrics?.resources ?? "—"} />
        <Metric label="Authorization tests" value={latest?.metrics?.tests ?? "—"} />
        <Metric label="Confirmed violations" value={latest?.metrics?.violations ?? (counts.confirmed ?? "—")}
          danger={!!(latest?.metrics?.violations || counts.confirmed)} />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-label">Findings by severity — latest scan</div>
          {latest && latest.status === "completed" ? (
            <>
              <SeverityBar counts={counts as Record<string, number>} />
              <div className="btn-row" style={{ marginTop: 14 }}>
                {SEV.map((s) => (
                  <span key={s} className={`chip sev-${s}`}>{s}: {(counts as Record<string, number>)[s] || 0}</span>
                ))}
              </div>
              <div className="stat-sub" style={{ marginTop: 10 }}>
                {counts.confirmed || 0} confirmed · {counts.observation || 0} observations
              </div>
            </>
          ) : (
            <Empty message={latest ? "Latest scan has no completed results." : "Run a scan to populate this."} />
          )}
        </div>
        <div className="card">
          <div className="card-label">Checks</div>
          {config.checks.map((c) => (
            <div key={c.id} style={{ padding: "4px 0" }}>
              <span className="tag">{c.id}</span> {c.title} <span className="faint">({c.cwe})</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="row-between" style={{ marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>Recent scans</h2>
          <button className="btn-sm btn-primary" onClick={() => navigate("/start")}>Start a scan</button>
        </div>
        <ScanTable scans={all.slice(0, 8)} navigate={navigate} />
      </div>
    </>
  );
}

function Metric({ label, value, danger }: { label: string; value: number | string; danger?: boolean }) {
  return (
    <div className="card">
      <div className="card-label">{label}</div>
      <div className="stat-value" style={{ color: danger ? "var(--high)" : undefined }}>{value}</div>
    </div>
  );
}

function ScanTable({ scans, navigate }: { scans: ReturnType<typeof Object>[] | any[]; navigate: (p: string) => void }) {
  if (!scans.length) return <Empty message="No scans recorded yet." />;
  return (
    <table>
      <thead>
        <tr><th>Configuration</th><th>Status</th><th>Findings</th><th>Requests</th><th>Created</th></tr>
      </thead>
      <tbody>
        {scans.map((s) => (
          <tr key={s.id} className="clickable" onClick={() => navigate(`/scans/${s.id}`)}>
            <td><strong>{s.configuration}</strong> <span className="chip" style={{ fontSize: 10 }}>{s.kind || "manifest"}</span><div className="faint mono">{s.target_id}</div></td>
            <td><StatusPill status={s.status} /></td>
            <td>{s.metrics?.violations ?? s.severity_counts?.confirmed ?? 0} confirmed{s.severity_counts?.observation ? ` · ${s.severity_counts.observation} obs` : ""}</td>
            <td>{s.requests_sent}</td>
            <td className="faint">{new Date(s.created_at).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

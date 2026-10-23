import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { ErrorState, Loading } from "../components";
import { useAsync } from "../hooks";

export function StartScan() {
  const navigate = useNavigate();
  const cfg = useAsync(() => api.config(), []);
  const [targetId, setTargetId] = useState("");
  const [ack, setAck] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (cfg.loading) return <Loading />;
  if (cfg.error) return <ErrorState message={cfg.error} />;
  const config = cfg.data!;
  const selected = config.targets.find((t) => t.id === (targetId || config.targets[0]?.id));
  const effectiveTarget = targetId || config.targets[0]?.id || "";
  const needsAck = config.require_acknowledgment && !ack;

  const start = async () => {
    setSubmitting(true);
    setErr(null);
    try {
      const scan = await api.startScan(effectiveTarget, ack);
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setErr((e as Error).message);
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <h1>Start scan</h1>
        <p>Scans run only against the configured demo targets below. The scanner never accepts an
          arbitrary URL typed into the browser; targets and their credentials live server-side in the manifest.</p>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Target</h2>
          <label htmlFor="target">Configured demo target</label>
          <select id="target" value={effectiveTarget} onChange={(e) => setTargetId(e.target.value)}>
            {config.targets.map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
          </select>
          {selected && (
            <div className="stat-sub" style={{ marginTop: 10 }}>
              Origin <span className="mono">{selected.origin}</span> · configuration <strong>{selected.configuration}</strong>
              {selected.local_demo && <> · <span className="chip">local demo</span></>}
            </div>
          )}

          <div className="divider" />
          <label className="checkbox">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>I confirm I am authorized to scan this target. {config.authorization_statement}</span>
          </label>

          {err && <div className="error-state" style={{ padding: "14px 0" }}>⚠ {err}</div>}
          <div className="btn-row" style={{ marginTop: 16 }}>
            <button className="btn-primary" disabled={submitting || needsAck || !effectiveTarget} onClick={start}>
              {submitting ? "Starting…" : "Start scan"}
            </button>
            {needsAck && <span className="faint">Acknowledge authorization to continue.</span>}
          </div>
        </div>

        <div className="card">
          <h2>Request limits</h2>
          <p className="muted">Every scan is bounded. These limits come from the manifest and cannot be exceeded.</p>
          <dl className="kv">
            <dt>Request budget</dt><dd>{config.limits.max_requests} requests</dd>
            <dt>Concurrency</dt><dd>{config.limits.concurrency} parallel</dd>
            <dt>Per-request timeout</dt><dd>{config.limits.timeout_seconds}s</dd>
            <dt>Max response size</dt><dd>{(config.limits.max_response_bytes / 1024).toFixed(0)} KiB</dd>
            <dt>Max redirects</dt><dd>{config.limits.max_redirects} (validated in scope)</dd>
          </dl>
          <div className="divider" />
          <div className="card-label">Checks executed</div>
          {config.checks.map((c) => (
            <div key={c.id} style={{ padding: "3px 0", fontSize: 13 }}>
              <span className="tag">{c.id}</span> {c.title}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type Endpoint } from "../api";
import { ErrorState, Loading } from "../components";
import { useAsync } from "../hooks";

export function AutoScan() {
  const navigate = useNavigate();
  const cfg = useAsync(() => api.config(), []);
  const [targetId, setTargetId] = useState("");
  const [ack, setAck] = useState(false);
  const [confidence, setConfidence] = useState(60);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // discovery preview
  const [source, setSource] = useState("openapi");
  const [content, setContent] = useState("");
  const [preview, setPreview] = useState<Endpoint[] | null>(null);
  const [importErr, setImportErr] = useState<string | null>(null);

  if (cfg.loading) return <Loading />;
  if (cfg.error) return <ErrorState message={cfg.error} />;
  const config = cfg.data!;
  const target = targetId || config.targets[0]?.id || "";
  const needsAck = config.require_acknowledgment && !ack;

  const start = async () => {
    setSubmitting(true); setErr(null);
    try {
      const scan = await api.startAutoscan(target, ack, confidence);
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setErr((e as Error).message);
      setSubmitting(false);
    }
  };

  const runImport = async () => {
    setImportErr(null); setPreview(null);
    try {
      const r = await api.importDiscovery(source, content);
      setPreview(r.endpoints);
    } catch (e) {
      setImportErr((e as Error).message);
    }
  };

  return (
    <>
      <div className="page-head">
        <h1>Automated authorization scan</h1>
        <p>Discovers the target's API (from its OpenAPI document), extracts resource identifiers under each
          configured identity, then automatically generates and runs bounded cross-identity BOLA, function-level
          (BFLA) and anonymous-access tests, confirming violations with differential evidence.</p>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Run a scan</h2>
          <label htmlFor="t">Target (endpoints are discovered from its OpenAPI)</label>
          <select id="t" value={target} onChange={(e) => setTargetId(e.target.value)}>
            {config.targets.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
          <label htmlFor="c" style={{ marginTop: 12 }}>Confidence threshold to confirm a violation: <strong>{confidence}%</strong></label>
          <input id="c" type="range" min={40} max={95} value={confidence} style={{ width: "100%" }}
            onChange={(e) => setConfidence(Number(e.target.value))} />
          <div className="divider" />
          <label className="checkbox">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>I am authorized to scan this target. {config.authorization_statement}</span>
          </label>
          {err && <div className="error-state" style={{ padding: "12px 0" }}>⚠ {err}</div>}
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button className="btn-primary" disabled={submitting || needsAck || !target} onClick={start}>
              {submitting ? "Starting…" : "Start automated scan"}
            </button>
            {needsAck && <span className="faint">Acknowledge authorization to continue.</span>}
          </div>
        </div>

        <div className="card">
          <h2>Discovery import (preview)</h2>
          <p className="muted">Normalize an OpenAPI, Postman or HAR source into endpoints. The dashboard scan uses
            the target's own OpenAPI; this preview shows how any source maps to the internal model.</p>
          <div className="btn-row">
            <select value={source} onChange={(e) => setSource(e.target.value)} style={{ width: 140 }}>
              <option value="openapi">OpenAPI</option>
              <option value="postman">Postman</option>
              <option value="har">HAR</option>
            </select>
            <button onClick={runImport} disabled={!content.trim()}>Parse</button>
          </div>
          <textarea value={content} onChange={(e) => setContent(e.target.value)} rows={5}
            placeholder="Paste OpenAPI / Postman / HAR JSON or YAML…"
            style={{ width: "100%", marginTop: 10, fontFamily: "var(--mono)", fontSize: 12,
              background: "var(--surface-2)", color: "var(--text)", border: "1px solid var(--border-strong)",
              borderRadius: 8, padding: 10 }} />
          {importErr && <div className="error-state" style={{ padding: "10px 0" }}>⚠ {importErr}</div>}
          {preview && (
            <div style={{ marginTop: 10 }}>
              <div className="card-label">{preview.length} endpoint(s)</div>
              <div style={{ maxHeight: 180, overflow: "auto" }}>
                {preview.map((e, i) => (
                  <div key={i} className="mono" style={{ fontSize: 12, padding: "2px 0" }}>
                    <span className="tag">{e.method}</span> {e.path}
                    {e.requires_auth === false && <span className="faint"> · public</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Configured identities</h2>
        <table>
          <thead><tr><th>Identity</th><th>Role</th><th>Auth kind</th><th>Credential source</th><th>JWT context</th></tr></thead>
          <tbody>
            {config.identities.map((i) => (
              <tr key={i.id}>
                <td className="mono">{i.id}</td>
                <td><span className="chip">{i.role}</span></td>
                <td>{i.authenticated ? "login/session" : "anonymous"}</td>
                <td className="faint mono">{i.username ? `env password` : "—"}</td>
                <td className="faint">not a JWT identity</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="faint" style={{ fontSize: 12, marginTop: 8 }}>
          Identities authenticate server-side; credentials come only from environment variables and never appear here.
          Bearer/JWT identities (configured via boundarylens.yaml) also show decoded, signature-free JWT claims.
        </p>
      </div>
    </>
  );
}

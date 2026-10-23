// Shared presentational components.
import type { Evidence, Finding, WorkflowStep } from "./api";

export function Chip({ kind, label }: { kind: string; label?: string }) {
  return <span className={`chip ${kind}`}>{label ?? kind}</span>;
}

export function SeverityChip({ severity }: { severity: string }) {
  return <span className={`chip sev-${severity}`}>{severity}</span>;
}

export function ConfirmationChip({ confirmation }: { confirmation: string }) {
  const label = confirmation.replace("_", " ");
  return <span className={`chip ${confirmation}`}>{label}</span>;
}

export function StatusPill({ status }: { status: string }) {
  return (
    <span className={`status ${status}`}>
      <span className="dot" style={{ background: "currentColor" }} /> {status}
    </span>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading-state">
      <div className="spinner" />
      {label}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return <div className="error-state">⚠ {message}</div>;
}

export function Empty({ message }: { message: string }) {
  return <div className="empty-state">{message}</div>;
}

export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
  if (!total) return <div className="severity-bar" />;
  return (
    <div className="severity-bar">
      {order.map((k) =>
        counts[k] ? (
          <div key={k} title={`${k}: ${counts[k]}`} style={{ width: `${(counts[k] / total) * 100}%`, background: `var(--${k})` }} />
        ) : null
      )}
    </div>
  );
}

function headerLines(headers: Record<string, string> | undefined): string {
  if (!headers) return "";
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

export function EvidenceView({ evidence }: { evidence?: Evidence }) {
  if (!evidence) return <p className="faint">No evidence captured.</p>;
  const { request, response, error } = evidence;
  return (
    <div className="grid" style={{ gap: 12 }}>
      {request && (
        <div>
          <div className="card-label">Request (sanitized)</div>
          <pre>
            {`${request.method} ${request.url}\n${headerLines(request.headers)}`}
            {request.body ? `\n\n${request.body}` : ""}
          </pre>
        </div>
      )}
      {response ? (
        <div>
          <div className="card-label">Response · HTTP {response.status}{response.truncated ? " (truncated)" : ""}</div>
          <pre>
            {headerLines(response.headers)}
            {response.redirect_blocked ? `\n\n[redirect not followed: ${response.redirect_blocked}]` : ""}
            {`\n\n${response.body_excerpt}`}
          </pre>
        </div>
      ) : (
        <p className="faint">No response{error ? ` — ${error}` : ""}.</p>
      )}
    </div>
  );
}

export function FindingRow({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  return (
    <tr className="clickable" onClick={onClick}>
      <td><SeverityChip severity={finding.severity} /></td>
      <td>
        <strong>{finding.title}</strong>
        <div className="faint mono">{finding.method} {finding.route}</div>
      </td>
      <td className="mono">{finding.actor_identity}</td>
      <td><ConfirmationChip confirmation={finding.confirmation} /></td>
      <td>{finding.instance_count}</td>
    </tr>
  );
}

export function WorkflowSteps({ steps }: { steps: WorkflowStep[] }) {
  return (
    <div className="step-list">
      {steps.map((s) => (
        <div className="step" key={s.id}>
          <div className={`step-marker ${s.ok ? "ok" : "bad"}`}>{s.ok ? "✓" : "✕"}</div>
          <div style={{ flex: 1 }}>
            <div className="row-between">
              <strong>{s.label}</strong>
              <span className="faint mono">{s.status != null ? `HTTP ${s.status}` : "—"}</span>
            </div>
            {s.note && <div className="muted" style={{ fontSize: 13 }}>{s.note}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

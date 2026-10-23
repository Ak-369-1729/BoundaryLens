import { useState } from "react";
import { api } from "../api";
import { Empty, ErrorState, Loading } from "../components";
import { useAsync } from "../hooks";
import { scanLabel, useScanSelection } from "./scanpick";

type Tab = "endpoints" | "identities" | "resources";

export function Inventory() {
  const { scans, completed, selected, setSelected } = useScanSelection({ autoOnly: true });
  const [tab, setTab] = useState<Tab>("endpoints");
  const detail = useAsync(() => (selected ? api.getScan(selected) : Promise.resolve(null)), [selected]);

  if (scans.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;
  const result = detail.data?.result;

  return (
    <>
      <div className="page-head">
        <h1>Discovery inventory</h1>
        <p>What an automated scan discovered: the normalized API endpoints, the identities exercised, and the
          resource identifiers extracted from responses (used to generate cross-identity tests).</p>
      </div>
      {!completed.length ? (
        <Empty message="No automated scans yet. Run one from “Automated scan”." />
      ) : (
        <>
          <div className="toolbar">
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {completed.map((s) => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
            </select>
            <div className="btn-row">
              {(["endpoints", "identities", "resources"] as Tab[]).map((t) => (
                <button key={t} className={`btn-sm ${tab === t ? "btn-primary" : ""}`} onClick={() => setTab(t)}>
                  {t[0].toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
          </div>
          {detail.loading ? <Loading /> : !result ? <Empty message="No result." /> : (
            <div className="card">
              {tab === "endpoints" && <Endpoints result={result} />}
              {tab === "identities" && <Identities result={result} />}
              {tab === "resources" && <Resources result={result} />}
            </div>
          )}
        </>
      )}
    </>
  );
}

function Endpoints({ result }: { result: NonNullable<ReturnType<() => any>> }) {
  const eps = result.endpoints || [];
  if (!eps.length) return <Empty message="No endpoints discovered." />;
  return (
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Source</th><th>Auth</th><th>Tags</th><th>Fields</th></tr></thead>
      <tbody>
        {eps.map((e: any, i: number) => (
          <tr key={i}>
            <td><span className="tag">{e.method}</span></td>
            <td className="mono">{e.path}</td>
            <td className="faint">{e.source}</td>
            <td>{e.requires_auth === true ? "required" : e.requires_auth === false ? "public" : "unknown"}</td>
            <td className="faint">{(e.tags || []).join(", ") || "—"}</td>
            <td className="faint">{(e.response_fields || []).slice(0, 4).join(", ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Identities({ result }: { result: any }) {
  const ids = result.identities || [];
  if (!ids.length) return <Empty message="No identities." />;
  return (
    <table>
      <thead><tr><th>Identity</th><th>Role</th><th>Kind</th><th>Credential</th><th>JWT context</th></tr></thead>
      <tbody>
        {ids.map((i: any) => (
          <tr key={i.id}>
            <td className="mono">{i.id}</td>
            <td><span className="chip">{i.role}</span></td>
            <td>{i.kind}</td>
            <td className="faint mono">{i.credential_source || "—"}</td>
            <td className="faint">{i.jwt_context
              ? `alg ${i.jwt_context.alg}; claims ${Object.keys(i.jwt_context.claims).join(", ")} (unverified)`
              : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Resources({ result }: { result: any }) {
  const res = result.resources || { items: [], by_identity: {}, by_type: {} };
  const items = res.items || [];
  if (!items.length) return <Empty message="No resources extracted." />;
  return (
    <>
      <div className="btn-row" style={{ marginBottom: 12 }}>
        {Object.entries(res.by_identity as Record<string, number>).map(([k, v]) => (
          <span key={k} className="chip">{k}: {v}</span>
        ))}
      </div>
      <table>
        <thead><tr><th>Type</th><th>Value</th><th>Discovered by</th><th>Source</th><th>Protected fields</th></tr></thead>
        <tbody>
          {items.map((r: any, i: number) => (
            <tr key={i}>
              <td><span className="chip">{r.resource_type}</span></td>
              <td className="mono">{r.value}</td>
              <td className="mono">{r.identity}</td>
              <td className="faint mono">{r.source}</td>
              <td className="faint">{(r.protected_fields || []).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

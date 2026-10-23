import { api, type Graph as GraphData } from "../api";
import { Empty, ErrorState, Loading } from "../components";
import { useAsync } from "../hooks";
import { scanLabel, useScanSelection } from "./scanpick";

export function Graph() {
  const { scans, completed, selected, setSelected } = useScanSelection({ autoOnly: true });
  const detail = useAsync(() => (selected ? api.graph(selected) : Promise.resolve(null)), [selected]);

  if (scans.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;

  return (
    <>
      <div className="page-head">
        <h1>Authorization graph</h1>
        <p>Observed access between identities and resources. Green edges are legitimate ownership; red edges are
          confirmed authorization violations (an identity reaching a resource it should not).</p>
      </div>
      {!completed.length ? (
        <Empty message="No automated scans yet. Run one from “Automated scan”." />
      ) : (
        <>
          <div className="toolbar">
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {completed.map((s) => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
            </select>
          </div>
          {detail.error ? <ErrorState message={detail.error} /> : !detail.data ? <Loading /> :
            <GraphSvg graph={detail.data.graph} />}
        </>
      )}
    </>
  );
}

function GraphSvg({ graph }: { graph: GraphData }) {
  const identities = graph.nodes.filter((n) => n.type === "identity");
  const resources = graph.nodes.filter((n) => n.type === "resource");
  if (!identities.length) return <Empty message="This scan produced no graph." />;

  const W = 820, rowH = 54, padY = 40;
  const H = Math.max(identities.length, resources.length) * rowH + padY * 2;
  const leftX = 150, rightX = W - 150;
  const pos = new Map<string, { x: number; y: number }>();
  identities.forEach((n, i) => pos.set(n.id, { x: leftX, y: padY + i * rowH + rowH / 2 }));
  resources.forEach((n, i) => pos.set(n.id, { x: rightX, y: padY + i * rowH + rowH / 2 }));

  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <div className="btn-row" style={{ marginBottom: 10 }}>
        <span className="chip" style={{ color: "var(--ok)" }}>● owns</span>
        <span className="chip sev-high">● violation</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxHeight: 560 }}>
        {graph.edges.map((e, i) => {
          const a = pos.get(e.source), b = pos.get(e.target);
          if (!a || !b) return null;
          const color = e.violation ? "var(--critical)" : "var(--ok)";
          const mx = (a.x + b.x) / 2;
          return (
            <g key={i}>
              <path d={`M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`}
                fill="none" stroke={color} strokeWidth={e.violation ? 2.2 : 1.2}
                strokeDasharray={e.violation ? "0" : "4 3"} opacity={e.violation ? 0.95 : 0.5} />
              {e.violation && e.confidence != null && (
                <text x={mx} y={(a.y + b.y) / 2 - 4} fill="var(--critical)" fontSize="10" textAnchor="middle">
                  {e.confidence}%
                </text>
              )}
            </g>
          );
        })}
        {graph.nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          const isId = n.type === "identity";
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={7} fill={isId ? "var(--accent)" : "var(--surface-2)"}
                stroke={isId ? "var(--accent)" : "var(--border-strong)"} strokeWidth={1.5} />
              <text x={isId ? p.x - 14 : p.x + 14} y={p.y + 4} textAnchor={isId ? "end" : "start"}
                fill="var(--text)" fontSize="12" fontFamily="var(--mono)">{n.label}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

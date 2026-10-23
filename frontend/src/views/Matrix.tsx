import { useNavigate } from "react-router-dom";
import { api, type MatrixCell } from "../api";
import { Empty, ErrorState, Loading } from "../components";
import { useAsync } from "../hooks";
import { scanLabel, useScanSelection } from "./scanpick";

const STATUS_STYLE: Record<string, { bg: string; fg: string }> = {
  PASS: { bg: "rgba(70,209,158,0.14)", fg: "var(--ok)" },
  BLOCKED: { bg: "rgba(70,209,158,0.10)", fg: "var(--ok)" },
  VIOLATION: { bg: "rgba(255,90,110,0.16)", fg: "var(--critical)" },
  NOT_TESTED: { bg: "var(--surface-2)", fg: "var(--text-faint)" },
  UNSAFE: { bg: "rgba(240,180,41,0.14)", fg: "var(--medium)" },
  ERROR: { bg: "rgba(240,180,41,0.14)", fg: "var(--medium)" },
};

export function Matrix() {
  const navigate = useNavigate();
  const { scans, completed, selected, setSelected } = useScanSelection({ autoOnly: true });
  const detail = useAsync(() => (selected ? api.matrix(selected) : Promise.resolve(null)), [selected]);

  if (scans.loading) return <Loading />;
  if (scans.error) return <ErrorState message={scans.error} />;

  return (
    <>
      <div className="page-head">
        <h1>Authorization matrix</h1>
        <p>Identity × Resource × Operation outcomes from an automated scan. <strong>VIOLATION</strong> cells are
          confirmed authorization-boundary failures; <strong>BLOCKED</strong> cells behaved correctly.</p>
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
            <MatrixGrid cells={detail.data.matrix} onOpen={(c) => c.finding_id && navigate(`/scans/${selected}/findings/${c.finding_id}`)} />}
        </>
      )}
    </>
  );
}

function MatrixGrid({ cells, onOpen }: { cells: MatrixCell[]; onOpen: (c: MatrixCell) => void }) {
  if (!cells.length) return <Empty message="This scan produced no matrix cells." />;
  const identities = [...new Set(cells.map((c) => c.identity))];
  const resources = [...new Set(cells.map((c) => c.resource))];
  const ops = [...new Set(cells.map((c) => c.operation))];
  // Prefer VIOLATION on any collision so a violation can never be hidden by a BLOCKED cell.
  const rank: Record<string, number> = { VIOLATION: 5, ERROR: 4, UNSAFE: 3, PASS: 2, BLOCKED: 1, NOT_TESTED: 0 };
  const lookup = new Map<string, MatrixCell>();
  for (const c of cells) {
    const key = `${c.identity}|${c.resource}|${c.operation}`;
    const prev = lookup.get(key);
    if (!prev || (rank[c.status] ?? 0) > (rank[prev.status] ?? 0)) lookup.set(key, c);
  }

  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <table>
        <thead>
          <tr>
            <th>Identity</th><th>Resource</th>
            {ops.map((o) => <th key={o}>{o}</th>)}
          </tr>
        </thead>
        <tbody>
          {identities.flatMap((identity) =>
            resources.map((resource) => {
              const row = ops.map((o) => lookup.get(`${identity}|${resource}|${o}`));
              if (row.every((c) => !c)) return null;
              return (
                <tr key={`${identity}|${resource}`}>
                  <td className="mono">{identity}</td>
                  <td className="mono faint">{resource}</td>
                  {ops.map((o, i) => {
                    const c = row[i];
                    if (!c) return <td key={o} className="faint">—</td>;
                    const st = STATUS_STYLE[c.status] || STATUS_STYLE.NOT_TESTED;
                    return (
                      <td key={o}>
                        <span onClick={() => onOpen(c)} title={c.detail}
                          className={c.finding_id ? "clickable" : ""}
                          style={{ display: "inline-block", padding: "3px 9px", borderRadius: 6,
                            background: st.bg, color: st.fg, fontWeight: 600, fontSize: 12 }}>
                          {c.status}{c.status === "VIOLATION" && c.confidence ? ` ${c.confidence}%` : ""}
                        </span>
                      </td>
                    );
                  })}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

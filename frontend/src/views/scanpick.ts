import { useState } from "react";
import { api, type Scan } from "../api";
import { useAsync } from "../hooks";

// Shared helper: list completed scans (optionally autoscans only) and track a selection.
export function useScanSelection(opts: { autoOnly?: boolean } = {}) {
  const scans = useAsync(() => api.listScans(), []);
  const [selected, setSelected] = useState("");
  const completed = (scans.data || []).filter(
    (s) => s.status === "completed" && (!opts.autoOnly || s.kind === "autoscan")
  );
  const effective = selected || completed[0]?.id || "";
  return { scans, completed, selected: effective, setSelected };
}

export function scanLabel(s: Scan): string {
  const kind = s.kind === "autoscan" ? "auto" : "manifest";
  return `${s.configuration} · ${kind} · ${new Date(s.created_at).toLocaleString()}`;
}

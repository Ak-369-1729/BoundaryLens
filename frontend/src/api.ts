// Typed client for the BoundaryLens backend API.

export interface Identity { id: string; role: string; username: string | null; authenticated: boolean }
export interface TargetCfg { id: string; label: string; origin: string; configuration: string; local_demo: boolean }
export interface CheckCfg { id: string; title: string; cwe: string }
export interface RouteCfg { id: string; method: string; path: string; rule: string; executed: boolean; safe: boolean }
export interface Limits {
  max_requests: number; concurrency: number; timeout_seconds: number;
  max_response_bytes: number; max_redirects: number;
}
export interface Config {
  manifest_name: string; authorization_statement: string; require_acknowledgment: boolean;
  targets: TargetCfg[]; identities: Identity[]; limits: Limits; checks: CheckCfg[]; routes: RouteCfg[];
}

export interface SeverityCounts {
  critical: number; high: number; medium: number; low: number; info: number;
  confirmed: number; observation: number; total: number;
}
export interface Evidence {
  request?: { identity: string; method: string; url: string; headers: Record<string, string>; body: string | null };
  response?: {
    status: number; headers: Record<string, string>; body_excerpt: string;
    truncated: boolean; redirects: { status: number; location: string }[]; redirect_blocked: string | null;
  } | null;
  error?: string | null; duration_ms?: number;
}
export interface Instance {
  method?: string; path?: string; status?: number | null; resource?: string | null;
  markers_found?: string[]; observed_owner?: string; observation?: string; evidence?: Evidence;
}
export interface Finding {
  finding_id: string; check_id: string; title: string; severity: string; confirmation: string;
  method: string; route: string; actor_identity: string; expected_rule: string;
  expected_behavior: string; observed_behavior: string; severity_rationale: string;
  cwe: string; remediation: string; limitations: string; instance_count: number;
  instances: Instance[]; evidence: Evidence;
}
export interface WorkflowStep { id: string; label: string; status: number | null; ok: boolean; note: string; evidence?: Evidence }
export interface Workflow { id: string; identity: string; steps: WorkflowStep[]; confirmed_finding: string | null }
export interface ActivityEntry {
  seq: number; identity: string; method: string; path: string; purpose: string;
  status: number | null; error: string | null; duration_ms: number; redirect_blocked: string | null; at: string;
}
export interface ScanResult {
  manifest_name: string; authorization_statement: string; findings: Finding[];
  severity_counts: SeverityCounts; check_coverage: Record<string, string>;
  workflow: Workflow | null; activity: ActivityEntry[];
  limits: Partial<Limits>; request_budget: number;
}
export interface ScanMetrics { endpoints: number; resources: number; tests: number; violations: number }
export interface Endpoint {
  method: string; path: string; source: string; operation_id: string | null; tags: string[];
  path_params: string[]; query_params: string[]; security: string[]; requires_auth: boolean | null;
  summary: string; response_fields: string[];
}
export interface JwtContext { alg: string | null; typ: string | null; claims: Record<string, unknown>; signature_verified: boolean; note: string }
export interface PlatformIdentity {
  id: string; role: string; kind: string; authenticated: boolean;
  credential_source: string | null; jwt_context: JwtContext | null;
}
export interface ResourceItem {
  resource_type: string; value: string; identity: string; source: string;
  json_path: string; protected_fields: string[]; fingerprint: string;
}
export interface ResourceSummary { total: number; by_identity: Record<string, number>; by_type: Record<string, number>; items: ResourceItem[] }
export interface MatrixCell {
  identity: string; resource: string; operation: string; status: string;
  confidence: number; finding_id: string | null; detail: string;
}
export interface GraphNode { id: string; label: string; type: string }
export interface GraphEdge { source: string; target: string; kind: string; violation: boolean; confidence?: number }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface Scan {
  id: string; target_id: string; configuration: string; origin: string; status: string;
  kind?: string; created_at: string; started_at: string | null; finished_at: string | null;
  requests_sent: number; error: string | null; severity_counts: Partial<SeverityCounts>;
  metrics?: ScanMetrics;
  result?: (ScanResult & {
    matrix?: MatrixCell[]; graph?: Graph; resources?: ResourceSummary;
    endpoints?: Endpoint[]; identities?: PlatformIdentity[]; test_count?: number; scan_kind?: string;
  }) | null;
  live?: { requests_sent: number; activity: ActivityEntry[] };
}

export interface BaselineRow { id: string; name: string; target_id: string; configuration: string; scan_id: string; created_at: string; violation_count: number }
export interface RegressionRow {
  key: string; check_id: string; method: string; route: string; identity: string;
  severity: string; previous_status: string; current_status: string; confidence?: number; evidence_summary?: string;
}
export interface RegressionResult {
  baseline_id: string; scan_id: string; fail_on: string; passed: boolean;
  regressions: RegressionRow[]; fixed: RegressionRow[]; persisting: RegressionRow[]; gating_regressions: RegressionRow[];
}
export interface Compare {
  baseline: { id: string; configuration: string; status: string };
  candidate: { id: string; configuration: string; status: string };
  resolved: Finding[]; persisting: Finding[]; new: Finding[];
}
export interface ReplayResult {
  target_id: string; configuration: string; identity: string;
  requested: { method: string; path: string }; result: Evidence; note: string;
}

async function http<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  config: () => http<Config>("/api/config"),
  listScans: () => http<{ scans: Scan[] }>("/api/scans").then((d) => d.scans),
  getScan: (id: string) => http<Scan>(`/api/scans/${id}`),
  startScan: (target_id: string, ack: boolean) =>
    http<Scan>("/api/scans", { method: "POST", body: JSON.stringify({ target_id, authorization_acknowledged: ack }) }),
  startAutoscan: (target_id: string, ack: boolean, confidence_threshold = 60) =>
    http<Scan>("/api/autoscans", { method: "POST", body: JSON.stringify({ target_id, authorization_acknowledged: ack, confidence_threshold }) }),
  cancelScan: (id: string) => http<{ cancel_requested: boolean }>(`/api/scans/${id}/cancel`, { method: "POST" }),
  compare: (baseline: string, candidate: string) =>
    http<Compare>(`/api/compare?baseline_scan=${baseline}&candidate_scan=${candidate}`),
  replay: (scan_id: string, finding_id: string, instance_index: number) =>
    http<ReplayResult>("/api/replay", { method: "POST", body: JSON.stringify({ scan_id, finding_id, instance_index }) }),
  importDiscovery: (source: string, content: string) =>
    http<{ source: string; count: number; endpoints: Endpoint[] }>("/api/discovery/import",
      { method: "POST", body: JSON.stringify({ source, content }) }),
  decodeJwt: (token: string) => http<JwtContext>("/api/jwt/decode", { method: "POST", body: JSON.stringify({ token }) }),
  matrix: (id: string) => http<{ matrix: MatrixCell[]; identities: PlatformIdentity[]; resources: ResourceSummary }>(`/api/scans/${id}/matrix`),
  graph: (id: string) => http<{ graph: Graph }>(`/api/scans/${id}/graph`),
  listBaselines: () => http<{ baselines: BaselineRow[] }>("/api/baselines").then((d) => d.baselines),
  createBaseline: (scan_id: string, name: string) =>
    http<BaselineRow>("/api/baselines", { method: "POST", body: JSON.stringify({ scan_id, name }) }),
  regression: (baseline_id: string, scan_id: string, fail_on: string) =>
    http<RegressionResult>("/api/regression/compare", { method: "POST", body: JSON.stringify({ baseline_id, scan_id, fail_on }) }),
  reportJsonUrl: (id: string) => `/api/scans/${id}/report.json`,
  reportHtmlUrl: (id: string) => `/api/scans/${id}/report.html`,
  reportSarifUrl: (id: string) => `/api/scans/${id}/report.sarif`,
};

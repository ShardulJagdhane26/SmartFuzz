/**
 * api.ts — SmartFuzz API service layer
 * Backend URL is read from VITE_API_BASE_URL at build time, falling back to
 * http://localhost:5000 for local development.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

// ── Request / Response types ──────────────────────────────────────────────────

export type VulnClass = "SQLi" | "XSS" | "RCE" | "SSRF" | "Command Injection"
  | "Auth Bypass" | "IDOR" | "NoSQL" | "XXE" | "SSTI" | "Open Redirect";

export interface StartScanPayload {
  target_url: string;
  scan_type: "GET" | "POST";
  vuln_classes: VulnClass[];
  auth?: {
    cookies?: Array<{ name: string; value: string; domain?: string; path?: string }>;
    headers?: Record<string, string>;
    login?: {
      url: string;
      username: string;
      password: string;
      username_field?: string;
      password_field?: string;
    };
  };
}

export interface ScanStatusResponse {
  id: string;
  target_url: string;
  scan_type: string;
  vuln_classes: string[];
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  current_step: string;
  findings_so_far: number;
  created_at: string;
  completed_at: string | null;
}

export interface BackendFinding {
  id: string;
  vuln_type: string;
  parameter: string;
  payload: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  signature_label: string;
  url: string;
  method: string;
  status_code: number;
  response_time_ms: number;
  response_snippet: string;
  timestamp: string;
  remediation: string;
  evidence: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  owasp_category?: string | null;
  owasp_name?: string | null;
}

export interface ScanResultsResponse {
  id: string;
  target_url: string;
  status: string;
  progress: number;
  created_at: string;
  completed_at: string | null;
  findings: BackendFinding[];
  stats: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    total_payloads_generated: number;
    forms_crawled: number;
    get_params_found: number;
  };
  crawl_summary: {
    forms: number;
    get_params: number;
  };
}

/** Scan history item — returned by GET /api/scans */
export interface ScanHistoryItem {
  id: string;
  target_url: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  current_step: string;
  created_at: string;
  completed_at: string | null;
  vuln_classes: string[];
  findings_count: number;
}

// ── Internal fetch helper ─────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  const json = await res.json();

  if (!res.ok) {
    throw new Error(json?.error ?? `HTTP ${res.status}`);
  }

  return json as T;
}

// ── Exported API calls ────────────────────────────────────────────────────────

/** Start a new scan. Returns the scan ID immediately. */
export async function startScan(payload: StartScanPayload): Promise<string> {
  const data = await apiFetch<{ scan_id: string }>("/api/scan/new", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  return data.scan_id;
}

/** Poll scan progress and status. */
export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  return apiFetch<ScanStatusResponse>(`/api/scan/${scanId}/status`);
}

/** Fetch completed results (findings + stats). */
export async function getScanResults(scanId: string): Promise<ScanResultsResponse> {
  return apiFetch<ScanResultsResponse>(`/api/scan/${scanId}/results`);
}

/** Cancel a running scan. */
export async function cancelScan(scanId: string): Promise<void> {
  await apiFetch(`/api/scan/${scanId}/cancel`, { method: "POST" });
}

/** Trigger PDF report download — opens in new tab. */
export function downloadPdfReport(scanId: string): void {
  window.open(`${BASE_URL}/api/report/${scanId}/pdf`, "_blank");
}

/** Fetch all past scans for the Scan History page. */
export async function getAllScans(): Promise<ScanHistoryItem[]> {
  const data = await apiFetch<{ scans: ScanHistoryItem[]; total: number }>("/api/scans");
  return data.scans;
}
export interface Source {
  source_id: string;
  content_hash: string;
  declared_host: string;
  collection_metadata: any;
  export_metadata: any;
  byte_size: number;
  acquisition_time_if_known?: string;
  exporter_version: string;
  original_source_mapping: string;
}

export interface Event {
  event_id: string;
  source_id: string;
  source_locator: string;
  original_timestamp_text: string;
  normalized_timestamp: string;
  timestamp_status: string;
  host: string;
  provider: string;
  channel: string;
  event_record_id: string;
  process_guid?: string;
  parent_process_guid?: string;
  raw_fields: any;
  parse_status: string;
}

export interface Finding {
  finding_id: string;
  detector: string;
  detector_version: string;
  rule_id: string;
  source_event_refs: string[];
  original_severity: string;
  matched_fields: any;
  mapping_status: string;
}

export interface ClaimSupport {
  event_id: string;
  fields: string[];
}

export type ClaimStatus = "observed" | "supported_inference" | "hypothesis" | "insufficient_evidence";

export interface Claim {
  claim_id: string;
  predicate_type: string;
  bound_entities: string[];
  support_sets: ClaimSupport[];
  contradictory_evidence: string[];
  unmet_prerequisites: string[];
  status: ClaimStatus;
  canonical_support_sets?: {evidence_ids: string[], relevant_fields: Record<string, unknown>, description: string}[];
}

const API_BASE = "http://localhost:8000/api/v1";

function withRevision(url: string, revision?: string) {
  return revision ? url + (url.includes("?") ? "&" : "?") + "revision=" + encodeURIComponent(revision) : url;
}

export async function getClaim(caseId: string, claimId: string, revision?: string): Promise<Claim> {
  const response = await caseFetch(withRevision(API_BASE + "/cases/" + caseId + "/claims/" + claimId, revision));
  if (!response.ok) throw new Error("The selected claim is unavailable");
  return response.json();
}

export interface MonitorState {
  state: "not_configured" | "monitoring" | "processing" | "paused" | "error";
  configured: boolean;
  enabled: boolean;
  workspace?: string;
  last_scan: string | null;
  last_success: string | null;
  files_discovered: number;
  files_processed: number;
  events_processed: number;
  new_findings: number;
  new_claims: number;
  unread_notifications: number;
  errors: Record<string, string>;
  error?: string;
  revision_id?: string;
}

export interface InvestigationNotification {
  notification_id: string;
  case_id: string;
  revision_id: string;
  claim_id: string;
  finding_ids: string[];
  type: string;
  title: string;
  predicate: string;
  status: ClaimStatus;
  historical: boolean;
  host: string;
  entities: string[];
  supporting_evidence_count: number;
  message: string;
  created_at: string;
  read: boolean;
}

async function monitorRequest(caseId: string, path: string, method = "GET") {
  const response = await caseFetch(API_BASE + "/cases/" + caseId + "/" + path, { method });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(body.detail || "Monitoring request failed");
  }
  return response.json();
}

export function getMonitor(caseId: string): Promise<MonitorState> {
  return monitorRequest(caseId, "monitor");
}

export function controlMonitor(caseId: string, action: "start" | "pause" | "retry"): Promise<MonitorState> {
  return monitorRequest(caseId, "monitor/" + action, "POST");
}

export function getNotifications(caseId: string): Promise<{items: InvestigationNotification[], unread: number, total: number}> {
  return monitorRequest(caseId, "notifications");
}

export function markNotificationRead(item: InvestigationNotification) {
  return monitorRequest(item.case_id, "notifications/" + item.notification_id + "/read", "POST");
}

export function knownCases() {
  return Object.keys(sessionStorage).filter(k => k.startsWith("sentinel-token-")).map(k => k.slice("sentinel-token-".length)).sort();
}

export async function createCase() {
  const response = await fetch(`${API_BASE}/cases`, { method: "POST" });
  if (!response.ok) throw new Error("Could not create case");
  const result = await response.json();
  sessionStorage.setItem(`sentinel-token-${result.case_id}`, result.token);
  sessionStorage.setItem("sentinel-case", result.case_id);
  return result.case_id as string;
}

async function caseFetch(url: string, init: RequestInit = {}) {
  const caseId = url.split("/cases/")[1]?.split("/")[0]?.split("?")[0];
  const token = sessionStorage.getItem(`sentinel-token-${caseId}`) || "";
  return fetch(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token}` } });
}

export async function getReport(caseId: string, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/report`, revision));
  if (!response.ok) throw new Error("Case unavailable. Create a new case if this browser session expired.");
  return response.json();
}

export async function getPacket(caseId: string, claimId: string, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/claims/${claimId}/packet`, revision));
  if (!response.ok) throw new Error("Evidence packet unavailable or exceeds the AI budget; inspect the full report.");
  return response.json();
}

export async function downloadSource(caseId: string, sourceId: string) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/sources/${sourceId}/original`);
  if (!response.ok) throw new Error("Source unavailable");
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = "evidence.jsonl";
  link.click();
  URL.revokeObjectURL(url);
}

export async function importEvidence(caseId: string, file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await caseFetch(`${API_BASE}/cases/${caseId}/import`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || "Upload failed");
  }
  return response.json();
}

export async function getEvents(caseId: string, page = 1, size = 50, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/events?page=${page}&size=${size}`, revision));
  if (!response.ok) throw new Error("Failed to fetch events");
  return response.json();
}

export async function getFindings(caseId: string, page = 1, size = 50, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/findings?page=${page}&size=${size}`, revision));
  if (!response.ok) throw new Error("Failed to fetch findings");
  return response.json();
}

export async function getClaims(caseId: string, page = 1, size = 50, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/claims?page=${page}&size=${size}`, revision));
  if (!response.ok) throw new Error("Failed to fetch claims");
  return response.json();
}

export async function getEvent(caseId: string, eventId: string, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/events/${eventId}`, revision));
  if (!response.ok) throw new Error("Failed to fetch event");
  return response.json();
}

export async function explainClaim(caseId: string, claimId: string, revision?: string) {
  const response = await caseFetch(withRevision(`${API_BASE}/cases/${caseId}/claims/${claimId}/explain`, revision));
  if (!response.ok) throw new Error("Failed to fetch explanation");
  return response.json();
}

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
}

const API_BASE = "http://localhost:8000/api/v1";

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

export async function getReport(caseId: string) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/report`);
  if (!response.ok) throw new Error("Case unavailable. Create a new case if this browser session expired.");
  return response.json();
}

export async function getPacket(caseId: string, claimId: string) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/claims/${claimId}/packet`);
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

export async function getEvents(caseId: string, page = 1, size = 50) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/events?page=${page}&size=${size}`);
  if (!response.ok) throw new Error("Failed to fetch events");
  return response.json();
}

export async function getFindings(caseId: string, page = 1, size = 50) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/findings?page=${page}&size=${size}`);
  if (!response.ok) throw new Error("Failed to fetch findings");
  return response.json();
}

export async function getClaims(caseId: string, page = 1, size = 50) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/claims?page=${page}&size=${size}`);
  if (!response.ok) throw new Error("Failed to fetch claims");
  return response.json();
}

export async function getEvent(caseId: string, eventId: string) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/events/${eventId}`);
  if (!response.ok) throw new Error("Failed to fetch event");
  return response.json();
}

export async function explainClaim(caseId: string, claimId: string) {
  const response = await caseFetch(`${API_BASE}/cases/${caseId}/claims/${claimId}/explain`);
  if (!response.ok) throw new Error("Failed to fetch explanation");
  return response.json();
}

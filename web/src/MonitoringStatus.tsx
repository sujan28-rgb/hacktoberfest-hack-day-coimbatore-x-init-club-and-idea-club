import { useEffect, useState } from "react";
import { controlMonitor, getMonitor } from "./api";
import type { MonitorState } from "./api";

export function MonitoringStatus({caseId, onRevision}: {caseId: string, onRevision: (revision: string) => void}) {
  const [status, setStatus] = useState<MonitorState | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    let inFlight = false;
    const refresh = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const next = await getMonitor(caseId);
        if (active) {
          setStatus(next);
          setError("");
          onRevision(next.revision_id || "");
        }
      } catch (err) {
        if (active) setError(String(err));
      } finally { inFlight = false; }
    };
    void refresh();
    const timer = window.setInterval(refresh, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [caseId, onRevision]);
  const control = async (action: "start" | "pause" | "retry") => {
    setBusy(true);
    try { setStatus(await controlMonitor(caseId, action)); setError(""); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  const labels = {not_configured: "Monitoring not started", monitoring: "● Monitoring",
    processing: "Processing evidence…", paused: "Monitoring paused", error: "Monitoring error"};
  return <section aria-label="Background monitoring" className="monitor-panel">
    <h2>{status ? labels[status.state] : "Checking monitoring status…"}</h2>
    {error && <p role="alert">{error}</p>}
    {status && <>
      <p>Authorized workspace: {status.workspace || (status.configured ? "Configured evidence folder" : "Not configured")}. Direct JSONL exports only.</p>
      {!status.configured && <p>Set SENTINEL_EVIDENCE_WORKSPACE in the backend environment to authorize a dedicated evidence folder, then restart the backend. This does not collect OS events.</p>}
      <button disabled={busy || (!status.configured && !status.enabled)} onClick={() => control(status.enabled ? "pause" : "start")}>
        {status.enabled ? "Pause monitoring" : "Start monitoring"}
      </button>
      {status.enabled && <button disabled={busy} onClick={() => control("retry")}>Scan again / retry</button>}
      <p>Last scan: {status.last_scan ? new Date(status.last_scan).toLocaleString() : "Not scanned"}</p>
      <p>Last scan — files discovered: {status.files_discovered}; changed files processed: {status.files_processed}; events analyzed: {status.events_processed}; new findings: {status.new_findings}; new claims: {status.new_claims}; unread notifications: {status.unread_notifications}.</p>
      {status.error && <p role="alert">{status.error}</p>}
      {Object.keys(status.errors).length > 0 && <ul>{Object.entries(status.errors).map(([name, detail]) => <li key={name}>{name}: {detail}</li>)}</ul>}
    </>}
  </section>;
}

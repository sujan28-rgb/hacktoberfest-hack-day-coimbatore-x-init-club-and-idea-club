import { CaseView } from './CaseView';
import { useState } from 'react';
import { createCase, knownCases } from './api';
import type { InvestigationNotification } from './api';
import { MonitoringStatus } from './MonitoringStatus';
import { NotificationCenter } from './NotificationCenter';

function App() {
  const [caseId, setCaseId] = useState(sessionStorage.getItem("sentinel-case") || "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [caseIds, setCaseIds] = useState(knownCases);
  const [revision, setRevision] = useState<string>();
  const [claimId, setClaimId] = useState<string>();
  const [liveRevision, setLiveRevision] = useState("");
  const startCase = async () => {
    setBusy(true);
    setError("");
    try { setCaseId(await createCase()); setCaseIds(knownCases()); setRevision(undefined); setClaimId(undefined); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  const openNotification = (item: InvestigationNotification) => {
    setCaseId(item.case_id);
    sessionStorage.setItem("sentinel-case", item.case_id);
    setRevision(item.revision_id);
    setClaimId(item.claim_id);
  };
  return (
    <div className="App">
      <button disabled={busy} onClick={startCase}>{busy ? "Creating…" : "New investigation"}</button>
      <NotificationCenter caseIds={caseIds} onOpen={openNotification} />
      {error && <p role="alert">{error}</p>}
      {caseId && <MonitoringStatus key={caseId} caseId={caseId} onRevision={setLiveRevision} />}
      {revision && <aside className="snapshot-banner">Viewing the saved evidence snapshot for this notification.
        <button onClick={() => { setRevision(undefined); setClaimId(undefined); }}>Return to live investigation</button>
      </aside>}
      {caseId ? <CaseView key={caseId + "-" + (revision || "live")} caseId={caseId} revision={revision} selectedClaimId={claimId} liveRevision={liveRevision} /> : <p>Create an investigation to authorize background monitoring or import evidence manually.</p>}
    </div>
  );
}

export default App;

import { CaseView } from './CaseView';
import { useState } from 'react';
import { createCase } from './api';

function App() {
  const [caseId, setCaseId] = useState(sessionStorage.getItem("sentinel-case") || "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const startCase = async () => {
    setBusy(true);
    setError("");
    try { setCaseId(await createCase()); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  return (
    <div className="App">
      <button disabled={busy} onClick={startCase}>{busy ? "Creating…" : "New investigation"}</button>
      {error && <p role="alert">{error}</p>}
      {caseId ? <CaseView key={caseId} caseId={caseId} /> : <p>Create an investigation to import evidence. Cases are private to this browser session.</p>}
    </div>
  );
}

export default App;

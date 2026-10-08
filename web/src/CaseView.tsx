import { useEffect, useState } from 'react';
import { getClaims, getFindings, getReport } from './api';
import type { Claim, Finding } from './api';
import { Timeline } from './Timeline';
import { ClaimPanel } from './ClaimPanel';
import { Import } from './Import';

export function CaseView({ caseId }: { caseId: string }) {
  const [claims, setClaims] = useState<Claim[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState("");
  const [report, setReport] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    setLoading(true);
    setError("");
    Promise.all([
      getClaims(caseId, page).then(res => { setClaims(res.items); setTotal(res.total); }),
      getFindings(caseId, page).then(res => setFindings(res.items)),
      getReport(caseId).then(setReport)
    ])
    .catch(err => setError(err.message))
    .finally(() => setLoading(false));
  }, [caseId, refreshKey, page]);

  return (
    <div style={{ padding: '20px', maxWidth: '1000px', margin: '0 auto', fontFamily: 'sans-serif' }}>
      <h1>Sentinel Evidence - Case {caseId}</h1>
      {error && <p role="alert">{error}</p>}
      {report?.run && <details><summary>Deterministic report: {report.edges.length} relationships, {Object.values(report.identities).filter((i: any) => i.method === "unresolved_or_ambiguous").length} unresolved identities</summary><pre style={{whiteSpace: "pre-wrap", overflowWrap: "anywhere"}}>{JSON.stringify(report, null, 2)}</pre></details>}

      <Import caseId={caseId} onImportComplete={() => { setPage(1); setRefreshKey(k => k + 1); }} />

      <div style={{ display: 'flex', gap: '20px' }}>
        <div style={{ flex: 1 }}>
          <Timeline caseId={caseId} key={`timeline-${refreshKey}`} />

          <h3 style={{ marginTop: '20px' }}>Findings</h3>
          {loading ? <p>Loading...</p> : (
            <ul style={{ paddingLeft: '20px' }}>
              {findings.map(f => (
                <li key={f.finding_id}>
                  <strong>{f.rule_id}</strong> ({f.detector} v{f.detector_version}): Severity {f.original_severity}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div style={{ flex: 1 }}>
          <h3>Typed Claims</h3>
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</button>
          <span> Page {page} </span>
          <button disabled={page * 50 >= Math.max(total, report?.findings.length || 0)} onClick={() => setPage(p => p + 1)}>Next</button>
          {loading ? (
            <p>Loading claims...</p>
          ) : (
            claims.map(claim => (
              <ClaimPanel key={claim.claim_id} caseId={caseId} claim={claim} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}

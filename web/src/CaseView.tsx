import { useEffect, useState } from 'react';
import { getClaims, getFindings } from './api';
import type { Claim, Finding } from './api';
import { Timeline } from './Timeline';
import { ClaimPanel } from './ClaimPanel';
import { Import } from './Import';

export function CaseView({ caseId }: { caseId: string }) {
  const [claims, setClaims] = useState<Claim[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      getClaims(caseId).then(res => setClaims(res.items)),
      getFindings(caseId).then(res => setFindings(res.items))
    ])
    .catch(err => console.error("Error loading case data", err))
    .finally(() => setLoading(false));
  }, [caseId, refreshKey]);

  return (
    <div style={{ padding: '20px', maxWidth: '1000px', margin: '0 auto', fontFamily: 'sans-serif' }}>
      <h1>Sentinel Evidence - Case {caseId}</h1>

      <Import caseId={caseId} onImportComplete={() => setRefreshKey(k => k + 1)} />

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

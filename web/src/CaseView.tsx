import { useEffect, useState } from 'react';
import { getClaims, getFindings, getReport, getClaim } from './api';
import type { Claim, Finding } from './api';
import { Timeline } from './Timeline';
import { ClaimPanel } from './ClaimPanel';
import { Import } from './Import';

export function CaseView({ caseId, revision, selectedClaimId, liveRevision }: { caseId: string, revision?: string, selectedClaimId?: string, liveRevision?: string }) {
  const [claims, setClaims] = useState<Claim[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState("");
  const [report, setReport] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedClaim, setSelectedClaim] = useState<Claim | null>(null);
  const refreshRevision = revision || liveRevision;

  useEffect(() => {
    setLoading(true);
    setError("");
    Promise.all([
      getClaims(caseId, page, 50, revision).then(res => { setClaims(res.items); setTotal(res.total); }),
      getFindings(caseId, page, 50, revision).then(res => setFindings(res.items)),
      getReport(caseId, revision).then(setReport),
      selectedClaimId ? getClaim(caseId, selectedClaimId, revision).then(setSelectedClaim) : Promise.resolve()
    ])
    .catch(err => setError(err.message))
    .finally(() => setLoading(false));
  }, [caseId, refreshKey, page, revision, selectedClaimId, refreshRevision]);

  return (
    <div className="case-view" style={{ padding: '20px', maxWidth: '1000px', margin: '0 auto', fontFamily: 'sans-serif' }}>
      <h1>Sentinel Evidence</h1>
      <p style={{overflowWrap: "anywhere"}}>Investigation {caseId}</p>
      {error && <p role="alert">{error}</p>}
      {report?.run && <details><summary>Deterministic report: {report.edges.length} relationships, {Object.values(report.identities).filter((i: any) => i.method === "unresolved_or_ambiguous").length} unresolved identities</summary><pre style={{whiteSpace: "pre-wrap", overflowWrap: "anywhere"}}>{JSON.stringify(report, null, 2)}</pre></details>}

      {!revision && <details><summary>Manual JSONL import / fallback</summary>
        <p>Pause monitoring before importing manually. Background collection uses the configured workspace.</p>
        <Import caseId={caseId} onImportComplete={() => { setPage(1); setRefreshKey(k => k + 1); }} />
      </details>}

      {selectedClaim && selectedClaim.claim_id === selectedClaimId && <section aria-label="Selected notification investigation">
        <h2>Notification → Finding → Claim → Evidence</h2>
        <p>{report?.findings.filter((f: any) => selectedClaim.canonical_support_sets?.some(s => s.evidence_ids.includes(f.finding_id))).map((f: any) => f.rule_name).join(", ") || "Review the claim's evidence and prerequisites."}</p>
        <ClaimPanel key={selectedClaim.claim_id + (revision || "")} caseId={caseId} claim={selectedClaim} revision={revision} initiallyExpanded />
      </section>}

      <div style={{ display: 'flex', gap: '20px' }}>
        <div style={{ flex: 1 }}>
          <Timeline caseId={caseId} revision={revision} key={`timeline-${refreshKey}-${refreshRevision}`} />

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
              <ClaimPanel key={claim.claim_id} caseId={caseId} claim={claim} revision={revision} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}

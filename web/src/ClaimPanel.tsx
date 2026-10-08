import { useState } from 'react';
import type { Claim } from './api';
import { EvidenceDetail } from './EvidenceDetail';
import { AIExplanation } from './AIExplanation';
import { getPacket } from './api';

export function ClaimPanel({ caseId, claim, revision, initiallyExpanded = false }: { caseId: string, claim: Claim, revision?: string, initiallyExpanded?: boolean }) {
  const [expanded, setExpanded] = useState(initiallyExpanded);
  const [packet, setPacket] = useState("");

  const getStatusColor = (status: string) => {
    switch(status) {
      case 'observed': return '#28a745';
      case 'supported_inference': return '#17a2b8';
      case 'hypothesis': return '#ffc107';
      case 'insufficient_evidence': return '#dc3545';
      default: return '#6c757d';
    }
  };

  return (
    <div style={{ border: '1px solid #ddd', margin: '10px 0', borderRadius: '4px' }}>
      <div
        style={{ padding: '10px', backgroundColor: 'var(--code-bg)', color: 'var(--text-h)', cursor: 'pointer', display: 'flex', gap: '10px', flexWrap: 'wrap', justifyContent: 'space-between' }}
        onClick={() => setExpanded(!expanded)}
      >
        <strong>{claim.predicate_type}</strong>
        <span style={{
          backgroundColor: getStatusColor(claim.status),
          color: claim.status === 'hypothesis' ? '#000' : '#fff',
          padding: '2px 8px', borderRadius: '12px', fontSize: '12px'
        }}>
          {claim.status}
        </span>
      </div>

      {expanded && (
        <div style={{ padding: '10px' }}>
          <div><strong>Entities:</strong> {claim.bound_entities.join(', ')}</div>

          {claim.unmet_prerequisites.length > 0 && (
            <div style={{ color: '#dc3545', marginTop: '10px' }}>
              <strong>Unmet Prerequisites:</strong>
              <ul>
                {claim.unmet_prerequisites.map((req, i) => <li key={i}>{req}</li>)}
              </ul>
            </div>
          )}

          {claim.contradictory_evidence.length > 0 && (
            <div style={{ color: '#dc3545', marginTop: '10px' }}>
              <strong>Contradictory Evidence Events:</strong> {claim.contradictory_evidence.join(', ')}
            </div>
          )}

          <div style={{ marginTop: '15px' }}>
            <strong>Supporting Evidence:</strong>
            {claim.support_sets.length === 0 ? (
              <p style={{ fontStyle: 'italic', color: '#666' }}>No supporting evidence found.</p>
            ) : (
              claim.support_sets.map((support, i) => (
                <EvidenceDetail
                  key={i}
                  caseId={caseId}
                  eventId={support.event_id}
                  highlightedFields={support.fields}
                  revision={revision}
                />
              ))
            )}
          </div>

          <AIExplanation caseId={caseId} claimId={claim.claim_id} revision={revision} />
          <button onClick={() => getPacket(caseId, claim.claim_id, revision).then(p => setPacket(JSON.stringify(p, null, 2))).catch(err => setPacket(err.message))}>Inspect evidence packet</button>
          {packet && <pre style={{whiteSpace: "pre-wrap", overflowWrap: "anywhere"}}>{packet}</pre>}
        </div>
      )}
    </div>
  );
}

import { useEffect, useState } from 'react';
import { explainClaim } from './api';

export function AIExplanation({ caseId, claimId, revision }: { caseId: string, claimId: string, revision?: string }) {
  const [explanation, setExplanation] = useState<string>('');
  const [disclaimer, setDisclaimer] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    setLoading(true);
    setError('');
    explainClaim(caseId, claimId, revision)
      .then(res => {
        setExplanation(res.explanation);
        setDisclaimer(res.disclaimer);
        setStatus(res.status);
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [caseId, claimId, revision]);

  return (
    <div style={{ border: '1px solid #ccc', padding: '10px', marginTop: '10px', backgroundColor: 'var(--code-bg)' }}>
      <h4>AI Explanation</h4>
      <p>{status}</p>
      {loading ? <p>Loading explanation...</p> : null}
      {error ? <p style={{ color: 'red' }}>{error}</p> : null}
      {explanation && !loading && (
        <>
          <p>{explanation}</p>
          <small style={{ color: '#888', fontStyle: 'italic' }}>{disclaimer}</small>
        </>
      )}
    </div>
  );
}

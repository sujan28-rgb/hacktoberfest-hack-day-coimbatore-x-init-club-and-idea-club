import { useEffect, useState } from 'react';
import { explainClaim } from './api';

export function AIExplanation({ caseId, claimId }: { caseId: string, claimId: string }) {
  const [explanation, setExplanation] = useState<string>('');
  const [disclaimer, setDisclaimer] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    setLoading(true);
    setError('');
    explainClaim(caseId, claimId)
      .then(res => {
        setExplanation(res.explanation);
        setDisclaimer(res.disclaimer);
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [caseId, claimId]);

  return (
    <div style={{ border: '1px solid #ccc', padding: '10px', marginTop: '10px', backgroundColor: '#f9f9ff' }}>
      <h4>AI Explanation</h4>
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

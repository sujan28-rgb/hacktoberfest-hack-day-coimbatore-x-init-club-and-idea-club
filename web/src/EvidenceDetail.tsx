import { useEffect, useState } from 'react';
import { getEvent } from './api';
import type { Event } from './api';

export function EvidenceDetail({ caseId, eventId, highlightedFields }: { caseId: string, eventId: string, highlightedFields: string[] }) {
  const [event, setEvent] = useState<Event | null>(null);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    getEvent(caseId, eventId)
      .then(setEvent)
      .catch(err => setError(err.message));
  }, [caseId, eventId]);

  if (error) return <p style={{ color: 'red' }}>Error loading evidence: {error}</p>;
  if (!event) return <p>Loading evidence...</p>;

  return (
    <div style={{ borderLeft: '3px solid #0056b3', paddingLeft: '10px', marginTop: '10px' }}>
      <h5>Original Record ({event.source_locator})</h5>
      <p><strong>Timestamp:</strong> {event.original_timestamp_text}</p>
      <div style={{ backgroundColor: '#f0f0f0', padding: '5px' }}>
        <pre style={{ margin: 0 }}>
          {Object.entries(event.raw_fields).map(([key, value]) => {
            const isHighlighted = highlightedFields.includes(key);
            return (
              <div key={key} style={{ backgroundColor: isHighlighted ? '#ffffcc' : 'transparent', fontWeight: isHighlighted ? 'bold' : 'normal' }}>
                {key}: {String(value)}
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}

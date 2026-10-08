import { useEffect, useState } from 'react';
import { getEvents } from './api';
import type { Event } from './api';

export function Timeline({ caseId }: { caseId: string }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getEvents(caseId)
      .then(res => setEvents(res.items))
      .finally(() => setLoading(false));
  }, [caseId]);

  if (loading) return <p>Loading timeline...</p>;

  return (
    <div>
      <h3>Timeline</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ backgroundColor: '#f0f0f0', textAlign: 'left' }}>
            <th style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>Time</th>
            <th style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>Provider</th>
            <th style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>Event ID</th>
            <th style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>Host</th>
          </tr>
        </thead>
        <tbody>
          {events.map(ev => (
            <tr key={ev.event_id}>
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{ev.normalized_timestamp}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{ev.provider}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{ev.event_record_id}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{ev.host}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

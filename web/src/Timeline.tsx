import { useEffect, useState } from 'react';
import { getEvents } from './api';
import type { Event } from './api';
import { EvidenceDetail } from './EvidenceDetail';

export function Timeline({ caseId, revision }: { caseId: string, revision?: string }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    getEvents(caseId, page, 50, revision)
      .then(res => { setEvents(res.items); setTotal(res.total); })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [caseId, page, revision]);

  if (loading) return <p>Loading timeline...</p>;

  return (
    <div>
      <h3>Timeline</h3>
      {error && <p role="alert">{error}</p>}
      <button disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</button>
      <span> Page {page} </span>
      <button disabled={page * 50 >= total} onClick={() => setPage(p => p + 1)}>Next</button>
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
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}><button onClick={() => setSelected(ev.event_id)}>{ev.event_record_id || ev.source_locator}</button></td>
              <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{ev.host}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {selected && <EvidenceDetail key={selected} caseId={caseId} eventId={selected} highlightedFields={[]} revision={revision} />}
    </div>
  );
}

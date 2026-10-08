import { useState } from 'react';
import { importEvidence } from './api';

export function Import({ caseId, onImportComplete }: { caseId: string, onImportComplete: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const handleImport = async () => {
    if (!file) return;
    setLoading(true);
    setStatus('Importing...');
    try {
      const result = await importEvidence(caseId, file);
      setStatus(`Success! Imported ${result.filename} (${result.size} bytes). Hash status: ${result.hash_status}`);
      onImportComplete();
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ border: '1px solid #aaa', padding: '15px', marginBottom: '20px', borderRadius: '5px' }}>
      <h3>Import Evidence (JSONL)</h3>
      <p style={{ color: '#555' }}>Select a JSONL file to import. We do not scan your filesystem.</p>
      <input 
        type="file" 
        accept=".jsonl" 
        onChange={(e) => setFile(e.target.files?.[0] || null)}
      />
      <button 
        onClick={handleImport} 
        disabled={!file || loading}
        style={{ marginLeft: '10px', padding: '5px 15px' }}
      >
        {loading ? 'Importing...' : 'Import'}
      </button>
      
      {status && <div style={{ marginTop: '10px', fontWeight: 'bold' }}>{status}</div>}
      
      {file && (
        <ul style={{ marginTop: '10px' }}>
          <li><strong>Filename:</strong> {file.name}</li>
          <li><strong>Size:</strong> {file.size} bytes</li>
          <li><strong>Format:</strong> {file.type || 'application/jsonl'}</li>
        </ul>
      )}
    </div>
  );
}

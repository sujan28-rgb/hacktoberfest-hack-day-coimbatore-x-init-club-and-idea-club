# Local threat model

Imported records and model responses are untrusted. The app never executes their
commands, dereferences evidence paths, or interprets embedded HTML as markup.
React renders values as text; downloads use application/octet-stream and nosniff.

Case identifiers and independent random bearer tokens scope every read/import.
Tokens are stored hashed in SQLite, and comparisons are constant-time. Unknown and
unauthorized cases both return 404. Source and event queries remain case-scoped.
Bind to loopback only. CORS allows the two local development origins.

Uploads allow safe JSONL basenames only; source names are metadata, never storage paths.
Limits: 10 MiB upload, 1 MiB record, 10,000 lines. Invalid UTF-8/JSON, non-object rows
and malformed identity fields are rejected before persistence. The original bytes and
normalized report commit atomically. Invalid reimports leave existing evidence intact.

Ollama uses loopback HTTP only, no environment proxies or redirects, a request timeout,
bounded packets and bounded output reads. Exact approved-object validation prevents
prompt injection from introducing new facts, references or status upgrades. Model failure
returns deterministic results. No arbitrary AI prose is accepted as verified evidence.

Out of scope: a compromised local OS/browser, malicious administrator, multi-user
deployment, encrypted database storage, and denial of service from an authorized local
user repeatedly creating cases. Do not expose the development servers publicly.

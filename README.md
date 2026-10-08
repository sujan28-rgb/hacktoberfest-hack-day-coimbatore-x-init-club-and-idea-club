# Sentinel Evidence

A local-first Windows telemetry investigation tool: **evidence first, claims second,
explanation last**. Monitor an explicitly authorized evidence workspace, receive
notifications about meaningful deterministic results, and trace each claim back to
its original bytes. Manual JSONL import remains available for testing and fallback.

## Team and problem

Built by Sujan, Pramit, Jana and Sujai. Current integration ownership follows the final
integration brief: Sujan — intake/normalization/SQLite; Pramit — identity/correlation;
Jana — scenarios/typed claims; Sujai — API/React/security/local AI/integration.
The team name and actual event-day contribution history still require team confirmation.

Security investigations can overstate telemetry: a connection is not exfiltration,
a file creation is not persistence, and timestamp proximity is not causation.
This project was selected to make these boundaries explicit and inspectable.

## Implemented solution

- SHA-256 source hashing, exact original-byte retention and stable source/line event IDs.
- Flat Sysmon JSONL normalization, raw values and timestamp uncertainty preserved.
- Same-host ProcessGuid identity; bounded PID fallback with ambiguity surfaced.
- Three bounded scenarios: flagged parent/child, flagged process/network, flagged process/file.
- One explicit encoded-PowerShell detector indicator, not a comprehensive malware detector.
- Typed support sets, missing prerequisites, conflicting-record preservation and evidence-removal checks.
- Canonical deterministic report, budgeted evidence packets and optional local Ollama.
- SQLite case storage, random bearer-token isolation, paginated FastAPI endpoints.
- React import, timeline, claims, packet inspection and original-source download.
- Shared headless CLI and fixture replay/evaluation.
- Background workspace monitoring with pause/retry, real status counters and persistent state.
- Evidence-backed in-app notifications, deduplication and historical investigation drill-down.

The differentiator is traceable support and conservative uncertainty, rather than an AI
narrative. Claims remain authoritative when the model is unavailable.

## Architecture and contracts

JSONL → hashing/normalization → detector → identity/edges → scenarios → typed claims
→ deterministic report → API/React. A separate optional path passes a complete bounded
packet to local Ollama and validates its response before displaying it.

One Python package, SQLite, FastAPI and React/TypeScript. Canonical Python domain objects
are in src/sentinel_evidence/contracts.py; API fields are presentation views.
See [the supplied architecture specification](docs/architecture-spec.md),
[integration decisions and limitations](docs/integration.md), and
[the local threat model](docs/threat-model.md).

The supplied specification describes the target architecture, including research and
submission work not yet completed. This README describes the code actually present.

## Setup

Prerequisites: Python 3.10+, Node.js 22.14+ (or a compatible newer release), npm.
Ollama is optional. The supplied folder-monitoring adapter requires macOS/Linux.
Run all commands from the repository root unless noted.

~~~sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m uvicorn sentinel_evidence.api.app:app --host 127.0.0.1 --port 8000
~~~

In a second terminal:

~~~sh
cd web
npm ci
npm run dev -- --host 127.0.0.1
~~~

Open http://127.0.0.1:5173 and click **New investigation**. With an evidence workspace
configured below, click **Start monitoring**. New or changed JSONL snapshots in that
folder are analyzed automatically; no manual upload is needed. The notification bell
opens the relevant saved claim and evidence. The source-download button returns the
exact original file.

For development/manual fallback, expand **Manual JSONL import / fallback**, select
fixtures/tiny-supported.jsonl, and click **Import**. Pause monitoring before importing.
Manual import replaces the active source selection; previous evidence snapshots are
retained for notification links. Monitoring correlates all valid selected workspace
files together. Create separate investigations to keep separate selections.

Case access tokens remain in browser sessionStorage. Keep the browser session open.
API clients receive case_id and token from POST /api/v1/cases; subsequent
case requests require an Authorization: Bearer token header. API documentation is at
http://127.0.0.1:8000/docs. This is a local tool; bind servers to loopback.

### Input profile

UTF-8 JSONL, one complete flat Sysmon record per line. Relevant fields:
EventID, Computer, UtcTime or TimeCreated, ProcessGuid, ParentProcessGuid,
ProcessId, Image, CommandLine, DestinationIp, DestinationPort,
Initiated, TargetFilename, EventRecordID, and Channel.

Supported event kinds include process creation/termination, network, file creation,
file deletion, image load, registry set and DNS. Unknown kinds remain evidence.
Raw fields are preserved. Explicit Z/offset timestamps retain their timezone;
naive timestamps remain naive; absent/unparseable timestamps stay unresolved.
No binary EVTX parser is provided.

Imports are limited to 10 MiB, 1 MiB per line and 10,000 lines.
Relationships use a 300-second window. Verified joins require ProcessGuid.
Network claims require explicit outbound Initiated: true and a destination.
Missing prerequisites produce insufficient evidence or no relationship.

### Configuration

[.env.example](.env.example) lists supported settings. Export them in the backend shell;
the app does not automatically load .env files.

- SENTINEL_DB: defaults to .sentinel/cases.db.
- OLLAMA_URL: defaults to http://127.0.0.1:11434; loopback HTTP only.
- OLLAMA_MODEL: empty/absent disables AI. Set to a model already installed locally.
- SENTINEL_EVIDENCE_WORKSPACE: no default; absolute path to an explicitly authorized,
  dedicated evidence folder. Only direct ordinary JSONL files are read.
- SENTINEL_MONITOR_INTERVAL: scan interval in seconds, default 5, bounded to 1–300.

Before starting the backend, authorize your evidence workspace:

~~~sh
export SENTINEL_EVIDENCE_WORKSPACE=/absolute/path/to/your/evidence-workspace
export SENTINEL_MONITOR_INTERVAL=5
~~~

Use one backend worker. Monitoring runs while the backend is running and resumes
enabled subscriptions after restart. A collector/exporter must publish complete JSONL
snapshots into this folder; Sentinel does not yet include an OS-level event collector.
No whole-computer or recursive directory scan occurs. Missing/malformed sources keep
their last valid evidence and display errors; unchanged snapshots do not repeat
processing or notifications. See [monitoring behavior and the collector boundary](docs/monitoring.md).

~~~sh
export OLLAMA_MODEL='your-installed-model'
~~~

Ollama must already be running locally. No cloud service or automatic model download
is used. Requests have a timeout and bounded input/output. The model may return only
the approved explanation object; changes to prose, citations or status are rejected.
This is constrained explanation selection, not general semantic verification of free
prose. Disabled/unavailable/invalid AI returns an explicitly labeled deterministic fallback.

### Headless use and verification

~~~sh
python -m sentinel_evidence.cli fixtures/tiny-supported.jsonl
python -m sentinel_evidence.evaluation --fixtures fixtures
python -m pytest -q
cd web
npm run build
npm run lint
~~~

The CLI and API use the same deterministic engine. Repeated input produces the same
events, claims and output hash; run timestamps record actual execution times.
See [evaluation methodology](docs/evaluation.md). Synthetic fixtures are regression
tests, not a representative security benchmark.

## Work present and challenges

This integration connected the existing foundation and claim modules with the API/UI
from the repository's API branch, adapted the identity implementation to the active
contracts, removed production mock dependencies, added packets/local AI validation,
and introduced integrated/security tests and fixture replay.

The major integration challenges were conflicting branch contracts, invented timestamps,
missing normalization for network/file records, and partial support removal incorrectly
leaving claims verified. The implementation preserves compatible interfaces while
correcting these evidence-integrity defects. Actual Hack Day timing and contribution
history must be confirmed by the team; they are not inferred from code availability.

## Open source, AI and credits

- Python and SQLite provide the local engine/storage; SQLite is public domain.
- FastAPI, Uvicorn, Pydantic, React, TypeScript, Vite and PyYAML are external open-source
  components; their upstream licenses and installed package notices apply.
- Pytest and HTTPX support testing. npm records frontend dependencies in its lockfile.
- Ollama is an optional external local inference runtime. Model weights are external;
  the selected model's own license applies. No model is trained by this team.
- AI-assisted integration/code changes were made with OpenAI Codex in this workspace.
- Fixtures are hand-authored synthetic examples, not real incident captures.

## Submission items still requiring team input

Confirm the team name, event-day history, demo video, Devpost link and project license.
No project license was selected in the existing repository; this integration does not
grant a license on behalf of the contributors. Do not describe the repository as fully
licensed until the team supplies an appropriate LICENSE file.

Independent Windows captures, broader detectors and unconstrained/citation-only model
benchmark comparisons remain future evaluation work. No enterprise-scale accuracy,
performance, or deployment claim is made. The application is intended to run locally.

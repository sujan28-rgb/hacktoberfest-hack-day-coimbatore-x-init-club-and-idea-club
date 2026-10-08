# Integration decisions and remaining submission inputs

The supplied specification is preserved in architecture-spec.md. Implemented Python
contracts remain in src/sentinel_evidence/contracts.py. Existing branches disagreed:
the foundation/claim branch used Event.kind/timestamp/source and event-to-event Edge;
the identity branch used Event.raw_fields/normalized_timestamp and entity-to-entity
Edge. Identity resolution was adapted to the former contract. This avoids replacing
the working scenario and claim implementations.

Event now also preserves raw_fields, original_timestamp_text, timestamp_status and
parse_status. Its timestamp can be null: missing evidence must not become the current
time. Run gained the reproducibility fields from the specification. API presentation
fields are views, with complete canonical claims retained in reports and packets.
Source remains the existing per-record locator; the report adds a per-file manifest.

The engine uses one bounded path: JSONL -> normalization -> explicit encoded-PowerShell
indicator -> identity/edges -> existing scenarios/compiler/validator -> report.
The API saves the report and exact original bytes together in SQLite, scoped by case.
No production path imports a mock. CLI and evaluation call the same engine.

PID fallback resolves only a unique, same-host, bounded candidate with compatible
image context; ambiguous/reused PIDs stay unresolved. Verified scenario joins require
ProcessGuid. All three scenarios use a 300-second bound. Missing time or mixed
timezone knowledge cannot establish a relationship. Explicit outbound direction and
destination are required for network claims.

For AI, arbitrary free-form prose cannot be proven safe by checking citations alone.
The local model returns a deterministic, approved explanation object; every field,
status, citation and sentence must match. Any extra fact or changed status is rejected.
This intentionally limits AI to constrained explanations. It is not an unrestricted
natural-language semantic validator. The full canonical evidence packet is retained;
oversized packets fall back rather than dropping counterevidence.

## Scope and limitations

- Manual import selects one source; workspace monitoring correlates multiple files.
  Historical snapshots retain evidence cited by notifications.
- Flat Sysmon JSONL only. No binary EVTX parser, Hayabusa import or cloud AI.
- The detector is one transparent indicator, not a comprehensive threat ruleset.
- Contradiction detection handles conflicting values for the same host/channel/record
  ID. It does not infer every possible forensic contradiction.
- Case tokens are capabilities held in browser sessionStorage. This is a local,
  single-user tool, not enterprise identity/access management. Closing the browser
  loses the UI session token; API callers can retain their own case token securely.
- SQLite stores canonical normalized reports as JSON alongside original BLOBs.
  The older foundation repository remains available for its existing consumers/tests.
- Source/event/claim results and output hashes reproduce; wall-clock run timestamps differ.
- The replay suite uses three synthetic episodes. Model benchmark baselines B2/B3,
  independent Windows captures, corpus-level precision/recall and RAM/VRAM measurements
  remain research work. No performance result is claimed from these fixtures.

## Inputs only the team can supply

Confirm the team name, actual Hack Day work history, demo/Devpost links and the project
license. Existing README claims about completed event work were not independently
verifiable, so the updated README describes code present instead of inventing history.

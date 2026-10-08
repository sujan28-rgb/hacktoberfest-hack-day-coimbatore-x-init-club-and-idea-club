# Background monitoring and local notifications

## Authorization and operation

The backend can poll a dedicated evidence folder selected by the operator through
SENTINEL_EVIDENCE_WORKSPACE. There is no default directory and no OS event collector.
The supplied workspace adapter uses macOS/Linux safe directory-relative file access;
another platform can supply an EventSource adapter with equivalent safety guarantees.
The UI cannot submit arbitrary filesystem paths. Start monitoring in an authenticated
investigation to bind the configured folder to that case. Each case retains the local
account UID, collector device hostname and workspace directory identity. The original
record's User/host/GUID/PID fields remain unchanged and are not inferred from the collector.

Only direct ordinary JSONL files are supported. Symlinks, hard links, special files and
nested directories are not followed. Reads are bounded, opened relative to a pinned
directory descriptor and checked for modification during the read. Publish complete
export snapshots atomically (write a temporary file and rename it into the workspace).
The worker runs with the FastAPI lifespan, continues while the browser is closed, and
resumes enabled subscriptions when the backend restarts. Run one backend worker.

SENTINEL_MONITOR_INTERVAL defaults to five seconds and is bounded to 1–300 seconds.
There are at most 100 JSONL files/1000 direct entries per scan. The existing aggregate
10 MiB/10,000-event investigation limits still apply.

## One engine and stable provenance

WorkspaceSource implements the EventSource protocol and returns immutable
EvidenceSnapshot objects. A future real local collector can replace this adapter;
the current implementation does not pretend to capture Windows events directly.
Both manual imports and monitored snapshots call prepare_source and investigate
from the existing pipeline. Multiple monitored files can participate in the same
correlation. Unchanged content skips normalization and analysis, including after restart.
When evidence changes, cached normalized sources join the new evidence for correlation.

Every snapshot retains its original bytes, content hash and source locator. Canonical
event IDs continue to derive from source hash plus locator: changing an export creates
a new immutable source version, while previous versions remain inspectable. No new
competing event or claim model is introduced.

## Failures, removal and retention

Malformed, changing or unreadable sources show a monitoring error. The last valid
snapshot of that file remains available; valid changes from other files can still be
processed. Identical rejected content is not repeatedly parsed; Retry clears this
rejection cache. A missing file also retains its last valid snapshot: disappearance
alone does not establish that the reported security activity has been disproved.
A valid replacement export can withdraw claims when their evidence has been removed.

An unavailable/replaced workspace preserves existing analysis. Replacing the configured
directory/account/device requires authorization in a new investigation. Pause waits for
the current scan to finish before returning. Manual imports require monitoring to be
paused; resuming restores the monitored source selection. Ollama is never called by
the monitoring worker.

Reports, original bytes and notifications are persisted in SQLite. Historical reports
are intentionally retained to keep notification citations valid. This MVP has no
automatic evidence-retention/deletion policy; database size can grow as sources change.
Use a dedicated workspace and bounded exports. Paused cases remain readable.

## Evidence-backed notifications

Notifications describe new supported/hypothesis claims, changes to existing claims,
new support, or withdrawal of a previous claim. A file or ordinary event by itself does
not generate a notification. Text preserves canonical claim statuses and does not
claim malware, causation or confirmed maliciousness.

Deduplication compares predicate, bound entities, actual supporting record content,
status, prerequisites, findings and counterevidence. An unrelated appended record can
change source/event IDs without creating a duplicate alert. State transitions are compared
transactionally to the previous report; notification creation and evidence persistence
commit together. Returning to a previous state after a different state is a meaningful
transition and may notify again.

Withdrawal notifications show the previous claim's status explicitly as historical,
and link to its saved report rather than inventing a new deterministic claim. All
notification and snapshot reads use the same case bearer authorization as other APIs.
The UI bell polls investigations whose credentials are held in the current browser
session, shows unread counts, and opens Finding → Claim → Supporting Evidence.

NotificationSink is an optional local desktop/system-tray adapter interface. No OS
permission prompts, cloud delivery or system notification dependency are introduced.
A sink failure cannot remove or block the committed in-app notification.

## Status semantics and endpoints

The panel shows monitoring/paused/processing/error, last scan and last successful poll,
files discovered, changed files processed, events reanalyzed, new findings, new claims
and unread notifications. Counters describe the latest scan, so an unchanged scan shows
zero processed events and zero new claims. Discovered files include rejected JSONL files;
error details explain which ones were retained rather than replaced.

Case-scoped endpoints:

- GET monitor — current persisted status and configured-source availability.
- POST monitor/start, monitor/pause, monitor/retry — authenticated lifecycle controls.
- GET notifications — paginated notifications and the total unread count.
- POST notifications/{id}/read — mark one owned notification as read.
- Existing report/claim/event/packet endpoints accept ?revision={run_id} for historical drill-down.

The existing capability-token model is local and single-user. It is not multi-tenant
account management; bind to loopback. Browser-session token loss does not stop the
backend worker, but the UI cannot recover that case's access token automatically.

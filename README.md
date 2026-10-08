# Sentinel Evidence

## 1. Project Purpose

Sentinel Evidence is a local-first, evidence-grounded security
investigation system for Windows telemetry.

The system ingests documented JSONL evidence, normalizes it, resolves
process identity, correlates bounded activity patterns, compiles typed
claims with exact support sets, optionally uses a local Ollama model for
explanation, validates model output against the evidence, and presents
the result through a FastAPI + React case viewer.

The core principle is:

> Evidence first. Claims second. Explanation last.

The system must never turn telemetry into a stronger conclusion than the
evidence supports.

------------------------------------------------------------------------

## 2. Non-Negotiable Architecture

``` text
JSONL evidence
     |
     v
[1] Intake + Hashing
     |
     v
[2] Normalization
     |
     v
[3] Detector Adapter
     |
     v
[4] Entity Resolution
     |
     v
[5] Correlation / Scenarios
     |
     v
[6] Typed Claim Compiler
     |
     v
[7] Deterministic Report
     |
     +----------------------+
     |                      |
     v                      v
[8] Evidence Packet     [API / UI]
     |
     v
[9] Optional Ollama
     |
     v
[10] Validator
     |
     v
Validated explanation
```

Use one Python package, SQLite, FastAPI, React/TypeScript, and an
optional local model.

Do NOT introduce microservices, Kafka, a graph database, or a vector
database for the MVP.

The engine must work correctly with no model and no UI.

------------------------------------------------------------------------

## 3. Four-Member Ownership

### Sujan --- Evidence Foundation

Owns:

-   Intake
-   Hashing
-   Manifest
-   Resource/path limits
-   JSONL import
-   Source/Event contracts
-   Sysmon normalization
-   Timestamp parsing
-   Raw field/source locators
-   SQLite schema/repository
-   Deterministic event IDs

Must NOT implement:

-   Correlation
-   Claims
-   Ollama
-   React UI
-   API

Primary output:

``` text
raw JSONL -> verified normalized Events -> SQLite
```

------------------------------------------------------------------------

### Pramit --- Correlation and Claims

Owns:

-   Process/entity resolution
-   `(host, ProcessGuid)` identity
-   Bounded PID fallback
-   Parent/child relationships
-   Typed edges
-   Three MVP scenarios
-   Claim types
-   Predicate registry
-   Support sets
-   Contradictory evidence
-   Claim compiler
-   Claim validator

MVP scenarios:

1.  Suspicious parent/child execution
2.  Flagged process + outbound connection
3.  Flagged process + file creation

Must NOT implement:

-   Intake/normalization internals
-   React UI
-   FastAPI
-   Ollama

Primary output:

``` text
Events -> Edges -> Claims
```

------------------------------------------------------------------------

### Sujai --- AI, Validation, Evaluation

Owns:

-   Evidence packet builder
-   Evidence/counterevidence selection
-   Fixed model input budget
-   Ollama integration
-   Structured model output
-   AI output validation
-   Deterministic fallback
-   Evaluation harness
-   Baselines
-   Perturbation/evidence-removal tests
-   Metrics

The model is optional.

The model may explain approved claims but may NOT create new facts,
entities, relationships, values, or unsupported ATT&CK assertions.

Must NOT implement:

-   Core intake
-   Core correlation
-   React UI
-   FastAPI

Primary output:

``` text
validated claims -> bounded evidence packet -> optional AI explanation -> validated output
```

------------------------------------------------------------------------

### Jana --- API, UI, Security

Owns:

-   FastAPI
-   Case-scoped endpoints
-   Pagination
-   React/TypeScript case viewer
-   Timeline
-   Claim panel
-   Evidence drill-down
-   Security tests
-   Safe rendering
-   Case isolation

UI must distinguish:

-   Observed
-   Supported inference
-   Hypothesis
-   Insufficient evidence
-   AI draft

Must NOT implement:

-   Normalization
-   Correlation logic
-   Claim generation
-   Ollama logic

Primary output:

``` text
validated report data -> API -> React evidence viewer
```

------------------------------------------------------------------------

## 4. Shared Contracts --- Freeze Before Coding

All members MUST use these contracts.

### Source

``` text
Source
- source_id
- content_hash
- declared_host
- collection_metadata
- export_metadata
- byte_size
- acquisition_time_if_known
- exporter_version
- original_source_mapping
```

### Event

``` text
Event
- event_id
- source_id
- source_locator
- original_timestamp_text
- normalized_timestamp
- timestamp_status
- host
- provider
- channel
- event_id
- event_record_id
- process_guid
- parent_process_guid
- raw_fields
- parse_status
```

Stable event identity must be derived from source hash + locator.

Never invent timezone information.

Keep original values.

### Finding

``` text
Finding
- finding_id
- detector
- detector_version
- rule_id
- source_event_refs
- original_severity
- matched_fields
- mapping_status
```

If a detector row cannot be mapped unambiguously, mark it unlinked and
exclude it from verified claims.

### Edge

``` text
Edge
- edge_id
- source_entity
- target_entity
- relationship_type
- supporting_events
- identity_assumptions
- temporal_constraints
```

`reported_parent_of` and `near_in_time` are different relationship
types.

Never treat time adjacency as causality.

### Claim

``` text
Claim
- claim_id
- predicate_type
- bound_entities
- support_sets
- contradictory_evidence
- unmet_prerequisites
- status
```

Allowed status values:

``` text
observed
supported_inference
hypothesis
insufficient_evidence
```

### Run

``` text
Run
- run_id
- source_hashes
- parser_version
- detector_version
- rule_version
- policy_version
- model_digest
- prompt_digest
- parameters
- limits
- software_revision
- timestamps
- output_hashes
```

Every reproducible run must record these values.

------------------------------------------------------------------------

## 5. Evidence Rules

These rules apply to EVERY member.

### Never make these unsupported conclusions

Do not infer:

-   phishing from telemetry alone
-   exfiltration from a network connection
-   persistence from file creation
-   successful execution from a process-creation record
-   causality from timestamp proximity
-   identity from an ambiguous PID match

Examples:

``` text
Observed:
Record E2 reports P as Q's parent.

Observed:
Record E3 reports Q connecting to address A.

Not automatically verified:
Q exfiltrated data.
```

### Evidence removal rule

If E3 is the only support for a network-connection claim:

``` text
remove E3
    ->
claim disappears OR becomes insufficient_evidence
```

It must never remain verified without another valid support set.

### Duplicate evidence rule

Repeated exports of the same source are not independent corroboration.

Always retain provenance.

------------------------------------------------------------------------

## 6. Entity Resolution

Preferred process identity:

``` text
(host, ProcessGuid)
```

PID is only a bounded fallback.

Fallback PID matching must consider:

-   host
-   time interval
-   available process context

If identity is ambiguous:

``` text
do not merge
```

Keep it unresolved and surface the uncertainty.

Never merge processes across hosts.

------------------------------------------------------------------------

## 7. Input and Intake

MVP input is a documented JSONL export profile containing complete
selected event records.

Imported JSONL is itself evidence.

Before processing:

1.  Hash original bytes.
2.  Validate file/path limits.
3.  Prevent traversal and unsafe symlink behavior.
4.  Store manifest information.
5.  Finalize imports atomically.
6.  Preserve source locators.
7.  Normalize without deleting raw values.

Do not implement a new binary EVTX parser.

If EVTX bytes are supplied, preserve them when required, but rely on the
documented exporter mapping.

------------------------------------------------------------------------

## 8. Repository Layout

``` text
sentinel-evidence/
├── pyproject.toml
├── uv.lock
├── src/sentinel_evidence/
│   ├── cli.py
│   ├── contracts.py
│   ├── intake/
│   │   ├── manifest.py
│   │   ├── limits.py
│   │   └── store.py
│   ├── adapters/
│   │   ├── jsonl.py
│   │   └── hayabusa.py
│   ├── normalize/
│   │   ├── sysmon.py
│   │   ├── time.py
│   │   └── identity.py
│   ├── correlate/
│   │   ├── edges.py
│   │   └── scenarios.py
│   ├── claims/
│   │   ├── types.py
│   │   ├── predicates.py
│   │   ├── compile.py
│   │   └── validate.py
│   ├── explain/
│   │   ├── packet.py
│   │   ├── ollama.py
│   │   └── schemas.py
│   ├── report/
│   │   ├── template.py
│   │   └── export.py
│   ├── db/
│   │   ├── schema.sql
│   │   ├── repository.py
│   │   └── migrations/
│   └── api/
│       ├── app.py
│       ├── auth.py
│       ├── cases.py
│       └── jobs.py
├── policies/
│   ├── scenarios.yaml
│   ├── severity.yaml
│   └── limits.yaml
├── prompts/
│   └── explain-v1.txt
├── web/
│   └── src/
│       ├── CaseView.tsx
│       ├── ClaimPanel.tsx
│       ├── Timeline.tsx
│       └── api.ts
├── tests/
│   ├── unit/
│   ├── property/
│   ├── integration/
│   └── security/
├── eval/
│   ├── datasets.yaml
│   ├── labels/
│   ├── baselines/
│   ├── perturb.py
│   ├── run.py
│   └── metrics.py
├── fixtures/
│   ├── tiny-supported/
│   ├── tiny-ambiguous/
│   └── tiny-hostile/
└── docs/
    ├── decision.md
    ├── threat-model.md
    ├── evidence-contract.md
    └── evaluation.md
```

Do not change this architecture casually.

------------------------------------------------------------------------

## 9. Integration Dependencies

The dependency order is:

``` text
Sujan
  |
  v
contracts + normalized Events
  |
  v
Pramit
  |
  v
Edges + Claims
  |
  +----------------+
  |                |
  v                v
Sujai             Jana
AI/evaluation     API/UI
```

However, Jana can build against the frozen contracts before the backend
is complete, and Sujai can build the evaluation/packet schemas before
Ollama is connected.

### Required implementation order

#### Phase 0 --- Shared contracts

Everyone agrees on:

-   Source
-   Event
-   Finding
-   Edge
-   Claim
-   Run
-   API response shapes

No implementation should silently change these.

#### Phase 1 --- Foundation

Sujan:

``` text
JSONL -> Source -> Event -> SQLite
```

Pramit starts only after the Event contract is stable.

Jana can create API types from the same contracts.

Sujai can create evidence packet schemas from Claim/Event contracts.

#### Phase 2 --- Deterministic engine

Pramit:

``` text
Event -> identity -> edges -> scenarios -> claims
```

The deterministic claim engine must work without AI.

#### Phase 3 --- API/UI

Jana:

``` text
SQLite/claims -> FastAPI -> React
```

#### Phase 4 --- AI

Sujai:

``` text
validated claims -> evidence packet -> Ollama -> validator
```

AI is added after deterministic claims work.

#### Phase 5 --- Integration

All four run:

-   supported fixture
-   ambiguous fixture
-   hostile/injection fixture
-   evidence-removal fixture

before declaring MVP complete.

------------------------------------------------------------------------

## 10. Git/Antigravity Rules

Each member works in their assigned area.

Before editing:

1.  Inspect existing repository.
2.  Read this README.
3.  Read existing contracts.
4.  Reuse existing code.
5.  Do not rewrite another member's module.
6.  Do not silently change shared schemas.
7.  Add tests with every meaningful feature.
8.  Run relevant tests before committing.

If a shared contract must change:

``` text
STOP
-> document reason
-> update contract
-> update affected members
-> update tests
-> continue
```

Never solve integration problems by creating duplicate models or
adapters.

There must be ONE canonical definition for each core object.

------------------------------------------------------------------------

## 11. Antigravity Instructions

Every Antigravity agent should follow this sequence:

``` text
1. Read README.md completely.
2. Inspect the existing repository.
3. Identify what already exists.
4. Identify your assigned ownership area.
5. Check shared contracts before coding.
6. Implement only your assigned responsibility.
7. Reuse existing interfaces.
8. Add tests.
9. Run tests.
10. Report changed files and integration assumptions.
```

Do not create speculative architecture.

Do not add dependencies unless necessary.

Do not replace working code simply because another implementation looks
cleaner.

Prefer small, testable changes.

------------------------------------------------------------------------

## 12. Member Prompts

### Sujan

``` text
Read README.md first. You own the Evidence Foundation.

Implement only intake, hashing/manifest, limits, JSONL import, Source/Event contracts, Sysmon normalization, timestamp parsing, raw locators, SQLite repository, and deterministic event IDs.

Do not implement correlation, claims, AI, API, or React.

Use the shared contracts exactly. Preserve raw values. Never invent timezone. Add tests and run them. Inspect existing code before changing anything.
```

### Pramit

``` text
Read README.md first. You own Correlation + Claims.

Use the existing Event/Source contracts. Implement process identity using (host, ProcessGuid), bounded PID fallback, parent/child edges, the 3 MVP scenarios, typed predicates, support sets, contradiction handling, claim compilation, and validation.

Do not implement intake, API, React, or Ollama.

Never infer phishing, exfiltration, persistence, successful execution, or causality from insufficient telemetry. Add evidence-removal and ambiguity tests. Run tests.
```

### Sujai

``` text
Read README.md first. You own AI + Evaluation.

Consume only validated Claims/Events. Implement evidence packets, fixed evidence budgets, Ollama integration, structured output, validator, fallback, benchmark harness, baselines, perturbations, and metrics.

AI must never introduce facts, entities, relationships, values, or unsupported ATT&CK claims.

Do not implement intake, correlation, FastAPI, or React. Keep AI optional. Add adversarial/evidence-removal tests and run them.
```

### Jana

``` text
Read README.md first. You own API + React + Security.

Use the canonical contracts. Implement FastAPI case-scoped endpoints, pagination, React case viewer, timeline, claim panel, evidence drill-down, and security tests.

Clearly distinguish observed, supported inference, hypothesis, insufficient evidence, and AI draft.

Do not implement normalization, correlation, claim generation, or Ollama. Do not duplicate domain models. Inspect existing code first, integrate with current contracts, and run tests.
```

------------------------------------------------------------------------

## 13. Testing Requirements

Minimum fixtures:

### Fixture A --- Supported

A process creation followed by a bounded, supported network/file
activity sequence.

Expected:

``` text
identity resolves
edges are created
supported claims are generated
evidence drill-down works
```

### Fixture B --- Ambiguous

Missing/conflicting process identity or PID reuse.

Expected:

``` text
identity remains ambiguous
no unsafe merge
claim becomes insufficient_evidence where required
```

### Fixture C --- Hostile

Contains:

-   prompt injection text
-   malicious HTML
-   path traversal attempts
-   malformed values

Expected:

``` text
no code execution
no XSS
no unsafe file access
no unsupported claim acceptance
```

### Fixture D --- Evidence removal

Start with a valid claim.

Remove its only supporting event.

Expected:

``` text
claim removed OR insufficient_evidence
```

Never:

``` text
claim remains verified
```

------------------------------------------------------------------------

## 14. API/UI Contract

The UI must never independently calculate security claims.

The backend sends validated claim objects.

Example:

``` json
{
  "claim_id": "C123",
  "status": "supported_inference",
  "predicate": "process_connected_to_address",
  "entities": ["Q", "A"],
  "support": [
    {
      "event_id": "E3",
      "fields": ["DestinationIp", "ProcessGuid"]
    }
  ],
  "contradictory_evidence": []
}
```

Clicking the claim must expose:

``` text
Claim
 -> predicate
 -> bound entities
 -> supporting fields
 -> event ID
 -> source locator
 -> original evidence
```

------------------------------------------------------------------------

## 15. AI Safety Contract

The local model is an explanation component, not the source of truth.

Allowed:

``` text
Explain approved claim C123 in simpler language.
```

Not allowed:

``` text
Invent an event explaining why C123 happened.
```

Validator must reject:

-   unknown IDs
-   new entities
-   altered values
-   unsupported relationships
-   unsupported ATT&CK mappings
-   citations that exist but do not support the sentence

Canonical fact sentences should be machine-checked.

Free-form AI prose must remain visibly marked as AI-generated
draft/explanation.

------------------------------------------------------------------------

## 16. Evaluation

Use:

-   tiny hand-authored fixtures
-   public Windows telemetry where permitted
-   fresh controlled Windows VM captures

Do not treat generated variants as independent samples.

Keep all descendants of one original episode in the same split.

Compare:

``` text
B0 = detector/timeline baseline
B1 = deterministic report
B2 = unconstrained local model
B3 = model + citations without claim enforcement
Proposed = typed claims + evidence validation + optional AI
```

Measure:

-   precision
-   recall
-   false-positive rate
-   correlation precision/recall
-   incorrect joins
-   unresolved identity rate
-   supported factual claims
-   unsupported claims
-   critical-fact coverage
-   citation validity
-   citation support
-   evidence sensitivity
-   latency
-   RAM/VRAM
-   model failure rate
-   security failures

Do not claim enterprise-level performance from a small pilot.

------------------------------------------------------------------------

## 17. Definition of Done

The MVP is complete only when:

-   Intake is reproducible.
-   Source hashes are recorded.
-   Events preserve raw values and locators.
-   Process identity is deterministic and ambiguity-aware.
-   Three bounded scenarios work.
-   Every accepted factual claim has valid support.
-   Evidence removal withdraws unsupported claims.
-   Deterministic reporting works without AI.
-   Ollama is optional.
-   AI hallucinated references are rejected.
-   API is case-scoped.
-   UI provides evidence drill-down.
-   Security tests pass.
-   Evaluation can replay the same engine headlessly.
-   Run metadata is reproducible.
-   All four members' modules integrate without duplicate domain models.

------------------------------------------------------------------------

## 18. Final Engineering Principle

Do not optimize for a convincing story.

Optimize for:

``` text
same input
   ->
same normalized evidence
   ->
same deterministic claims
   ->
traceable support
   ->
safe explanation
```

If the evidence is insufficient, the correct result is:

``` text
INSUFFICIENT EVIDENCE
```

That is a successful result, not a failure.
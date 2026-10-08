"""Evidence-derived changes, independent of source file hashes and AI."""
import hashlib
from typing import Protocol
from sentinel_evidence.report.export import encode

VERIFIED = {"observed", "supported_inference"}


class NotificationSink(Protocol):
    """Future local desktop/tray adapters consume committed notifications."""
    def deliver(self, notification: dict) -> None: ...


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def claim_states(report):
    events = {e["event_id"]: e for e in report["events"]}
    states = {}
    for claim in report["claims"]:
        refs = {ref for support in claim["support_sets"] for ref in support["evidence_ids"]}
        # Insufficient claims may have no support_sets, but retain bound event locators.
        refs.update(v for k, v in claim["bound_entities"].items() if k.endswith("_event_id"))
        supporting = [events[r] for r in sorted(refs) if r in events]
        if not supporting:
            continue
        entities = {k: v for k, v in claim["bound_entities"].items() if not k.endswith("_event_id")}
        # Appending unrelated records changes canonical source/event IDs. Compare the
        # actual evidence content and entity values instead, without changing contracts.
        identity = digest({
            "predicate": claim["predicate_type"], "entities": entities,
            "evidence": sorted({digest(e["raw_fields"]) for e in supporting}),
        })
        counter_refs = {r for s in claim["contradictory_evidence"] for r in s["evidence_ids"]}
        state = digest({
            "status": claim["status"], "unmet": sorted(claim["unmet_prerequisites"]),
            "counterevidence": sorted(digest(events[r]["raw_fields"]) for r in counter_refs if r in events),
            "findings": sorted(digest({k: v for k, v in finding.items() if k not in {"finding_id", "matched_event_ids"}})
                               for finding in report["findings"] if finding["finding_id"] in refs),
        })
        states[identity] = {"claim": claim, "fingerprint": state, "events": supporting}
    return states


def changes(previous, current):
    before, after = claim_states(previous), claim_states(current)
    notifications = []
    for key, item in after.items():
        old = before.get(key)
        claim = item["claim"]
        if old and old["fingerprint"] == item["fingerprint"]:
            continue
        # A missing prerequisite on its own is not a new security finding.
        if old is None and claim["status"] not in VERIFIED | {"hypothesis"}:
            continue
        kind = "claim_changed" if old else "new_claim"
        if old and old["claim"]["status"] not in VERIFIED and claim["status"] in VERIFIED:
            kind = "claim_supported"
        notifications.append(notification(key, item, current, kind))
    for key, old in before.items():
        if key not in after and old["claim"]["status"] in VERIFIED | {"hypothesis"}:
            # Link to the immutable prior evidence; never manufacture a new Claim.
            notifications.append(notification(key, old, previous, "claim_withdrawn"))
    return notifications


def notification(key, item, report, kind):
    claim = item["claim"]
    titles = {"new_claim": "New investigation result", "claim_changed": "Investigation result changed",
              "claim_supported": "Claim is now supported", "claim_withdrawn": "Previous claim no longer present"}
    refs = {ref for support in claim["support_sets"] for ref in support["evidence_ids"]}
    findings = [f["finding_id"] for f in report["findings"] if f["finding_id"] in refs]
    images = sorted({e["image"] for e in item["events"] if e.get("image")})
    return {
        "semantic_key": key, "type": kind, "title": titles[kind],
        "claim_id": claim["claim_id"], "predicate": claim["predicate_type"],
        "status": claim["status"], "historical": kind == "claim_withdrawn",
        "host": claim["bound_entities"].get("host", ""), "entities": images,
        "supporting_event_ids": [e["event_id"] for e in item["events"]],
        "supporting_evidence_count": len(item["events"]), "finding_ids": findings,
        "revision_id": report["run"]["run_id"],
        "message": ("This claim is absent from the latest analysis. Review its previous evidence."
                    if kind == "claim_withdrawn" else
                    "Review the deterministic claim, its status and supporting evidence."),
    }

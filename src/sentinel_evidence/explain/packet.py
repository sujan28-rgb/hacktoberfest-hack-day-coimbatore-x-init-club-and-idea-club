"""Budgeted packets preserve complete claims, counterevidence and provenance."""
from sentinel_evidence.report.export import encode
from sentinel_evidence.claims.predicates import PREDICATE_REGISTRY
from sentinel_evidence.contracts import PredicateType

MAX_PACKET_BYTES = 32768


def build_packet(report, claim_id):
    claim = next((c for c in report["claims"] if c["claim_id"] == claim_id), None)
    if claim is None:
        raise KeyError(claim_id)
    refs = {ref for support in claim["support_sets"] + claim["contradictory_evidence"]
            for ref in support["evidence_ids"]}
    edges = [e for e in report["edges"] if e["edge_id"] in refs]
    findings = [f for f in report["findings"] if f["finding_id"] in refs]
    for edge in edges:
        refs.update((edge["source_event_id"], edge["target_event_id"]))
    for finding in findings:
        refs.update(finding["matched_event_ids"])
    events = [e for e in report["events"] if e["event_id"] in refs]
    source_ids = {e["source"]["file_hash"] for e in events}
    packet = {"claim": claim, "events": events, "edges": edges, "findings": findings,
              "sources": [s for s in report["sources"] if s["source_id"] in source_ids],
              "run_id": report["run"]["run_id"]}
    if len(encode(packet).encode()) > MAX_PACKET_BYTES:
        # Do not truncate away a contradiction or prerequisite to satisfy the budget.
        raise ValueError("Complete evidence packet exceeds the model input budget")
    return packet


def approved_explanation(packet):
    claim = packet["claim"]
    descriptions = {
        "suspicious_parent_child": "Records report a parent/child process relationship flagged by a detector.",
        "flagged_process_network": "Records link a detector-flagged process to a reported outbound connection.",
        "flagged_process_file_create": "Records link a detector-flagged process to a reported file creation.",
    }
    statement = descriptions.get(claim["predicate_type"], "A typed claim was produced from the evidence.")
    if claim["status"] in {"hypothesis", "insufficient_evidence"}:
        statement = "This claim is not established; inspect its missing prerequisites and evidence."
    limitations = PREDICATE_REGISTRY[PredicateType(claim["predicate_type"])].prohibitions
    text = f'{statement} Deterministic status: {claim["status"]}. ' + " ".join(limitations)
    if claim["contradictory_evidence"]:
        text += " Contradictory evidence is present and must be reviewed."
    return {"claim_id": claim["claim_id"], "status": claim["status"],
            "evidence_ids": sorted(e["event_id"] for e in packet["events"]), "explanation": text}

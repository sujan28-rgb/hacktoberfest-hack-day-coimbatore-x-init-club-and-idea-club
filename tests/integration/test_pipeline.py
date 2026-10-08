import copy
import hashlib
import json
from pathlib import Path
import pytest
from sentinel_evidence.pipeline import analyze
from sentinel_evidence.explain.packet import build_packet, approved_explanation
from sentinel_evidence.explain.ollama import explain

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures"


def supported():
    return (FIXTURE / "tiny-supported.jsonl").read_bytes()


def test_three_scenarios_and_reproducible_provenance():
    contents = supported()
    report = analyze(contents)
    repeated = analyze(contents)
    assert report["events"] == repeated["events"]
    assert report["claims"] == repeated["claims"]
    assert report["run"]["output_hashes"] == repeated["run"]["output_hashes"]
    assert len(report["claims"]) == 3
    assert all(c["status"] == "supported_inference" for c in report["claims"])
    assert len(report["edges"]) == 3
    for event, line in zip(report["events"], contents.splitlines(keepends=True)):
        assert event["source"]["raw_hash"] == hashlib.sha256(line).hexdigest()
        assert event["raw_fields"] == json.loads(line)
        assert event["timestamp"].endswith("+00:00")
    for claim in report["claims"]:
        packet = build_packet(report, claim["claim_id"])
        assert packet["claim"] == claim
        assert packet["events"] and packet["sources"]


def test_evidence_removal_withdraws_network_claim():
    lines = supported().splitlines()
    report = analyze(b"\n".join(line for line in lines if json.loads(line)["EventID"] != 3))
    assert not any(c["predicate_type"] == "flagged_process_network" for c in report["claims"])


def test_ambiguous_pid_never_joins():
    report = analyze((FIXTURE / "tiny-ambiguous.jsonl").read_bytes())
    assert not report["edges"] and not report["claims"]
    event = report["events"][-1]
    assert report["identities"][event["event_id"]]["method"] == "unresolved_or_ambiguous"


@pytest.mark.parametrize("change", ["other_host", "missing_time", "missing_guid", "outside_window", "inbound", "unknown_direction"])
def test_invalid_prerequisites_never_produce_verified_network_claim(change):
    rows = [json.loads(line) for line in supported().splitlines()]
    network = rows[2]
    if change == "other_host": network["Computer"] = "OTHER"
    if change == "missing_time": network.pop("UtcTime")
    if change == "missing_guid": network.pop("ProcessGuid")
    if change == "outside_window": network["UtcTime"] = "2026-10-08T12:00:00Z"
    if change == "inbound": network["Initiated"] = False
    if change == "unknown_direction": network.pop("Initiated")
    report = analyze("\n".join(json.dumps(r) for r in rows).encode())
    assert not any(c["predicate_type"] == "flagged_process_network" and c["status"] in {"observed", "supported_inference"} for c in report["claims"])


def test_missing_and_naive_timestamps_are_not_fabricated():
    report = analyze(b'{"EventID":1}\n{"EventID":1,"UtcTime":"2026-10-08 10:00:00"}\n')
    assert report["events"][0]["timestamp"] is None
    assert report["events"][0]["timestamp_status"] == "missing"
    assert report["events"][1]["timestamp"] == "2026-10-08T10:00:00"


class Echo:
    def generate(self, packet, approved):
        return approved


class Hallucination:
    def generate(self, packet, approved):
        return {**approved, "explanation": "Confirmed exfiltration and persistence."}


class Unavailable:
    def generate(self, packet, approved):
        raise OSError("offline")


def test_ai_validates_facts_not_just_existing_citations():
    report = analyze(supported())
    claim_id = report["claims"][0]["claim_id"]
    assert explain(report, claim_id, Echo())["status"] == "validated_ai_explanation"
    assert explain(report, claim_id, Hallucination())["status"] == "deterministic_fallback"
    assert explain(report, claim_id, Unavailable())["status"] == "deterministic_fallback"


def test_counterevidence_and_status_preserved():
    report = analyze(supported())
    claim = report["claims"][0]
    claim["contradictory_evidence"] = copy.deepcopy(claim["support_sets"])
    claim["status"] = "hypothesis"
    claim["unmet_prerequisites"] = ["Conflicting evidence requires review"]
    packet = build_packet(report, claim["claim_id"])
    assert packet["claim"]["contradictory_evidence"] == claim["contradictory_evidence"]
    assert approved_explanation(packet)["status"] == "hypothesis"
    assert "not established" in approved_explanation(packet)["explanation"]
    assert explain(report, claim["claim_id"], Echo())["claim_status"] == "hypothesis"


def test_packet_budget_never_drops_counterevidence():
    report = analyze(supported())
    report["claims"][0]["contradictory_evidence"] = [{"evidence_ids": [], "relevant_fields": {"long": "x" * 40000}, "description": "counterevidence"}]
    with pytest.raises(ValueError):
        build_packet(report, report["claims"][0]["claim_id"])
    assert explain(report, report["claims"][0]["claim_id"], Echo())["status"] == "deterministic_fallback"

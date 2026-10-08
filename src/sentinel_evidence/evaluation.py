"""Replay hand-authored episodes and removal perturbations through the production engine."""
import argparse
import json
import time
import tracemalloc
from pathlib import Path
from sentinel_evidence.pipeline import analyze


def evaluate(directory):
    expected = {
        "tiny-supported.jsonl": {"suspicious_parent_child", "flagged_process_network", "flagged_process_file_create"},
        "tiny-ambiguous.jsonl": set(),
        "tiny-hostile.jsonl": {"flagged_process_file_create"},
    }
    results = []
    for name, labels in expected.items():
        contents = (directory / name).read_bytes()
        tracemalloc.start()
        start = time.perf_counter()
        report = analyze(contents, name)
        latency = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        predicted = {c["scenario_id"] for c in report["claims"] if c["status"] in {"observed", "supported_inference"}}
        tp, fp, fn = len(predicted & labels), len(predicted - labels), len(labels - predicted)
        universe = {"suspicious_parent_child", "flagged_process_network", "flagged_process_file_create"}
        tn = len(universe - labels - predicted)
        sensitivity_checks = []
        rows = contents.splitlines()
        for index, row in enumerate(rows):
            kind = json.loads(row).get("EventID")
            withdrawn = {3: "flagged_process_network", 11: "flagged_process_file_create"}.get(kind)
            if withdrawn and withdrawn in labels:
                variant = analyze(b"\n".join(rows[:index] + rows[index + 1:]), name)
                sensitivity_checks.append(not any(c["scenario_id"] == withdrawn and c["status"] in {"observed", "supported_inference"} for c in variant["claims"]))
        known = {e["event_id"] for e in report["events"]} | {e["edge_id"] for e in report["edges"]} | {f["finding_id"] for f in report["findings"]}
        refs = [ref for c in report["claims"] for support in c["support_sets"] for ref in support["evidence_ids"]]
        results.append({
            "episode": name, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "citation_validity": sum(ref in known for ref in refs) / len(refs) if refs else None,
            "unresolved_identity_rate": sum(i["entity_id"] is None for i in report["identities"].values()) / len(report["events"]),
            "evidence_removal_checks": sensitivity_checks,
            "latency_seconds": latency, "peak_python_bytes": peak,
            "baseline_B0": {"events": len(report["events"]), "findings": len(report["findings"])},
            "baseline_B1": {"verified_claims": len(predicted)},
            "run": report["run"],
        })
    return {"episodes": results, "B2_B3": "not measured; unconstrained model baselines are not implemented",
            "limitations": "Three synthetic episodes; perturbations belong to their parent episode. No independent benchmark, RAM/VRAM, or enterprise performance claim.",
            "passed": all(r["fp"] == r["fn"] == 0 and all(r["evidence_removal_checks"]) for r in results)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures"))
    args = parser.parse_args()
    result = evaluate(args.fixtures)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()

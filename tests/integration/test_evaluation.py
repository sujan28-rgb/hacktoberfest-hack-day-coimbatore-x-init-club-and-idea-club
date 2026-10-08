from pathlib import Path
from sentinel_evidence.evaluation import evaluate


def test_production_engine_replay_and_removal():
    result = evaluate(Path(__file__).resolve().parents[2] / "fixtures")
    assert result["passed"]
    assert len(result["episodes"]) == 3

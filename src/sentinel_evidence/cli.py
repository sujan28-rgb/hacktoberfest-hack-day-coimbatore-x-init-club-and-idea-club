"""Headless entry point using the same engine as the API."""
import argparse
from pathlib import Path
from sentinel_evidence.pipeline import analyze
from sentinel_evidence.intake.limits import IntakeLimits
from sentinel_evidence.report.export import encode


def main():
    parser = argparse.ArgumentParser(description="Analyze a flat Sysmon JSONL export locally")
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        path = IntakeLimits.validate_path(args.evidence)
        print(encode(analyze(path.read_bytes(), path.name)))
    except (ValueError, OSError) as error:
        parser.exit(2, f"Import failed: {error}\n")


if __name__ == "__main__":
    main()

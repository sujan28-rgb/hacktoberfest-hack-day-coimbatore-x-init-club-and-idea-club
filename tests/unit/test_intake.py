"""Unit tests for Sujan's Evidence Foundation module (using Python standard library unittest)."""

import json
import unittest
import tempfile
from pathlib import Path
from sentinel_evidence.contracts import Source, Event
from sentinel_evidence.intake.limits import IntakeLimits, IntakeLimitError
from sentinel_evidence.intake.manifest import create_source_manifest
from sentinel_evidence.adapters.jsonl import parse_jsonl_stream
from sentinel_evidence.normalize.sysmon import normalize_sysmon_event, compute_deterministic_event_id
from sentinel_evidence.db.repository import EvidenceRepository


class TestEvidenceFoundation(unittest.TestCase):

    def test_contracts_initialization(self):
        source = Source(file_hash="hash123", file_path="/path/test.jsonl", line_number=1, raw_hash="raw123")
        self.assertEqual(source.file_hash, "hash123")

    def test_intake_limits_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample.jsonl"
            sample_file.write_text('{"EventID": 1, "Computer": "HOST-01", "UtcTime": "2026-10-08 11:00:00"}\n')

            source = create_source_manifest(sample_file, declared_host="HOST-01")
            self.assertEqual(len(source.file_hash), 64)

    def test_invalid_extension_rejection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "sample.txt"
            bad_file.write_text("hello")
            with self.assertRaises(IntakeLimitError):
                IntakeLimits.validate_path(bad_file)

    def test_jsonl_streaming(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample.jsonl"
            sample_file.write_text('{"EventID": 1, "UtcTime": "2026-10-08 11:00:00"}\n{"invalid_json"\n')

            records = list(parse_jsonl_stream(sample_file))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0][0], "line:1")
            self.assertEqual(records[0][1]["EventID"], 1)
            self.assertIn("_parse_error", records[1][1])

    def test_sysmon_normalization(self):
        raw_fields = {
            "EventID": 1,
            "Computer": "WORKSTATION-01",
            "UtcTime": "2026-10-08 11:00:00.123",
            "ProcessGuid": "{12345678-1234-1234-1234-123456789012}"
        }
        event = normalize_sysmon_event("hash123", "/path/sample.jsonl", 1, raw_fields)
        self.assertEqual(event.event_id, compute_deterministic_event_id("hash123", "line:1"))
        self.assertEqual(event.host, "WORKSTATION-01")
        self.assertEqual(event.process_guid, "{12345678-1234-1234-1234-123456789012}")

    def test_repository_persistence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = str(Path(tmp_dir) / "test.db")
            repo = EvidenceRepository(db_file)

            source = Source(file_hash="hash999", file_path="/path/test.jsonl", line_number=1, raw_hash="raw999")
            inserted = repo.insert_source(source)
            self.assertTrue(inserted)

            event = normalize_sysmon_event("hash999", "/path/test.jsonl", 1, {"EventID": 1, "Computer": "HOST-01"})
            repo.insert_events_batch([event])

            self.assertEqual(repo.get_event_count(), 1)
            repo.close()


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the canonical-contract/API-schema merge decision."""

from dataclasses import fields, is_dataclass

from sentinel_evidence.api.models import ApiEvent, ApiSource
from sentinel_evidence.contracts import Event, Source


def test_pipeline_contracts_remain_canonical_dataclasses():
    assert is_dataclass(Source)
    assert is_dataclass(Event)
    assert {field.name for field in fields(Source)} == {
        "file_hash",
        "file_path",
        "line_number",
        "raw_hash",
    }
    assert "source" in {field.name for field in fields(Event)}
    assert "fields" in {field.name for field in fields(Event)}


def test_mock_api_schemas_are_explicit_adapters_not_contract_replacements():
    assert ApiSource is not Source
    assert ApiEvent is not Event
    assert "source_id" in ApiEvent.model_fields
    assert "raw_fields" in ApiEvent.model_fields

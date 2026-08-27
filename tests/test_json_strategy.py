"""Unit tests for nested JSON / JSONB masking strategy."""

import json

import pytest

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.registry import StrategyRegistry


@pytest.fixture
def base_context() -> TransformationContext:
    return TransformationContext(
        table_name="audit_logs",
        column_name="payload",
        row_index=1,
        seed=1337,
        salt="test-secret-salt",
    )


def test_json_mask_dot_notation(base_context: TransformationContext):
    strat = StrategyRegistry.get("json_mask")
    raw_payload = json.dumps(
        {
            "user": {
                "name": "Bruce Wayne",
                "email": "bruce@wayne-enterprises.com",
                "age": 35,
            },
            "status": "ACTIVE",
        }
    )

    rules = {
        "user.name": {"strategy": "constant", "params": {"value_to_set": "REDACTED NAME"}},
        "user.email": {
            "strategy": "faker",
            "params": {"provider": "email", "preserve_domain": True},
        },
    }

    result = strat.transform(raw_payload, base_context, rules=rules)
    assert isinstance(result, str)
    parsed = json.loads(result)
    assert parsed["user"]["name"] == "REDACTED NAME"
    assert parsed["user"]["email"].endswith("@wayne-enterprises.com")
    assert not parsed["user"]["email"].startswith("bruce@")
    assert parsed["user"]["age"] == 35
    assert parsed["status"] == "ACTIVE"


def test_json_mask_array_wildcard(base_context: TransformationContext):
    strat = StrategyRegistry.get("json_mask")
    raw_payload = json.dumps(
        {
            "orders": [
                {"id": 101, "credit_card": "4532015012345678", "total": 120.50},
                {"id": 102, "credit_card": "5425233430109823", "total": 85.00},
            ]
        }
    )

    rules = {
        "orders[*].credit_card": {"strategy": "credit_card_mask"},
        "orders[*].total": {"strategy": "constant", "params": {"value_to_set": 0.0}},
    }

    result = strat.transform(raw_payload, base_context, rules=rules)
    parsed = json.loads(result)
    assert len(parsed["orders"]) == 2
    assert parsed["orders"][0]["credit_card"] == "****-****-****-5678"
    assert parsed["orders"][1]["credit_card"] == "****-****-****-9823"
    assert parsed["orders"][0]["total"] == 0.0
    assert parsed["orders"][1]["total"] == 0.0
    assert parsed["orders"][0]["id"] == 101


def test_json_mask_specific_index_and_dict_wildcard(base_context: TransformationContext):
    strat = StrategyRegistry.get("json_mask")
    raw_payload = json.dumps(
        {
            "tokens": ["tok_abc_123", "tok_def_456"],
            "metadata": {
                "ip": "192.168.1.1",
                "agent": "Mozilla/5.0",
            },
        }
    )

    rules = {
        "tokens[0]": {"strategy": "constant", "params": {"value_to_set": "REDACTED_TOK"}},
        "metadata.*": {"strategy": "constant", "params": {"value_to_set": "[FILTERED]"}},
    }

    result = strat.transform(raw_payload, base_context, rules=rules)
    parsed = json.loads(result)
    assert parsed["tokens"][0] == "REDACTED_TOK"
    assert parsed["tokens"][1] == "tok_def_456"
    assert parsed["metadata"]["ip"] == "[FILTERED]"
    assert parsed["metadata"]["agent"] == "[FILTERED]"


def test_json_mask_dict_input_and_type_preservation(base_context: TransformationContext):
    strat = StrategyRegistry.get("json_mask")
    raw_dict = {
        "is_admin": True,
        "score": 98.5,
        "count": 42,
        "secret": "top-secret",
        "null_val": None,
    }

    rules = {
        "secret": {"strategy": "nullify"},
        "count": {"strategy": "jitter", "params": {"percentage": 10.0}},
    }

    result = strat.transform(raw_dict, base_context, rules=rules)
    assert isinstance(result, dict)
    assert result["is_admin"] is True
    assert result["score"] == 98.5
    assert result["secret"] is None
    assert result["null_val"] is None
    assert isinstance(result["count"], int)


def test_json_mask_error_handling_and_edge_cases(base_context: TransformationContext):
    strat = StrategyRegistry.get("json_mask")

    # None input
    assert strat.transform(None, base_context) is None

    # Empty rules
    assert strat.transform('{"a": 1}', base_context, rules=None) == '{"a": 1}'

    # Non-JSON string passthrough
    assert strat.transform("regular text", base_context, rules={"a": "nullify"}) == "regular text"

    # Malformed JSON
    malformed = "{ unclosed json"
    assert strat.transform(malformed, base_context, rules={"a": "nullify"}) == malformed

    with pytest.raises(ValueError, match="Failed to parse JSON string"):
        strat.transform(malformed, base_context, rules={"a": "nullify"}, error_handling="raise")

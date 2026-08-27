"""Nested JSON and JSONB masking strategy with dot-notation and wildcard path resolution."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import StrategyRegistry, register_strategy

_INDEX_REGEX = re.compile(r"^([^\[]+)?\[(\*|\d+)\]$")


def _tokenize_path(path: str) -> list[str]:
    """Tokenizes a JSON dot-notation path into traversal segments.

    Examples:
        'profile.contact.email' -> ['profile', 'contact', 'email']
        'orders[*].credit_card' -> ['orders', '[*]', 'credit_card']
        'items[0].sku' -> ['items', '[0]', 'sku']
        'metadata.*' -> ['metadata', '*']
    """
    tokens: list[str] = []
    for part in path.strip().split("."):
        part = part.strip()
        if not part:
            continue
        # Check for bracket indexing in segment (e.g., 'orders[*]' or 'items[0]')
        match = _INDEX_REGEX.match(part)
        if match:
            field_name, index_spec = match.groups()
            if field_name:
                tokens.append(field_name)
            tokens.append(f"[{index_spec}]")
        else:
            tokens.append(part)
    return tokens


def _apply_sub_rule(
    val: Any,
    sub_rule: Any,
    context: TransformationContext,
) -> Any:
    """Executes a masking sub-rule on a target leaf value."""
    if isinstance(sub_rule, str):
        strategy_name = sub_rule
        params: dict[str, Any] = {}
        keep_null = True
    elif hasattr(sub_rule, "strategy"):
        strategy_name = sub_rule.strategy
        params = dict(getattr(sub_rule, "params", {}) or {})
        keep_null = getattr(sub_rule, "keep_null", True)
    elif isinstance(sub_rule, dict):
        strategy_name = sub_rule.get("strategy", "nullify")
        params = dict(sub_rule.get("params", {}))
        keep_null = sub_rule.get("keep_null", True)
    else:
        return val

    if val is None and keep_null:
        return None

    strat = StrategyRegistry.get(strategy_name)
    return strat.transform(val, context, **params)


def _traverse_and_mask(
    data: Any,
    tokens: list[str],
    sub_rule: Any,
    context: TransformationContext,
) -> Any:
    """Recursively traverses nested dicts/lists along path tokens and applies masking."""
    if not tokens:
        return _apply_sub_rule(data, sub_rule, context)

    current_token = tokens[0]
    remaining_tokens = tokens[1:]

    if current_token == "[*]":
        if isinstance(data, list):
            return [_traverse_and_mask(item, remaining_tokens, sub_rule, context) for item in data]
        return data

    if current_token.startswith("[") and current_token.endswith("]"):
        idx_str = current_token[1:-1]
        if idx_str.isdigit() and isinstance(data, list):
            idx = int(idx_str)
            if 0 <= idx < len(data):
                data[idx] = _traverse_and_mask(data[idx], remaining_tokens, sub_rule, context)
        return data

    if current_token == "*":
        if isinstance(data, dict):
            for k in list(data.keys()):
                data[k] = _traverse_and_mask(data[k], remaining_tokens, sub_rule, context)
        return data

    if isinstance(data, dict) and current_token in data:
        data[current_token] = _traverse_and_mask(
            data[current_token], remaining_tokens, sub_rule, context
        )
        return data

    return data


@register_strategy("json_mask", aliases=["json", "jsonb"])
class JSONMaskStrategy(MaskingStrategy):
    """Masks nested fields inside JSON and Postgres JSONB string or dictionary payloads."""

    description = "Masks nested keys inside JSON/JSONB payloads using dot-notation & wildcards"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        rules: dict[str, Any] | None = None,
        error_handling: str = "passthrough",
        ensure_ascii: bool = False,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        if not rules:
            return value

        is_string_input = isinstance(value, str)
        if is_string_input:
            trimmed = value.strip()
            if not (trimmed.startswith("{") or trimmed.startswith("[")):
                return value
            try:
                parsed_json = json.loads(trimmed)
            except Exception as err:
                if error_handling == "raise":
                    raise ValueError(f"Failed to parse JSON string: {err}") from err
                return value
        elif isinstance(value, (dict, list)):
            parsed_json = copy.deepcopy(value)
        else:
            return value

        # Apply each path rule
        for path_expr, sub_rule in rules.items():
            tokens = _tokenize_path(path_expr)
            parsed_json = _traverse_and_mask(parsed_json, tokens, sub_rule, context)

        if is_string_input:
            return json.dumps(parsed_json, ensure_ascii=ensure_ascii)

        return parsed_json

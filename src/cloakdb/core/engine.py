"""Core masking orchestration engine."""

from __future__ import annotations

import ast
import operator
import time
from collections.abc import Callable
from typing import Any

from cloakdb.config.models import CloakConfig, ColumnRule, TableRule
from cloakdb.core.context import MaskingStats, TransformationContext
from cloakdb.core.integrity import ReferentialIntegrityManager
from cloakdb.strategies.registry import StrategyRegistry

_SAFE_OPERATORS: dict[type, Callable[..., Any]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Not: operator.not_,
}


def _eval_ast_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        key = node.id.lower()
        for k, v in context.items():
            if str(k).lower().strip().strip('"').strip("`").strip("[]") == key:
                return v
        return None
    if isinstance(node, ast.UnaryOp):
        op_fn = _SAFE_OPERATORS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        return op_fn(_eval_ast_node(node.operand, context))
    if isinstance(node, ast.BinOp):
        op_fn = _SAFE_OPERATORS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported binary operator: {type(node.op).__name__}")
        return op_fn(_eval_ast_node(node.left, context), _eval_ast_node(node.right, context))
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(_eval_ast_node(val, context) for val in node.values)
        if isinstance(node.op, ast.Or):
            return any(_eval_ast_node(val, context) for val in node.values)
        raise ValueError(f"Unsupported boolean operator: {type(node.op).__name__}")
    if isinstance(node, ast.Compare):
        left = _eval_ast_node(node.left, context)
        for op, comparator in zip(node.ops, node.comparators):
            op_fn = _SAFE_OPERATORS.get(type(op))
            if op_fn is None:
                raise ValueError(f"Unsupported comparison operator: {type(op).__name__}")
            right = _eval_ast_node(comparator, context)
            if not op_fn(left, right):
                return False
            left = right
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_eval_ast_node(el, context) for el in node.elts]
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


def evaluate_condition(condition_str: str, row_data: dict[str, Any]) -> bool:
    """Safely evaluates a boolean condition on row data using AST traversal."""
    if not condition_str or not condition_str.strip():
        return True
    try:
        parsed = ast.parse(condition_str.strip(), mode="eval")
        result = _eval_ast_node(parsed.body, row_data)
        return bool(result)
    except Exception:
        return False


class CloakEngine:
    """Central processing engine for database anonymization and masking."""

    def __init__(
        self,
        config: CloakConfig,
        incremental_since: str | None = None,
        incremental_column: str | None = None,
    ):
        self.config = config
        self.incremental_since = incremental_since
        self.incremental_column = incremental_column
        self.stats = MaskingStats()
        cache_enabled = (
            self.config.global_settings.cache_pseudonyms
            and not getattr(self.config.global_settings, "stateless", False)
        )
        self.integrity_manager = ReferentialIntegrityManager(
            groups=config.consistency_groups,
            max_cache_size=config.global_settings.max_cache_size,
            cache_enabled=cache_enabled,
        )

        # Normalize table names for case-insensitive / quoted lookup
        self._table_rules: dict[str, TableRule] = {}
        for tbl_name, rule in config.tables.items():
            self._table_rules[self._normalize_name(tbl_name)] = rule

    def _normalize_name(self, name: str) -> str:
        return name.strip().strip('"').strip("`").strip("[]").lower()

    def get_table_rule(self, table_name: str) -> TableRule | None:
        """Looks up rules for a table name (case-insensitive & quote-agnostic)."""
        return self._table_rules.get(self._normalize_name(table_name))

    def should_truncate_table(self, table_name: str) -> bool:
        rule = self.get_table_rule(table_name)
        return bool(rule and rule.truncate)

    def mask_row_values(
        self,
        table_name: str,
        column_names: list[str],
        row_values: list[Any],
        row_index: int = 0,
    ) -> list[Any]:
        """Masks an ordered list of values corresponding to column names in a table."""
        tbl_rule = self.get_table_rule(table_name)
        composite_groups = self.integrity_manager.get_composite_groups_for_table(table_name)
        if (not tbl_rule or not tbl_rule.columns) and not composite_groups:
            return row_values

        row_dict = dict(zip(column_names, row_values))
        masked_dict = self.mask_record(table_name, row_dict, row_index=row_index)
        return [masked_dict.get(col, orig) for col, orig in zip(column_names, row_values)]

    def _apply_composite_groups(self, table_name: str, record: dict[str, Any]) -> dict[str, Any]:
        """Applies referential integrity consistency to multi-column composite keys."""
        composite_groups = self.integrity_manager.get_composite_groups_for_table(table_name)
        if not composite_groups:
            return dict(record)

        output = dict(record)
        norm_keys = {self._normalize_name(k): k for k in record.keys()}

        for cols_tuple, group in composite_groups:
            if not all(c in norm_keys for c in cols_tuple):
                continue

            actual_keys = [norm_keys[c] for c in cols_tuple]
            raw_vals = tuple(record[k] for k in actual_keys)

            if any(v is None for v in raw_vals):
                continue

            cached_tuple = self.integrity_manager.get_cached_value(group.name, raw_vals)
            if cached_tuple is not None and isinstance(cached_tuple, (tuple, list)):
                for k, masked_v in zip(actual_keys, cached_tuple):
                    output[k] = masked_v
                self.stats.cells_masked += len(actual_keys)
                continue

            # Deterministic composite HMAC derivation
            import hashlib
            import hmac

            salt = self.config.global_settings.salt
            masked_list: list[Any] = []
            for idx, orig_v in enumerate(raw_vals):
                token = f"{group.name}:{raw_vals}:{idx}".encode("utf-8")
                h = hmac.new(salt.encode("utf-8"), token, hashlib.sha256).digest()
                res_val: str | int
                if isinstance(orig_v, int):
                    res_val = 100000 + (int.from_bytes(h[:8], "big") % 899999)
                else:
                    res_val = h.hex()[:16]
                masked_list.append(res_val)

            masked_tuple = tuple(masked_list)
            self.integrity_manager.store_cached_value(group.name, raw_vals, masked_tuple)

            for k, masked_v in zip(actual_keys, masked_tuple):
                output[k] = masked_v
            self.stats.cells_masked += len(actual_keys)

        return output

    def mask_record(
        self,
        table_name: str,
        record: dict[str, Any],
        row_index: int = 0,
    ) -> dict[str, Any]:
        """Masks a dictionary record representing a database row."""
        output_record = self._apply_composite_groups(table_name, record)
        tbl_rule = self.get_table_rule(table_name)
        if not tbl_rule or not tbl_rule.columns:
            self.stats.rows_processed += 1
            return output_record

        norm_keys = {self._normalize_name(k): k for k in record.keys()}

        # Incremental masking check
        if self.incremental_since:
            inc_col = self._normalize_name(self.incremental_column) if self.incremental_column else None
            matched_key = None
            if inc_col:
                matched_key = norm_keys.get(inc_col)
            else:
                for candidate in ("updated_at", "created_at", "modified_at", "timestamp", "date"):
                    if candidate in norm_keys:
                        matched_key = norm_keys[candidate]
                        break

            if matched_key and record.get(matched_key) is not None:
                val_str = str(record[matched_key])
                if val_str < self.incremental_since:
                    self.stats.rows_processed += 1
                    return dict(record)

        for col_name, col_rule in tbl_rule.columns.items():
            norm_col = self._normalize_name(col_name)
            if norm_col in norm_keys:
                actual_key = norm_keys[norm_col]
                orig_val = output_record[actual_key]
                masked_val = self._apply_column_rule(
                    table_name=table_name,
                    column_name=actual_key,
                    value=orig_val,
                    rule=col_rule,
                    row_index=row_index,
                    row_data=output_record,
                )
                output_record[actual_key] = masked_val

        self.stats.rows_processed += 1
        return output_record

    def _apply_column_rule(
        self,
        table_name: str,
        column_name: str,
        value: Any,
        rule: ColumnRule,
        row_index: int,
        row_data: dict[str, Any],
    ) -> Any:
        """Applies a single column rule to a value, respecting conditions and referential integrity."""
        # Handle NULL values
        if value is None and rule.keep_null:
            return None

        # Check optional condition
        if rule.condition and not evaluate_condition(rule.condition, dict(row_data)):
            return value

        # Check referential integrity / consistency group
        group = self.integrity_manager.get_group_for_column(table_name, column_name)
        group_name = rule.consistency_group or (group.name if group else None)

        if group_name and value is not None:
            cached = self.integrity_manager.get_cached_value(group_name, value)
            if cached is not None:
                self.stats.cells_masked += 1
                return cached

        # Strategy resolution
        strategy_name = (group.strategy if group else None) or rule.strategy
        strategy_params = dict(group.params if group else {})
        strategy_params.update(rule.params)

        strategy = StrategyRegistry.get(strategy_name)

        ctx = TransformationContext(
            table_name=table_name,
            column_name=column_name,
            row_index=row_index,
            row_data=row_data,
            seed=self.config.global_settings.seed,
            salt=self.config.global_settings.salt,
            locale=self.config.global_settings.locale,
            group_name=group_name,
            stats=self.stats,
            integrity_manager=self.integrity_manager,
        )

        masked_value = strategy.transform(value, ctx, **strategy_params)

        if group_name and value is not None:
            self.integrity_manager.store_cached_value(group_name, value, masked_value)

        self.stats.cells_masked += 1
        return masked_value

    def finish(self) -> MaskingStats:
        """Finalizes execution and marks timing."""
        self.stats.end_time = time.perf_counter()
        return self.stats

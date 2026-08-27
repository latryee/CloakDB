"""Core masking orchestration engine."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from cloakdb.config.models import CloakConfig, ColumnRule, TableRule
from cloakdb.core.context import MaskingStats, TransformationContext
from cloakdb.core.integrity import ReferentialIntegrityManager
from cloakdb.strategies.registry import StrategyRegistry


class CloakEngine:
    """Central processing engine for database anonymization and masking."""

    def __init__(self, config: CloakConfig):
        self.config = config
        self.stats = MaskingStats()
        self.integrity_manager = ReferentialIntegrityManager(
            groups=config.consistency_groups,
            max_cache_size=config.global_settings.max_cache_size,
            cache_enabled=config.global_settings.cache_pseudonyms,
        )

        # Normalize table names for case-insensitive / quoted lookup
        self._table_rules: Dict[str, TableRule] = {}
        for tbl_name, rule in config.tables.items():
            self._table_rules[self._normalize_name(tbl_name)] = rule

    def _normalize_name(self, name: str) -> str:
        return name.strip().strip('"').strip('`').strip('[]').lower()

    def get_table_rule(self, table_name: str) -> Optional[TableRule]:
        """Looks up rules for a table name (case-insensitive & quote-agnostic)."""
        return self._table_rules.get(self._normalize_name(table_name))

    def should_truncate_table(self, table_name: str) -> bool:
        rule = self.get_table_rule(table_name)
        return bool(rule and rule.truncate)

    def mask_row_values(
        self,
        table_name: str,
        column_names: List[str],
        row_values: List[Any],
        row_index: int = 0,
    ) -> List[Any]:
        """Masks an ordered list of values corresponding to column names in a table."""
        tbl_rule = self.get_table_rule(table_name)
        if not tbl_rule or not tbl_rule.columns:
            return row_values

        # Build column index to rule map
        normalized_cols = [self._normalize_name(c) for c in column_names]
        rule_map: Dict[int, ColumnRule] = {}
        for col_name, col_rule in tbl_rule.columns.items():
            norm = self._normalize_name(col_name)
            if norm in normalized_cols:
                idx = normalized_cols.index(norm)
                rule_map[idx] = col_rule

        if not rule_map:
            return row_values

        row_dict = dict(zip(normalized_cols, row_values))
        output_values = list(row_values)

        for col_idx, col_rule in rule_map.items():
            if col_idx >= len(row_values):
                continue
            orig_val = row_values[col_idx]
            col_name = column_names[col_idx]
            masked_val = self._apply_column_rule(
                table_name=table_name,
                column_name=col_name,
                value=orig_val,
                rule=col_rule,
                row_index=row_index,
                row_data=row_dict,
            )
            output_values[col_idx] = masked_val

        self.stats.rows_processed += 1
        return output_values

    def mask_record(
        self,
        table_name: str,
        record: Dict[str, Any],
        row_index: int = 0,
    ) -> Dict[str, Any]:
        """Masks a dictionary record representing a database row."""
        tbl_rule = self.get_table_rule(table_name)
        if not tbl_rule or not tbl_rule.columns:
            return record

        output_record = dict(record)
        norm_keys = {self._normalize_name(k): k for k in record.keys()}

        for col_name, col_rule in tbl_rule.columns.items():
            norm_col = self._normalize_name(col_name)
            if norm_col in norm_keys:
                actual_key = norm_keys[norm_col]
                orig_val = record[actual_key]
                masked_val = self._apply_column_rule(
                    table_name=table_name,
                    column_name=actual_key,
                    value=orig_val,
                    rule=col_rule,
                    row_index=row_index,
                    row_data=record,
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
        row_data: Dict[str, Any],
    ) -> Any:
        """Applies a single column rule to a value, respecting conditions and referential integrity."""
        # Handle NULL values
        if value is None and rule.keep_null:
            return None

        # Check optional condition
        if rule.condition:
            try:
                # Safe evaluation with row_data
                cond_passed = bool(eval(rule.condition, {"__builtins__": {}}, dict(row_data)))
                if not cond_passed:
                    return value
            except Exception:
                pass

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

"""Configuration schemas and validation models using Pydantic v2."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ColumnRule(BaseModel):
    """Configuration rule for masking a specific database column."""

    strategy: str = Field(
        ...,
        description="Masking strategy identifier (e.g. 'faker', 'deterministic_hash', 'pattern_mask', 'jitter', 'nullify')",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Strategy-specific parameters (e.g. provider='email', salt='secret', format='***')",
    )
    condition: str | None = Field(
        default=None,
        description="Optional boolean Python/SQL expression condition to evaluate before masking",
    )
    keep_null: bool = Field(
        default=True,
        description="If True, existing NULL/None values will not be altered",
    )
    consistency_group: str | None = Field(
        default=None,
        description="Group name to maintain referential consistency across foreign keys",
    )

    @field_validator("strategy")
    @classmethod
    def normalize_strategy_name(cls, v: str) -> str:
        return v.strip().lower()


class TableRule(BaseModel):
    """Masking rules for a database table."""

    columns: dict[str, ColumnRule] = Field(
        default_factory=dict,
        description="Map of column name to masking rule",
    )
    where_clause: str | None = Field(
        default=None,
        description="Optional WHERE clause filter for live database processing",
    )
    truncate: bool = Field(
        default=False,
        description="If True, table contents will be skipped/truncated",
    )


class ConsistencyGroup(BaseModel):
    """Defines a relationship where multiple columns across tables share deterministic pseudonyms."""

    name: str = Field(..., description="Unique name of the consistency group")
    columns: list[str] = Field(
        ...,
        description="List of 'table.column' references that must mask to identical pseudonyms",
    )
    strategy: str = Field(
        default="deterministic_hash",
        description="Strategy to use for this consistency group",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for the group strategy",
    )


class GlobalConfig(BaseModel):
    """Global runtime settings for the anonymization engine."""

    seed: int | None = Field(
        default=42,
        description="Global PRNG seed for reproducible synthetic data generation",
    )
    salt: str = Field(
        default="cloakdb-default-salt-v1",
        description="HMAC secret salt for deterministic hashing",
    )
    locale: str = Field(
        default="en_US",
        description="Locale for synthetic Faker generation (e.g. en_US, tr_TR, de_DE, fr_FR)",
    )
    batch_size: int = Field(
        default=5000,
        ge=1,
        le=100000,
        description="Batch chunk size for streaming and database operations",
    )
    cache_pseudonyms: bool = Field(
        default=True,
        description="Cache synthetic replacements in memory to ensure consistent cross-table mapping",
    )
    max_cache_size: int = Field(
        default=500000,
        description="Maximum entries to keep in consistency LRU cache",
    )


class CloakConfig(BaseModel):
    """Root configuration object for CloakDB."""

    version: str = Field(default="1", description="Configuration schema version")
    global_settings: GlobalConfig = Field(
        default_factory=GlobalConfig,
        alias="global",
        description="Global engine parameters",
    )
    tables: dict[str, TableRule] = Field(
        default_factory=dict,
        description="Rules per table name",
    )
    consistency_groups: list[ConsistencyGroup] = Field(
        default_factory=list,
        description="Referential integrity consistency groups",
    )

    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

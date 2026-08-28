"""Configuration schemas and validation models using Pydantic v2."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    rules: dict[str, Any] | None = Field(
        default=None,
        description="Optional nested field path rules for composite/JSON masking",
    )

    @field_validator("strategy")
    @classmethod
    def normalize_strategy_name(cls, v: str) -> str:
        return v.strip().lower()

    def model_post_init(self, __context: Any) -> None:
        if self.rules is not None and "rules" not in self.params:
            self.params["rules"] = self.rules


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
        ...,
        description="HMAC secret salt for deterministic hashing",
    )
    salt_fingerprint: str | None = Field(
        default=None,
        description="Deterministic SHA-256 fingerprint of the salt to ensure FK integrity across runs",
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
    stateless: bool = Field(
        default=False,
        description="Run in purely stateless mode with O(1) memory and no in-memory cache",
    )
    max_cache_size: int = Field(
        default=500000,
        description="Maximum entries to keep in consistency LRU cache",
    )

    @field_validator("salt")
    @classmethod
    def validate_salt(cls, v: Any) -> str:
        if not v or not isinstance(v, str) or not v.strip():
            raise ValueError(
                "Global salt is not set. Populate `global.salt` with a random value of at "
                "least 32 chars, e.g. `python -c 'import secrets; print(secrets.token_hex(32))'`."
            )
        return v

    def compute_fingerprint(self) -> str:
        """Calculates the SHA-256 fingerprint for the current active salt."""
        import hashlib

        return hashlib.sha256(self.salt.strip().encode("utf-8")).hexdigest()[:16]

    def verify_fingerprint(self) -> bool:
        """Verifies if the configured salt_fingerprint matches the current active salt."""
        if not self.salt_fingerprint:
            return True
        return self.salt_fingerprint == self.compute_fingerprint()


class CloakConfig(BaseModel):
    """Root configuration object for CloakDB."""

    version: str = Field(default="1", description="Configuration schema version")
    global_settings: GlobalConfig = Field(
        ...,
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

    @model_validator(mode="before")
    @classmethod
    def validate_global_salt_present(cls, data: Any) -> Any:
        if isinstance(data, dict):
            g = data.get("global") if "global" in data else data.get("global_settings")
            if g is None:
                raise ValueError(
                    "Global salt is not set. Populate `global.salt` with a random value of at "
                    "least 32 chars, e.g. `python -c 'import secrets; print(secrets.token_hex(32))'`."
                )
            if isinstance(g, dict):
                s = g.get("salt")
                if not s or not isinstance(s, str) or not s.strip():
                    raise ValueError(
                        "Global salt is not set. Populate `global.salt` with a random value of at "
                        "least 32 chars, e.g. `python -c 'import secrets; print(secrets.token_hex(32))'`."
                    )
        return data

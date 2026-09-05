# CloakDB Roadmap

This document outlines the planned future direction and engineering priorities for CloakDB.

## Completed Architectural Milestones ✅

- [x] **Nested JSON / JSONB Masking (`json_mask`)**: Recursive dot-notation and wildcard path traversal (`profile.contact.email`, `orders[*].card`, `metadata.*`).
- [x] **Multi-Core Chunk Streaming (`ParallelStreamParser`)**: Bounded-queue parallel streaming with `--workers N`.
- [x] **Extended SQL Dialects**: MS SQL Server (T-SQL bracketed identifiers, `N'...'` unicode literals, `IDENTITY_INSERT`, `GO`) and Oracle SQL (`REM`, `PROMPT`, quoted identifiers).
- [x] **Safe AST Expression Evaluator**: Elimination of arbitrary code execution vectors in conditional masking.
- [x] **Zero-Hardcoded Secrets & Dynamic Salt Generation**: Complete elimination of static fallback salts and enforced cryptographically secure random salt initialization.
- [x] **Golden Integration Fixture Suite**: End-to-end multi-table relational tests.
- [x] **Semantic Redaction in Free-Text (`text_redact`)**: In-place unstructured entity redaction for customer notes, support tickets, and chat logs.
- [x] **Mathematical Privacy Evaluator (`cloakdb evaluate`)**: Formal $k$-anonymity, $l$-diversity, and re-identification risk metrics engine.
- [x] **Referential Data Subsetting (`cloakdb subset`)**: Relational foreign-key graph traversal for proportional staging dataset extraction.
- [x] **GitHub Actions Step Summaries & PR Annotations**: Native `$GITHUB_STEP_SUMMARY` and workflow commands.
- [x] **Pluggable KMS & Secret Vault Providers**: Pluggable secret salt and FPE key providers (Env, HashiCorp Vault, AWS KMS).
- [x] **Ecosystem Connectors**: Native DuckDB connector and Apache Airflow `CloakDBOperator`.

---

## Planned Future Priorities

### 1. Direct PyPI Distribution & Signed Releases
- Set up automated GitHub Actions release workflow publishing wheels and sdist packages directly to PyPI with provenance attestations upon git tag creation.

### 2. Additional Database Connectors
- Native connectors for MongoDB collections and ClickHouse tables for live staging sanitization.


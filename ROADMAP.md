# CloakDB Roadmap

This document outlines the planned future direction and engineering priorities for CloakDB.

## Completed Architectural Milestones ✅

- [x] **Nested JSON / JSONB Masking (`json_mask`)**: Recursive dot-notation and wildcard path traversal (`profile.contact.email`, `orders[*].card`, `metadata.*`).
- [x] **Multi-Core Chunk Streaming (`ParallelStreamParser`)**: Bounded-queue parallel streaming with `--workers N`.
- [x] **Extended SQL Dialects**: MS SQL Server (T-SQL bracketed identifiers, `N'...'` unicode literals, `IDENTITY_INSERT`, `GO`) and Oracle SQL (`REM`, `PROMPT`, quoted identifiers).
- [x] **Safe AST Expression Evaluator**: Elimination of arbitrary code execution vectors in conditional masking.
- [x] **Golden Integration Fixture Suite**: End-to-end multi-table relational tests.

---

## Planned Future Priorities

### 1. Semantic Redaction in Free-Text
- Integrate regex and NLP entity recognition for partial PII redaction inside unstructured text fields (e.g. customer support notes).

### 2. Direct PyPI Distribution & Signed Releases
- Set up automated GitHub Actions release workflow publishing wheels and sdist packages directly to PyPI with provenance attestations upon git tag creation.

### 3. Additional Database Connectors
- Native connectors for MongoDB collections and ClickHouse tables for live staging sanitization.

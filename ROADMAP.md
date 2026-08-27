# CloakDB Roadmap

This document outlines the planned future direction and engineering priorities for CloakDB.

## Planned Features & Enhancements

### 1. Nested JSON / JSONB Masking
- Currently, CloakDB treats JSON column payloads as opaque strings.
- Future work will add recursive key-path masking for JSON/JSONB columns (e.g. `raw_payload.user.email` -> mask with `faker`).

### 2. Expanded SQL Dialect Support
- Add specialized parsers and test suites for Microsoft SQL Server (`T-SQL`), Oracle SQL dumps, and MariaDB specific syntax.

### 3. Semantic Redaction in Free-Text
- Integrate regex and NLP entity recognition for partial PII redaction inside unstructured text fields (e.g. customer support notes).

### 4. Direct PyPI Distribution
- Set up automated GitHub Actions release workflow publishing wheels and sdist packages directly to PyPI upon git tag creation.

### 5. Additional Connectors
- Native support for MongoDB collections and ClickHouse tables for live staging sanitization.

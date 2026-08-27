# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Nested JSON / JSONB Masking Engine (`json_mask`)**: Support for dot-notation (`profile.contact.email`), array wildcards (`orders[*].card`), and object wildcards (`metadata.*`) with native data type preservation.
- **Multi-Core Chunk Streaming Parser (`ParallelStreamParser`)**: ProcessPoolExecutor-based bounded producer-consumer streaming via `cloakdb apply --workers N`.
- **Extended SQL Dialects**: Microsoft SQL Server (T-SQL bracketed identifiers, `N'...'` unicode string prefixes, `IDENTITY_INSERT`, `GO`) and Oracle SQL (`REM`, `PROMPT`, quoted identifiers).
- Safe AST-based condition evaluation replacing unsafe `eval()` expressions.
- Golden integration test fixture suite (`tests/fixtures/`) verifying end-to-end multi-table relational masking.
- Memory tracking with `tracemalloc` in benchmarking tools and CLI `cloakdb bench`.
- Automated CodeQL static analysis and Dependabot configuration.
- Comprehensive unit test suite with 70 passing tests.

### Changed
- Improved explicit seed scoping and cache-independent `ConsistencyGroup` determinism.
- Strict type checking with Mypy and automated linting/formatting with Ruff.
- Updated supported Python versions to Python 3.10, 3.11, and 3.12.

## [0.1.0] - 2024-03-01

### Added
- Initial release of CloakDB streaming masking engine.
- CLI commands: `scan`, `preview`, `apply`, `init`, `strategies`, and `bench`.
- Support for PostgreSQL `COPY`/`INSERT`, MySQL, SQLite, CSV, and JSONL streams.
- Referential integrity manager with LRU caching and HMAC-SHA256 pseudonymization.
- 17+ masking strategies including Faker, deterministic hashing, date shifting, numeric jitter, redaction, and Turkish TCKN generation.
- Automated PII detection with Luhn credit card and Mod-10/11 TCKN validation.

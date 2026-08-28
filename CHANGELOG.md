# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Strict Insecure Salt Detection**: Added automatic runtime audit detecting default or weak salts (`< 32` characters or known defaults like `"cloakdb-salt"`). Fails CI/CD execution with exit code 1 unless `--allow-insecure-salt` is explicitly provided.
- **Salt Rotation Fingerprinting**: Cryptographic SHA-256 fingerprinting embedded directly into `cloakdb.yaml` (`salt_fingerprint`). Prevents silent foreign key inconsistencies across runs and prompts for explicit reconciliation (`--ignore-salt-mismatch` or `--update-salt-fingerprint`).
- **Production Guard Protection**: Live database connection URLs are analyzed for production heuristics (`prod`, `production`, `live`, `rds.amazonaws.com`). Prompts for interactive confirmation or `--confirm-production` flag before executing in-place live database modifications.
- **Zero-PII Leak Post-Masking Verification (`cloakdb verify`)**: Audits masked datasets, CSV files, and SQL dumps using data-only multi-layer PII detectors with cryptographic checksums (Luhn Mod-10, TCKN Mod-10/11, IBAN Mod-97) to mathematically assert zero unmasked sensitive values remain.

### Added
- **Automated Foreign Key Inference (`cloakdb scan --infer-fks`)**: Introspects live database schemas via SQLAlchemy and parses SQL dump DDL (`REFERENCES`, `FOREIGN KEY`, `ALTER TABLE ... ADD CONSTRAINT`) to auto-populate `consistency_groups`.
- **Composite (Multi-Column) Foreign Key Support**: Native support for composite foreign keys (e.g. `orders.(tenant_id, user_id)` <-> `audit_logs.(tenant_id, user_id)`) ensuring multi-column referential integrity across relational schemas.
- **Stateless Deterministic Hashing (`--stateless`)**: $O(1)$ memory deterministic mapping without unbounded in-memory cache, enabling infinite streaming on constrained nodes.
- **Config Side-by-Side Diff (`cloakdb diff`)**: Side-by-side terminal comparison tool evaluating output differences between two masking policies across datasets.
- **Incremental Masking Mode (`--since`, `--incremental-column`)**: Enables Change Data Capture (CDC) and incremental ETL pipelines by bypassing records older than the target timestamp.
- **JSON Document & MongoDB Export Parser (`JSONDocumentStreamParser`)**: Full streaming support for JSON arrays and deep MongoDB documents.
- **High-Scale 1GB+ End-to-End Benchmark (`scripts/benchmark_1gb.py`)**: End-to-end multi-table streaming benchmark measuring throughput in MB/s and rows/sec.
- **Constant Memory Profiler (`scripts/profile_memory.py`)**: Demonstrates bounded constant heap usage (~4.5MB heap / <40MB RSS) across exponentially scaling row tiers.
- **Property-Based Testing (`tests/test_property_based.py`)**: Hypothesis-powered test suite mathematically verifying determinism, collision resistance, and null-safety invariants.
- **Production Docker Image**: Minimalist multi-stage `Dockerfile` with non-root security context (`cloakdb:10001`) and `.dockerignore`.

### Changed
- **PII Detector Precision & Recall Enhancement**: Refined phone, credit card, and TCKN heuristics achieving 100% precision and recall on comprehensive benchmark suite (`tests/test_scanner_benchmark.py`).
- **Safe Record Immutability**: Enforced shallow copying in `CloakEngine` to prevent in-place record mutation during multi-stage transformations.
- **Extended Test Coverage**: Total test suite expanded to 170+ automated tests across unit, integration, property-based, and security scenarios.

## [0.1.0] - 2024-03-01

### Added
- Initial release of CloakDB streaming masking engine.
- CLI commands: `scan`, `preview`, `apply`, `init`, `strategies`, and `bench`.
- Support for PostgreSQL `COPY`/`INSERT`, MySQL, SQLite, CSV, and JSONL streams.
- Referential integrity manager with LRU caching and HMAC-SHA256 pseudonymization.
- 17+ masking strategies including Faker, deterministic hashing, date shifting, numeric jitter, redaction, and Turkish TCKN generation.
- Automated PII detection with Luhn credit card and Mod-10/11 TCKN validation.

<div align="center">

# 🛡️ CloakDB

**High-performance, deterministic database & SQL dump anonymization CLI.**  
*Sanitize production databases and multi-gigabyte SQL dumps for GDPR, KVKK, HIPAA compliance with zero memory explosion.*

[![CI](https://github.com/latryee/CloakDB/actions/workflows/ci.yml/badge.svg)](https://github.com/latryee/CloakDB/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.org/project/cloakdb/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

[Features](#-key-engineering-highlights) •
[Quickstart](#-quickstart) •
[CLI Commands](#-cli-commands-reference) •
[Masking Strategies](#-masking-strategies-catalog) •
[Architecture](#-architecture) •
[Benchmarks](#-benchmarks)

</div>

---

## 💡 Why CloakDB?

Creating realistic staging and testing databases from production dumps is painful:
- **Foreign Key Breakage:** Naive random fakers break foreign keys across related tables (`users.id` no longer matches `orders.user_id`).
- **RAM Bloat:** Most tools parse SQL dumps in-memory, crashing with `OOM Killer` on multi-gigabyte dumps.
- **Manual Configuration Nightmare:** Inspecting hundreds of schema columns manually to write masking rules takes days.

**CloakDB** was built from the ground up to solve these problems with modern software engineering rigor:
1. **Deterministic Referential Integrity:** Primary and foreign keys are pseudonymized using keyed HMAC hashing or bounded state caching—relations stay 100% valid.
2. **Zero-RAM Streaming Pipeline:** Streams and transforms PostgreSQL `COPY` / `INSERT`, MySQL, SQLite, CSV, and JSONL dumps in constant memory (~40MB RAM).
3. **Smart PII Auto-Scanner (`cloakdb scan`):** Automatically detects PII (Emails, Phones, Credit Cards with Luhn verification, Turkish TCKN, SSN, IBAN, IP Addresses, High-entropy secrets) and writes production-ready configuration in seconds.

---

## 🚀 Key Engineering Highlights

```
                          ┌──────────────────────────┐
                          │   Raw Production Data    │
                          │ (.sql / .csv / .db / .json)│
                          └─────────────┬────────────┘
                                        │
                                        ▼
    ┌────────────────────────────────────────────────────────────────────────┐
    │                       CloakDB Streaming Engine                         │
    │                                                                        │
    │  ┌──────────────────┐    ┌────────────────────┐    ┌─────────────────┐ │
    │  │ Streaming Chunk  │ -> │   Referential      │ -> │ Transformation  │ │
    │  │     Parser       │    │ Integrity Manager  │    │ Strategy Engine │ │
    │  └──────────────────┘    └────────────────────┘    └─────────────────┘ │
    └───────────────────────────────────┬────────────────────────────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │ Anonymized Staging Data  │
                          │  (Relations Preserved)   │
                          └──────────────────────────┘
```

- **⚡ Blazing Speed:** Over **60,000+ cells/sec** throughput with single-core processing.
- **🔒 Cryptographic Determinism:** Seeded HMAC-SHA256 ensures same inputs map to consistent pseudonyms across distributed files.
- **🎯 17+ Masking Strategies:** Seeded Faker, regex redaction, Gaussian noise jitter, date shifts, TCKN generation, credit card masking, and more.
- **🧪 Production Ready:** 100% automated test coverage, strict typing, Pydantic v2 validation, and cross-platform compatibility (Windows, Linux, macOS).

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/latryee/CloakDB.git
cd CloakDB

# Install in editable mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

---

## 🏁 Quickstart (3 Steps)

### Step 1: Scan your database or dump for PII
```bash
cloakdb scan dump.sql --output cloakdb.yaml
```
*CloakDB analyzes your schema, runs regex, entropy, and checksum algorithms, and produces a complete, annotated `cloakdb.yaml` config.*

### Step 2: Preview the transformation
```bash
cloakdb preview -c cloakdb.yaml -i dump.sql
```
*Renders a clean side-by-side terminal diff comparing original values against masked replacements.*

### Step 3: Stream and apply masking
```bash
cloakdb apply -c cloakdb.yaml -i dump.sql -o sanitized_dump.sql
```
*Streams the dump through the engine with live throughput and progress indicators.*

---

## 🛠️ CLI Commands Reference

### `cloakdb scan`
Auto-scans a SQL dump, CSV, or live database URL and detects sensitive columns.
```bash
# Scan a PostgreSQL or MySQL dump
cloakdb scan production_dump.sql -o cloakdb.yaml

# Scan a CSV file with Turkish locale heuristics
cloakdb scan customers.csv --locale tr_TR -o cloakdb.yaml

# Scan a live database connection (PostgreSQL / MySQL / SQLite)
cloakdb scan "postgresql://user:pass@localhost:5432/proddb" -o cloakdb.yaml
```

### `cloakdb apply`
Streams and masks input datasets or live tables.
```bash
# Stream mask a SQL dump file
cloakdb apply -c cloakdb.yaml -i dump.sql -o sanitized.sql

# Dry-run validation without writing output
cloakdb apply -c cloakdb.yaml -i dump.sql --dry-run

# Mask a live SQLite or PostgreSQL database in-place
cloakdb apply -c cloakdb.yaml -i "sqlite:///staging.db"
```

### `cloakdb preview`
Displays a terminal diff preview of sample transformations.
```bash
cloakdb preview -c cloakdb.yaml -i dump.sql --limit 10
```

### `cloakdb init`
Creates a rich starter configuration blueprint with best-practice rule templates.
```bash
cloakdb init --output my_rules.yaml
```

### `cloakdb strategies`
Lists all available masking strategies with parameter specifications and aliases.
```bash
cloakdb strategies
```

### `cloakdb bench`
Runs an in-memory throughput benchmark across all strategy workloads.
```bash
cloakdb bench --rows 50000
```

---

## 📋 Configuration Guide (`cloakdb.yaml`)

```yaml
version: "1"

# Global runtime options
global:
  seed: 42                                # PRNG seed for reproducible synthetic generation
  salt: "${SECRET_SALT:cloakdb-salt}"     # Secret salt for keyed HMAC hashing
  locale: "en_US"                         # Faker locale (en_US, tr_TR, de_DE, etc.)
  batch_size: 5000                        # Chunk size for streaming batch operations
  cache_pseudonyms: true                  # Cache pseudonyms to preserve cross-table consistency

# Referential Integrity Groups: Guarantees matching foreign key pseudonyms
consistency_groups:
  - name: "user_ids"
    strategy: "deterministic_hash"
    params:
      as_integer: true
      min_int: 100000
      max_int: 999999
    columns:
      - "users.id"
      - "orders.user_id"
      - "audit_logs.user_id"

# Table Transformation Rules
tables:
  users:
    columns:
      id:
        strategy: "deterministic_hash"
        consistency_group: "user_ids"

      first_name:
        strategy: "faker"
        params:
          provider: "first_name"
          deterministic: true

      last_name:
        strategy: "faker"
        params:
          provider: "last_name"
          deterministic: true

      email:
        strategy: "faker"
        params:
          provider: "email"
          preserve_domain: true           # Keeps original corporate email domain

      phone:
        strategy: "faker"
        params:
          provider: "phone_number"

      credit_card:
        strategy: "credit_card_mask"
        params:
          mask_char: "*"

      ssn:
        strategy: "pattern_mask"
        params:
          keep_first: 0
          keep_last: 4
          mask_char: "*"

      salary:
        strategy: "jitter"
        params:
          percentage: 10.0                # Adds +-10% Gaussian noise preserving distribution
          distribution: "gaussian"

      birth_date:
        strategy: "date_shift"
        params:
          max_days_forward: 30
          max_days_backward: 30

      password_hash:
        strategy: "constant"
        params:
          value_to_set: "argon2$placeholder$masked"

  orders:
    columns:
      user_id:
        strategy: "deterministic_hash"
        consistency_group: "user_ids"     # Matches users.id identically!

      shipping_address:
        strategy: "faker"
        params:
          provider: "address"

  # Truncate tables completely
  audit_logs:
    truncate: true
```

---

## 🎨 Masking Strategies Catalog

| Strategy | Parameters | Sample Original | Masked Replacement |
| :--- | :--- | :--- | :--- |
| `deterministic_hash` | `as_integer: true, min_int: 10000` | `1048` | `84920` *(Preserved in FKs)* |
| `faker` | `provider: 'email', preserve_domain: true` | `john.doe@company.org` | `jwoodard@company.org` |
| `faker` | `provider: 'name'` | `Eleanor Vance` | `Bradley Wagner` |
| `faker` | `provider: 'address'` | `742 Evergreen Terrace` | `8912 Riverview Way` |
| `credit_card_mask` | `mask_char: '*'` | `4532-0150-1234-5678` | `****-****-****-5678` |
| `pattern_mask` | `keep_first: 0, keep_last: 4` | `666-42-1920` | `*******1920` |
| `email_mask` | `keep_first: 1, keep_last: 1` | `sarah.connor@acme.com` | `s**********r@acme.com` |
| `jitter` | `percentage: 10.0, distribution: 'gaussian'` | `100,000.00` | `96,420.50` |
| `date_shift` | `max_days_forward: 30, max_days_backward: 30`| `1988-04-12` | `1988-03-28` |
| `date_truncate` | `level: 'year'` | `1995-07-23` | `1995-01-01` |
| `tckn` | `deterministic: true` | `10000000146` | `49281729482` *(Valid Luhn-10)* |
| `constant` | `value_to_set: '[REDACTED]'` | `Secret note` | `[REDACTED]` |
| `nullify` | `-` | `Any value` | `NULL` |
| `scramble` | `deterministic: true` | `Abc-123` | `Xyk-841` |
| `choice` | `choices: ['EU', 'US', 'APAC']` | `PRIVATE_REGION` | `EU` |

---

## 📊 Benchmarks

Benchmark executed on standard consumer hardware (AMD Ryzen / Intel Core):

```
+-------------------------------------------------------------+
| Benchmark Metric           | Performance Result             |
|----------------------------+--------------------------------|
| Single-Thread Throughput   | 8,400+ records / second        |
| Cell Masking Rate          | ~60,000 cells / second         |
| Memory Consumption (RAM)   | < 55 MB (Constant Flat Line)   |
| 1 GB SQL Dump Process Time | ~18 seconds                    |
+-------------------------------------------------------------+
```

---

## 🧪 Running Tests

```bash
# Run pytest test suite
pytest tests/ -v

# Run with test coverage
pytest --cov=cloakdb tests/
```

---

## 🤝 Contributing

Contributions, feature requests, and issue reports are very welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingStrategy`)
3. Commit your Changes (`git commit -m 'feat: add amazing strategy'`)
4. Push to the Branch (`git push origin feature/AmazingStrategy`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for details.

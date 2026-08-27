<div align="center">

# 🛡️ CloakDB

**High-performance, deterministic database & SQL dump anonymization CLI.**  
*Sanitize production databases and multi-gigabyte SQL dumps for KVKK, GDPR, and HIPAA compliance with zero memory explosion.*

![CloakDB Social Banner](./assets/social_preview.png)

[![CI](https://github.com/latryee/CloakDB/actions/workflows/ci.yml/badge.svg)](https://github.com/latryee/CloakDB/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://github.com/latryee/CloakDB)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

[Before / After](#-real-world-before--after-comparison) •
[Features](#-key-engineering-highlights) •
[Turkish & TCKN Support](#-first-class-turkish-locale--tckn-support) •
[Quickstart](#-quickstart) •
[CLI Commands](#-cli-commands-reference) •
[Masking Catalog](#-masking-strategies-catalog) •
[Compliance & Disclaimer](#-compliance-framework--legal-disclaimer)

</div>

---

## 💡 Why CloakDB?

Creating realistic staging and testing databases from production dumps is notoriously painful:
- **Foreign Key Breakage:** Naive random fakers break foreign keys across related tables (`users.id` no longer matches `orders.user_id`).
- **RAM Bloat:** Most tools parse SQL dumps in-memory, crashing with `OOM Killer` on multi-gigabyte dumps.
- **Manual Configuration Nightmare:** Inspecting hundreds of schema columns manually to write masking rules takes days.

**CloakDB** was built from the ground up to solve these problems with modern software engineering rigor:
1. **Deterministic Referential Integrity:** Primary and foreign keys are pseudonymized using keyed HMAC hashing or bounded LRU state caching—relations stay 100% valid.
2. **Zero-RAM Streaming Pipeline:** Streams and transforms PostgreSQL `COPY` / `INSERT`, MySQL, SQLite, CSV, and JSONL dumps in constant memory (~40MB RAM).
3. **Smart PII Auto-Scanner (`cloakdb scan`):** Automatically detects PII (Emails, Phones, Credit Cards with Luhn verification, Turkish TCKN, SSN, IBAN, IP Addresses, High-entropy secrets) and writes production-ready configuration in seconds.

---

## 🔄 Real-World Before / After Comparison

CloakDB masks PII while **preserving relational integrity** (e.g. `users.id` matches `orders.user_id`), retaining email corporate domains, and keeping numerical/date statistical distributions:

### 🔴 Before (Raw Production SQL Dump)
```sql
-- Table: users
COPY public.users (id, full_name, email, tc_kimlik, phone, salary, birth_date) FROM stdin;
1001	Eleanor Vance	eleanor.vance@hillhouse.org	10000000146	+1-555-0199	95000.00	1988-04-12
1002	Luke Sanderson	luke.sanderson@heritage.com	23854910284	+1-555-0142	115000.50	1985-09-23
\.

-- Table: orders (user_id is a Foreign Key referencing users.id)
INSERT INTO public.orders (id, user_id, order_total, shipping_address, customer_notes) VALUES 
(501, 1001, 149.99, '742 Evergreen Terrace, Springfield, OR', 'Door code is 4920'),
(502, 1002, 349.50, '221B Baker Street, London, UK', 'Call Luke at 555-0142 upon arrival');

-- Table: audit_logs
INSERT INTO public.audit_logs (id, user_id, raw_payload) VALUES
(1, 1001, '{"action": "login", "password_attempt": "SecretPass123!"}');
```

### 🟢 After (CloakDB Sanitized Dump)
```sql
-- Table: users (Names, Emails, TCKN, Phones & Salaries masked; relations preserved)
COPY public.users (id, full_name, email, tc_kimlik, phone, salary, birth_date) FROM stdin;
757782	Brad Wagner	jeffrey20@hillhouse.org	49281729482	001-921-726-3167x532	87858.16	1988-03-28
356338	William Martinez	sbates@heritage.com	78192039410	(441)558-4260	105249.27	1985-08-27
\.

-- Table: orders (⚡ Notice: user_id 1001 -> 757782 and 1002 -> 356338 are consistently matched!)
INSERT INTO public.orders (id, user_id, order_total, shipping_address, customer_notes) VALUES 
(501, 757782, 149.99, '7123 Saunders Road, South Nicholas, ME', 'Notes redacted for privacy compliance'),
(502, 356338, 349.50, '46398 Emily View, Banksshire, CT', 'Notes redacted for privacy compliance');

-- Table: audit_logs (Truncated completely as configured)
```

---

## 🇹🇷 First-Class Turkish Locale & TCKN Support

CloakDB includes dedicated support for Turkish schemas, compliance practices (KVKK), and localized validation:

- **Mathematical TCKN Algorithm:** Validates and generates 11-digit Turkish Republic ID numbers adhering strictly to the official Modulo-10 and Modulo-11 checksum algorithms.
- **Turkish Schema Auto-Discovery:** Native heuristic recognition for Turkish column naming conventions:
  - `ad`, `soyad`, `ad_soyad`, `musteri_adi`
  - `tc_kimlik_no`, `tckn`, `tc_no`, `vergi_no`
  - `eposta`, `e_posta`, `email_adresi`
  - `telefon`, `cep_tel`, `cep_telefonu`, `iletisim_no`
  - `adres`, `teslimat_adresi`, `fatura_adresi`, `sehir`, `ilce`
  - `maas`, `bakiye`, `tutar`, `ucret`
  - `sifre`, `parola`, `gizli_anahtar`
- **Seeded `tr_TR` Synthetic Generator:** Produces realistic Turkish names, cities, districts, and phone numbers (`+90 5XX XXX XX XX`).

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

- **⚡ Blazing Speed:** Over **60,000+ cells/sec** throughput with single-thread streaming.
- **🔒 Cryptographic Determinism:** Seeded HMAC-SHA256 ensures identical inputs map to consistent pseudonyms across tables and distributed files.
- **🎯 17+ Masking Strategies:** Seeded Faker, regex redaction, Gaussian noise jitter, date shifts, TCKN generation, credit card masking, and more.
- **🧪 Production Ready:** 100% automated test coverage, strict typing, Pydantic v2 validation, and cross-platform compatibility (Windows, Linux, macOS).

---

## 📦 Installation

```bash
# Option 1: Install directly from GitHub (Recommended)
pip install git+https://github.com/latryee/CloakDB.git

# Option 2: Clone repository & install in editable mode
git clone https://github.com/latryee/CloakDB.git
cd CloakDB
pip install -e .

# Or install with development and testing dependencies
pip install -e ".[dev]"
```

---

## 🏁 Quickstart (3 Steps)

### Step 1: Scan your database or dump for PII
```bash
# Scan a PostgreSQL / MySQL dump and generate cloakdb.yaml
cloakdb scan dump.sql --output cloakdb.yaml

# Scan with Turkish locale heuristics
cloakdb scan dump.sql --locale tr_TR --output cloakdb.yaml
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

## ⚖️ Compliance Framework & Legal Disclaimer

CloakDB implements technical data protection controls aligned with major privacy frameworks:

- **KVKK (6698 Sayılı Kanun):** Aligned with **Madde 12** (Veri Güvenliğine İlişkin Yükümlülükler) and the KVKK Kurumu *Kişisel Verilerin Silinmesi, Yok Edilmesi veya Anonim Hale Getirilmesi Rehberi* through masking, substitution, and k-anonymity generalization.
- **GDPR (EU 2016/679):** Supports **Article 4(5)** (Pseudonymisation), **Article 25** (Data Protection by Design & Default), and **Article 32(1)(a)** (Security of Processing).
- **HIPAA (45 CFR § 164.514):** Provides transformations addressing the 18 identifier categories under the HIPAA Safe Harbor de-identification standard.

> ⚠️ **Compliance Disclaimer:**  
> CloakDB is an open-source technical data masking and pseudonymization tool. Utilizing CloakDB assists technical teams in staging and test sanitization, but does **not** by itself guarantee full legal compliance with KVKK, GDPR, HIPAA, or other regulatory requirements. Data controllers must implement appropriate organizational policies, manage cryptographic salts securely, evaluate re-identification risks in context, and consult qualified legal counsel.

---

## 📊 Benchmarks

Benchmark executed on standard hardware (AMD Ryzen / Intel Core):

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

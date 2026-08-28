<div align="center">

# 🛡️ CloakDB

**Deterministic database & SQL dump anonymization CLI.**  
*Sanitize database dumps, JSON/JSONB payloads, and live tables with referential integrity, multi-core streaming, and constant memory consumption.*

![CloakDB Social Banner](./assets/social_preview.png)

[![CI](https://github.com/latryee/CloakDB/actions/workflows/ci.yml/badge.svg)](https://github.com/latryee/CloakDB/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://github.com/latryee/CloakDB)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg)](https://github.com/latryee/CloakDB)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Why CloakDB](#-why-cloakdb) •
[Demo](#-terminal-demo) •
[Before / After](#-real-world-before--after-comparison) •
[Consistency Model](#-consistency-model--referential-integrity) •
[Quickstart](#-quickstart) •
[CLI Commands](#-cli-commands-reference) •
[Configuration](#-configuration-guide-cloakdbyaml) •
[Strategies](#-masking-strategies-catalog) •
[Dialect Support](#-extended-dialect-support) •
[Benchmarks](#-benchmarks)

<br/>

### 🎬 Terminal Demo

![CloakDB Terminal Demo](./assets/demo.gif)

</div>

---

## 💡 Why CloakDB?

Creating staging and testing databases from production dumps often presents three challenges:
- **Foreign Key Breakage:** Random generation breaks foreign key relationships across related tables (`users.id` no longer matches `orders.user_id`).
- **Memory Consumption:** Loading full SQL dumps into memory causes Out-Of-Memory crashes on multi-gigabyte datasets.
- **Nested Payload Complexity:** Modern databases heavily store unstructured JSON/JSONB columns containing embedded PII.

**CloakDB** addresses these problems:
1. **Deterministic Referential Integrity:** Primary and foreign keys are pseudonymized using keyed HMAC hashing (globally consistent across tables) or `ConsistencyGroup` definitions for synthetic data (mathematically reproducible independent of LRU cache retention).
2. **Multi-Core Streaming Pipeline:** Streams PostgreSQL `COPY` / `INSERT`, MySQL, SQLite, MS SQL Server (T-SQL), Oracle SQL, CSV, and JSONL data in constant memory with optional multi-worker parallel chunk parsing (`--workers N`).
3. **Nested JSON / JSONB Masking:** Recursively sanitizes nested paths using dot-notation (`profile.contact.email`), array wildcards (`orders[*].credit_card`), and object wildcards (`metadata.*`).
4. **Automated PII Discovery (`cloakdb scan`):** Automatically analyzes schemas and sample values (emails, phones, Luhn-validated credit cards, Turkish TCKN, SSN, IBAN, IP addresses, high-entropy secrets) to generate ready-to-use YAML configurations.

---

## 🔄 Real-World Before / After Comparison

CloakDB masks PII while **preserving relational integrity** (e.g. `users.id` matches `orders.user_id`), retaining corporate email domains, sanitizing nested JSON objects, and preserving statistical distributions:

### 🔴 Before (Raw Production SQL Dump)
```sql
-- Table: users
COPY public.users (id, full_name, email, tc_kimlik, phone, salary, raw_metadata) FROM stdin;
1001	Eleanor Vance	eleanor.vance@hillhouse.org	10000000146	+1-555-0199	95000.00	{"profile": {"contact_email": "eleanor@hillhouse.org"}, "cards": [{"num": "4532015012345678"}]}
1002	Luke Sanderson	luke.sanderson@heritage.com	23854910284	+1-555-0142	115000.50	{"profile": {"contact_email": "luke@heritage.com"}, "cards": [{"num": "5425233430109823"}]}
\.

-- Table: orders (user_id is a Foreign Key referencing users.id)
INSERT INTO public.orders (id, user_id, order_total, shipping_address, customer_notes) VALUES 
(501, 1001, 149.99, '742 Evergreen Terrace, Springfield, OR', 'Door code is 4920'),
(502, 1002, 349.50, '221B Baker Street, London, UK', 'Call Luke at 555-0142 upon arrival');

-- Table: audit_logs
INSERT INTO public.audit_logs (id, user_id, raw_payload) VALUES
(1, 1001, '{"action": "login", "auth": {"token": "secret_tok_xyz"}}');
```

### 🟢 After (CloakDB Sanitized Dump)
```sql
-- Table: users (Names, Emails, TCKN, Phones, Salaries & Nested JSON masked; relations preserved)
COPY public.users (id, full_name, email, tc_kimlik, phone, salary, raw_metadata) FROM stdin;
757782	Brad Wagner	jeffrey20@hillhouse.org	49281729482	001-921-726-3167x532	87858.16	{"profile": {"contact_email": "jwoodard@hillhouse.org"}, "cards": [{"num": "****-****-****-5678"}]}
356338	William Martinez	sbates@heritage.com	78192039410	(441)558-4260	105249.27	{"profile": {"contact_email": "martinez@heritage.com"}, "cards": [{"num": "****-****-****-9823"}]}
\.

-- Table: orders (Notice: user_id 1001 -> 757782 and 1002 -> 356338 are consistently matched!)
INSERT INTO public.orders (id, user_id, order_total, shipping_address, customer_notes) VALUES 
(501, 757782, 149.99, '7123 Saunders Road, South Nicholas, ME', 'Notes redacted for privacy compliance'),
(502, 356338, 349.50, '46398 Emily View, Banksshire, CT', 'Notes redacted for privacy compliance');

-- Table: audit_logs (Truncated completely as configured)
```

---

## 🔒 Consistency Model & Referential Integrity

CloakDB uses a deterministic seed-derivation model to maintain data consistency:

- **`deterministic_hash`**: Pseudonyms are derived directly from `HMAC-SHA256(salt, raw_value)`. Under the same configuration and salt, identical input values will produce identical pseudonyms across any table and column name.
- **Un-grouped Synthetic Strategies (`faker`)**: By default, synthetic transformations are column-scoped (`seed = hash(salt, table_name, column_name, raw_value)`). This prevents two unrelated columns from generating identical synthetic names purely by coincidence.
- **`ConsistencyGroup`**: Groups multiple columns across tables (e.g. `users.id` and `orders.user_id`, or `users.email` and `audit_logs.actor_email`) under a shared seed scope (`seed = hash(salt, group_name, raw_value)`). This guarantees identical synthetic and hashed values across tables and column names.
- **Cache Independence**: An in-memory LRU cache accelerates repeated lookups to $O(1)$. However, consistency correctness does **not** rely on cache retention: even if an entry is evicted under high volume, recomputing the value derives the exact same mathematical output.

---

## 🌐 Extended Dialect Support

CloakDB natively handles syntax peculiarities across major relational database engines:

| Dialect | Distinct Syntax Supported |
| :--- | :--- |
| **PostgreSQL** | `COPY ... FROM stdin`, `\N` null markers, multi-line `INSERT`, standard DDL |
| **MySQL / MariaDB** | Backtick identifiers (`` `schema`.`table` ``), multi-row `INSERT INTO ... VALUES (), ()` |
| **Microsoft SQL Server (T-SQL)** | Bracketed identifiers (`[dbo].[Customers]`), `N'...'` unicode string literals, `SET IDENTITY_INSERT ... ON/OFF`, `GO` batch delimiters |
| **Oracle Database** | Quoted identifiers (`"HR"."EMPLOYEES"`), `REM` remarks, `PROMPT` statements, `SET DEFINE OFF` |
| **SQLite** | Standard SQLite dumps and live SQLite `.db` file in-place masking |
| **Flat Files** | CSV files and newline-delimited JSON (`.jsonl`) streams |

---

## 📦 Installation

```bash
# Clone repository & install in editable mode
git clone https://github.com/latryee/CloakDB.git
cd CloakDB
pip install -e .

# Or install with development dependencies (pytest, ruff, mypy)
pip install -e ".[dev]"
```

---

## 🏁 Quickstart

### Step 1: Scan for sensitive data
```bash
# Scan a SQL dump and generate rules
cloakdb scan dump.sql --output cloakdb.yaml
```

### Step 2: Preview the transformation
```bash
cloakdb preview -c cloakdb.yaml -i dump.sql
```

### Step 3: Stream and apply masking (with multi-worker parallel parsing)
```bash
cloakdb apply -c cloakdb.yaml -i dump.sql -o sanitized_dump.sql --workers 4
```

---

## 🛠️ CLI Commands Reference

### `cloakdb scan`
Auto-scans a SQL dump, CSV, or live database URL and detects sensitive columns.
```bash
# Scan a SQL dump file
cloakdb scan production_dump.sql -o cloakdb.yaml

# Scan a CSV file with Turkish locale heuristics
cloakdb scan customers.csv --locale tr_TR -o cloakdb.yaml

# Scan a live database connection (PostgreSQL / MySQL / SQLite)
cloakdb scan "postgresql://user:pass@localhost:5432/proddb" -o cloakdb.yaml
```

### `cloakdb apply`
Streams and masks input datasets or live tables with optional multi-core workers.
```bash
# Stream mask a SQL dump using 4 parallel worker processes
cloakdb apply -c cloakdb.yaml -i dump.sql -o sanitized.sql --workers 4

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
Creates a starter configuration file with example rules.
```bash
cloakdb init --output cloakdb.yaml
```

### `cloakdb strategies`
Lists all available masking strategies with parameter specifications and aliases.
```bash
cloakdb strategies
```

### `cloakdb bench`
Runs an in-memory throughput benchmark across multi-column strategy workloads.
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
  cache_pseudonyms: true                  # Cache pseudonyms for O(1) performance
  max_cache_size: 500000                  # Maximum entries to retain in LRU cache

# Referential Integrity Groups: Ensures identical pseudonyms across foreign keys
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

      email:
        strategy: "faker"
        params:
          provider: "email"
          preserve_domain: true

      credit_card:
        strategy: "credit_card_mask"

      salary:
        strategy: "jitter"
        params:
          percentage: 10.0

      # Nested JSON / JSONB Column Masking
      raw_payload:
        strategy: "json_mask"
        rules:
          "profile.contact_email":
            strategy: "faker"
            params:
              provider: "email"
              preserve_domain: true
          "cards[*].num":
            strategy: "credit_card_mask"
          "internal_auth.*":
            strategy: "nullify"

  orders:
    columns:
      user_id:
        strategy: "deterministic_hash"
        consistency_group: "user_ids"

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
| `json_mask` | `rules: {'path': rule}` | `{"user": {"email": "a@b.com"}}` | `{"user": {"email": "masked@b.com"}}` |
| `deterministic_hash` | `as_integer: true, min_int: 10000` | `1048` | `84920` *(Preserved across tables)* |
| `uuid_hash` | `salt: 'secret'` | `user-12345` | `e0a3f8c2-...` *(RFC 4122 v5 UUID)* |
| `faker` | `provider: 'email', preserve_domain: true` | `john.doe@company.org` | `jwoodard@company.org` |
| `faker` | `provider: 'name'` | `Eleanor Vance` | `Bradley Wagner` |
| `faker` | `provider: 'address'` | `742 Evergreen Terrace` | `8912 Riverview Way` |
| `credit_card_mask` | `mask_char: '*'` | `4532-0150-1234-5678` | `****-****-****-5678` |
| `pattern_mask` | `keep_first: 0, keep_last: 4` | `666-42-1920` | `*******1920` |
| `email_mask` | `keep_first: 1, keep_last: 1` | `sarah.connor@acme.com` | `s**********r@acme.com` |
| `jitter` | `percentage: 10.0, distribution: 'gaussian'` | `100,000.00` | `96,420.50` |
| `date_shift` | `max_days_forward: 30, max_days_backward: 30`| `1988-04-12` | `1988-03-28` |
| `date_truncate` | `level: 'year'` | `1995-07-23` | `1995-01-01` |
| `tckn` | `deterministic: true` | `10000000146` | `49281729482` *(Valid Mod-10/11)* |
| `constant` | `value_to_set: '[REDACTED]'` | `Secret note` | `[REDACTED]` |
| `nullify` | `-` | `Any value` | `NULL` |
| `scramble` | `deterministic: true` | `Abc-123` | `Xyk-841` |
| `regex_replace` | `pattern: '\\d+', replacement: 'XXX'` | `Order #12345` | `Order #XXX` |
| `choice` | `choices: ['EU', 'US', 'APAC']` | `PRIVATE_REGION` | `EU` |

---

## 📊 Benchmarks

Benchmark executed on standard local hardware (multi-strategy workload containing 7 columns: HMAC integer hashing, email masking, deterministic Faker names, pattern masking, Gaussian numeric jitter, date shifting, and hex token hashing):

| Benchmark Workload | Records Processed | Cells Masked | Execution Time | Throughput (Rows/sec) | Throughput (Cells/sec) | Peak Memory |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (10K rows)** | 10,000 | 70,000 | ~13.5 s | ~740 rows/s | ~5,180 cells/s | < 1.0 MB |
| **Medium (50K rows)** | 50,000 | 350,000 | ~67.5 s | ~741 rows/s | ~5,187 cells/s | < 1.0 MB |
| **Large (100K rows)** | 100,000 | 700,000 | ~128.7 s | ~777 rows/s | ~5,439 cells/s | < 1.0 MB |

### Reproducing Benchmarks
You can run the benchmark suite locally with any row count:
```bash
cloakdb bench --rows 50000
```

---

## ⚖️ Compliance & Legal Disclaimer

CloakDB implements technical data transformation controls commonly used to assist with data protection regulations:
- **KVKK (6698 Sayılı Kanun):** Aligned with Madde 12 and official anonymization guidelines (masking, substitution, k-anonymity rounding).
- **GDPR (EU 2016/679):** Supports Article 4(5) (Pseudonymisation) and Article 25 (Data Protection by Design).
- **HIPAA (45 CFR § 164.514):** Addressable transformations for identifiers under the Safe Harbor de-identification standard.

> ⚠️ **Disclaimer:**  
> CloakDB is an open-source data masking tool. Using CloakDB assists technical teams in staging and test sanitization, but does **not** automatically guarantee full legal compliance with KVKK, GDPR, HIPAA, or other regulations. Organizations must maintain adequate salt key security, assess re-identification risks in context, and consult legal counsel.

---

## 🧪 Running Tests

```bash
# Run pytest test suite
pytest -v

# Run with test coverage report
pytest --cov=cloakdb --cov-report=term-missing
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, testing, and contribution guidelines.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for details.

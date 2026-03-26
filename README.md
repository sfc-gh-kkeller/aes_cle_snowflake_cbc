# AES-CBC Encryption & Decryption for Snowflake

Column-level AES-256-CBC encryption and decryption using Snowflake's native `ENCRYPT_RAW` / `DECRYPT_RAW` functions. Produces ciphertext in **Postgres pgcrypto-compatible format**: `BASE64(iv_raw_16_bytes || ciphertext_raw)`.

## Features

- AES-256-CBC encryption with random IV per row
- Optional fixed-IV mode for deterministic / cross-system testing
- Tag-based and column-level masking policies for transparent encrypt-on-read
- Decrypt-on-read masking policies for authorized roles
- Fake data generation via Python UDF (Faker)
- Stage-based bulk export workflow
- Cross-platform compatibility with Postgres pgcrypto (encrypt in Snowflake, decrypt in Postgres and vice versa)
- Four key management strategies (see below)
- Fourth approach: HYOK (Hold Your Own Key) with SHA-256 key wrapping
- Per-column external functions for fully server-side crypto (key never leaves the cloud)
- Per-session and per-query key delivery patterns with performance benchmarks
- BI integration guidance (Sigma, Tableau, notebooks)
- Sample AWS Lambda and Azure Function code included

## Repository Layout

```
.
├── README.md
├── LICENSE
├── sql/
│   ├── 01_session_variable_approach.sql      # Key in a session variable
│   ├── 02_udf_key_vault_approach.sql         # Key in a SECURE IMMUTABLE UDF
│   ├── 03_external_function_kms_approach.sql  # Key from AWS KMS / Azure Key Vault
│   └── 04_key_wrapping_approach.sql           # HYOK key wrapping with SHA-256 derivation
├── aws_lambda/
│   ├── handler.py              # Lambda: return AES key from KMS
│   ├── crypto_handler.py       # Lambda: encrypt/decrypt server-side (key stays in Lambda)
│   ├── key_wrapping_handler.py # Lambda: HYOK key wrapping (secret + session salt → wrapped TMK)
│   └── requirements.txt
└── azure_function/
    ├── function_app.py         # Azure Function: return AES key from Key Vault
    ├── crypto_handler.py       # Azure Function: encrypt/decrypt server-side
    └── requirements.txt
```

## Key Management Approaches

### 1. Session Variable (`01_session_variable_approach.sql`)

The AES key is set as a session variable (`SET aes_cbc_key = '...'`).

| Pros | Cons |
|------|------|
| Simple to use | Key visible in query history |
| Works with views (`$aes_cbc_key`) | Requires SET in every session |
| No extra objects | Not shareable across users |

### 2. UDF Key Vault (`02_udf_key_vault_approach.sql`)

The AES key is embedded inside a `SECURE IMMUTABLE` SQL UDF that requires a passphrase.

| Pros | Cons |
|------|------|
| Key never appears in query history | Passphrase must still be protected |
| SECURE hides UDF body from non-owners | IMMUTABLE caching may retain result |
| Reusable across sessions and users | Requires CREATE FUNCTION privilege |

### 3. External Function + Cloud KMS (`03_external_function_kms_approach.sql`)

The AES key is stored in AWS KMS or Azure Key Vault and retrieved at query time via a Snowflake External Function backed by a Lambda or Azure Function.

| Pros | Cons |
|------|------|
| Key never stored in Snowflake | Requires cloud infrastructure setup |
| Centralized key management (rotation, audit) | Adds network latency per query |
| CONTEXT_HEADERS enable per-user audit logging | Requires API integration + IAM config |
| Option to do crypto entirely server-side | More moving parts to maintain |

#### Two Sub-Patterns

| Pattern | How It Works | Key Exposure |
|---------|-------------|--------------|
| **Key retrieval** | External function returns the key; Snowflake does `ENCRYPT_RAW`/`DECRYPT_RAW` locally | Key transits through Snowflake (encrypted in flight) |
| **Server-side crypto** | External function does encrypt/decrypt; only ciphertext/plaintext crosses the wire | Key **never** leaves the cloud provider |

#### Architecture

```
┌─────────────┐      HTTPS       ┌──────────────────┐        ┌─────────────────┐
│  Snowflake   │ ──────────────▶ │  API Gateway /    │ ─────▶ │  Lambda /        │
│  (External   │ ◀────────────── │  API Management   │ ◀───── │  Azure Function  │
│   Function)  │                 └──────────────────┘        │                  │
└─────────────┘                                              │  ┌────────────┐ │
                                                              │  │ AWS KMS /  │ │
                                                              │  │ Key Vault  │ │
                                                              │  └────────────┘ │
                                                              └─────────────────┘
```

#### External Function Request/Response Format

Snowflake sends a batch of rows as a JSON POST:

```json
{"data": [[0, "MY_PASSPHRASE"], [1, "MY_PASSPHRASE"]]}
```

Your service returns:

```json
{"data": [[0, "base64-aes-256-key"], [1, "base64-aes-256-key"]]}
```

#### CONTEXT_HEADERS

When `CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)` is set on the external function, Snowflake sends these HTTP headers with every call:

| Header | Value |
|--------|-------|
| `sf-context-current-user` | Snowflake username executing the query |
| `sf-context-current-timestamp` | Query execution timestamp |
| `sf-context-current-account` | Snowflake account identifier |

Use these in your backend for **audit logging**, **rate limiting**, or **per-user access control**.

#### AWS Setup Steps

1. Create a Lambda function (see `aws_lambda/handler.py` or `aws_lambda/crypto_handler.py`)
2. Grant the Lambda execution role `kms:Decrypt` on your KMS key
3. Create an API Gateway (REST API) with a POST method pointing to the Lambda
4. In Snowflake: `CREATE API INTEGRATION` with the gateway URL and IAM role ARN
5. `DESCRIBE INTEGRATION` to get `API_AWS_IAM_USER_ARN` and `API_AWS_EXTERNAL_ID`
6. Update the IAM role trust policy to allow Snowflake to assume it
7. `CREATE SECURE EXTERNAL FUNCTION` pointing to the gateway endpoint
8. Test: `SELECT get_aes_key_aws('MY_PASSPHRASE');`

#### Azure Setup Steps

1. Create an Azure Function (see `azure_function/function_app.py` or `azure_function/crypto_handler.py`)
2. Enable managed identity and grant it **Key Vault Secrets User** on your vault
3. Create an API Management instance fronting the Function
4. Register an Azure AD application for Snowflake
5. In Snowflake: `CREATE API INTEGRATION` with the APIM URL and Azure AD details
6. `DESCRIBE INTEGRATION` to get `AZURE_CONSENT_URL`
7. Open the consent URL in a browser and grant admin consent
8. `CREATE SECURE EXTERNAL FUNCTION` pointing to the APIM endpoint
9. Test: `SELECT get_aes_key_azure('MY_PASSPHRASE');`

### 4. Key Wrapping / HYOK (`04_key_wrapping_approach.sql`)

Hold Your Own Key (HYOK) adds a **key wrapping layer** on top of the external function approach. Instead of using the KMS secret directly, a session-bound key is derived via SHA-256:

```
SHA-256(kms_secret || '|' || session_salt)  →  32-byte AES-256 wrapped TMK
```

This means the raw KMS secret alone cannot decrypt data — the session context is required for key derivation.

| Pros | Cons |
|------|------|
| Defense-in-depth: intercepted secret is useless without session context | Slightly more complex setup |
| Same KMS secret produces different keys per session | Requires SHA-256 derivation UDF |
| Compatible with both per-session and per-query patterns | Key derivation adds ~1ms overhead (negligible) |
| 1:1 query-to-KMS audit trail (per-query mode) | Per-query mode adds ~2-4s compile overhead |

#### Key Wrapping Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Key Retrieval (once per session or once per query)                  │
│                                                                             │
│  Snowflake  ──▶  API Gateway  ──▶  Lambda  ──▶  KMS Decrypt               │
│                                                   │                         │
│                                          returns kms_secret (Base64)        │
├─────────────────────────────────────────────────────────────────────────────┤
│ STEP 2: Key Wrapping (inside Snowflake, pure SQL)                           │
│                                                                             │
│  SHA-256( kms_secret || '|' || CURRENT_SESSION() || '|' || CURRENT_USER() )│
│                           ↓                                                 │
│              32-byte AES-256 wrapped TMK                                    │
│                           ↓                                                 │
│              DECRYPT_RAW(ciphertext, wrapped_tmk, iv, 'AES-CBC/PAD:PKCS')  │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Two Key Delivery Patterns

| | KEY_IN_SESSION | KEY_PER_QUERY-EXTFUNC |
|---|---|---|
| **Key Lifetime** | Entire session | Single query (compile phase) |
| **KMS Calls / Query** | 0 (amortised at connect) | 1 (exactly once per query) |
| **1:1 Query-to-KMS Audit** | No | Yes |
| **Client Cooperation** | Required (Init SQL / SP call) | None — fully transparent |
| **Per-Query Latency (L WH)** | ~2s (after setup) | ~3-7s (incl. compile) |
| **Session Setup Cost** | ~3s (SQL SP + ext func) | None |
| **Compile Overhead** | ~400-800ms (local) | ~2-4s (outbound call) |
| **Execution Path** | Pure SQL | Pure SQL (after compile) |

**KEY_IN_SESSION** — best for CLI, notebooks, and single-session apps:
```sql
-- Run once at connect
CALL sp_hyok_activate_session('MY_PASSPHRASE');
-- All subsequent queries: GETVARIABLE('HYOK_TMK') → DECRYPT_RAW (zero network calls)
SELECT * FROM employees_encrypted;
```

**KEY_PER_QUERY** — best for BI tools (Sigma, Tableau) and shared connections:
```sql
-- No setup needed. The masking policy calls the external function at compile time.
-- Exactly 1 Lambda + 1 KMS call per query (validated via CloudWatch).
SELECT * FROM employees_encrypted;
```

#### Two-Step Query Plan

When using KEY_PER_QUERY, the Snowflake query profile shows two distinct steps:

| Step | What Happens | Time (L WH, 50M rows) |
|------|--------------|-----------------------|
| **Step 1 (Compile)** | External function → API Gateway → Lambda → KMS. Key returned as plan constant. | ~1.2s |
| **Step 2 (Execute)** | TableScan + DECRYPT_RAW per row. Pure CPU, no network. | ~9-12s |

The key insight: the external function call happens **once** at compile time. The returned key becomes a plan constant used by all DECRYPT_RAW operations in execution — this is why column scaling is sub-linear.

## Architecture & Data Flows

### End-to-End Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        AES-256-CBC COLUMN-LEVEL ENCRYPTION                       │
│                                                                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐         │
│  │ 01 Session  │   │ 02 UDF Key  │   │ 03 External │   │ 04 HYOK Key │         │
│  │   Variable  │   │    Vault    │   │  Func + KMS │   │   Wrapping  │         │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘         │
│         │                 │                  │                  │                 │
│    SET var=key     get_aes_key()      ext func → KMS     ext func → KMS         │
│         │                 │                  │             + SHA-256 wrap         │
│         │                 │                  │                  │                 │
│         ▼                 ▼                  ▼                  ▼                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │                     AES-256 Key (32 bytes, Base64)                       │    │
│  └─────────────────────────────────┬────────────────────────────────────────┘    │
│                                    │                                             │
│                     ┌──────────────┴──────────────┐                              │
│                     ▼                             ▼                               │
│              ENCRYPT_RAW()                  DECRYPT_RAW()                         │
│              + RANDOM IV                    + IV from cipher                      │
│                     │                             │                               │
│                     ▼                             ▼                               │
│           BASE64(IV ‖ ciphertext)          UTF-8 plaintext                       │
│           (pgcrypto-compatible)                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Approach Decision Tree

```
                        How sensitive is the data?
                                   │
                   ┌───────────────┼───────────────┐
                   ▼               ▼               ▼
              Dev / POC      Production       Regulated / HYOK
                   │               │               │
                   ▼               ▼               ▼
            ┌──────────┐   ┌──────────┐   ┌──────────────────┐
            │    01     │   │    02    │   │ Key in Snowflake │
            │  Session  │   │   UDF   │   │   acceptable?    │
            │ Variable  │   │  Vault  │   └────────┬─────────┘
            └──────────┘   └──────────┘       Yes  │  No
                                               │    │
                                               ▼    ▼
                                          ┌──────┐ ┌──────┐
                                          │  03  │ │  04  │
                                          │ Ext  │ │ HYOK │
                                          │ Func │ │ Wrap │
                                          └──────┘ └──────┘
                                               │    │
                                       ┌───────┘    └───────┐
                                       ▼                    ▼
                                  Key retrieval      Key wrapping
                                  (key transits      (key derived in
                                   Snowflake)         session context)
                                       │
                                       ├── OR ──┐
                                       ▼        ▼
                                  Server-side   Key never
                                    crypto      leaves cloud
```

### Encryption Data Flow (Write Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ENCRYPT ON WRITE                                  │
│                                                                             │
│  Application / SQL                                                          │
│  ┌──────────────────────────────────────────────────────┐                   │
│  │ INSERT INTO encrypted_table                          │                   │
│  │   SELECT encrypt_cbc_random_iv(plaintext, aes_key)   │                   │
│  │   FROM source_table;                                 │                   │
│  └────────────────────────┬─────────────────────────────┘                   │
│                           │                                                 │
│                           ▼                                                 │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              encrypt_cbc_random_iv()                 │                    │
│  │                                                     │                    │
│  │  plaintext (UTF-8)                                  │                    │
│  │       │                                             │                    │
│  │       ▼                                             │                    │
│  │  ┌───────────────┐    ┌────────────────┐            │                    │
│  │  │ RANDOM_BYTES  │    │  AES-256 Key   │            │                    │
│  │  │   (16 bytes)  │    │  (32 bytes)    │            │                    │
│  │  └───────┬───────┘    └───────┬────────┘            │                    │
│  │          │ IV                 │ Key                  │                    │
│  │          ▼                    ▼                      │                    │
│  │  ┌────────────────────────────────┐                  │                    │
│  │  │       ENCRYPT_RAW()            │                  │                    │
│  │  │   mode = AES-CBC / PKCS#7      │                  │                    │
│  │  └───────────────┬────────────────┘                  │                    │
│  │                  │                                   │                    │
│  │                  ▼                                   │                    │
│  │  ┌────────────────────────────────┐                  │                    │
│  │  │  IV (16B) ‖ ciphertext (nB)   │                  │                    │
│  │  └───────────────┬────────────────┘                  │                    │
│  │                  │                                   │                    │
│  │                  ▼                                   │                    │
│  │  ┌────────────────────────────────┐                  │                    │
│  │  │       BASE64_ENCODE()          │                  │                    │
│  │  └───────────────┬────────────────┘                  │                    │
│  │                  │                                   │                    │
│  │                  ▼                                   │                    │
│  │  "dGVzdC1pdi4uLnRlc3QtY2lwaGVydGV4dA=="             │                    │
│  └─────────────────────────────────────────────────────┘                    │
│                           │                                                 │
│                           ▼                                                 │
│                  ┌─────────────────┐                                        │
│                  │  Snowflake Table │                                        │
│                  │  (VARCHAR col)   │                                        │
│                  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Decryption Data Flow (Read Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DECRYPT ON READ                                    │
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │  Snowflake Table │  stored: "dGVzdC1pdi4uLnRlc3QtY2lwaGVydGV4dA=="      │
│  │  (VARCHAR col)   │                                                       │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │               decrypt_cbc()                         │                    │
│  │                                                     │                    │
│  │  Base64 ciphertext                                  │                    │
│  │       │                                             │                    │
│  │       ▼                                             │                    │
│  │  ┌────────────────────────────────┐                  │                    │
│  │  │    BASE64_DECODE_BINARY()      │                  │                    │
│  │  └───────────────┬────────────────┘                  │                    │
│  │                  │                                   │                    │
│  │                  ▼                                   │                    │
│  │  ┌─────────────────────────────────┐                 │                    │
│  │  │  raw bytes: IV (16B) ‖ CT (nB)  │                 │                    │
│  │  └──────┬───────────────┬──────────┘                 │                    │
│  │         │               │                            │                    │
│  │   bytes[1:16]     bytes[17:]                         │                    │
│  │    = IV            = ciphertext                      │                    │
│  │         │               │         ┌──────────────┐   │                    │
│  │         │               │         │ AES-256 Key  │   │                    │
│  │         ▼               ▼         └──────┬───────┘   │                    │
│  │  ┌────────────────────────────────────────────┐      │                    │
│  │  │            DECRYPT_RAW()                    │      │                    │
│  │  │   mode = AES-CBC / PKCS#7                   │      │                    │
│  │  └──────────────────┬─────────────────────────┘      │                    │
│  │                     │                                 │                    │
│  │                     ▼                                 │                    │
│  │            plaintext (UTF-8)                          │                    │
│  └─────────────────────────────────────────────────────┘                    │
│           │                                                                 │
│           ▼                                                                 │
│  SELECT result → "Hello, World!"                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### External Function + KMS Data Flow (Approach 03)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│ SNOWFLAKE                          │ AWS / AZURE                                    │
│                                    │                                                │
│  SELECT decrypt_cbc(               │                                                │
│    col,                            │                                                │
│    get_aes_key_aws('pass')         │                                                │
│  )                                 │                                                │
│    │                               │                                                │
│    │  ┌──────────────────────────┐ │ ┌──────────────┐   ┌─────────────────────────┐│
│    ├─▶│  get_aes_key_aws()       │─┼▶│ API Gateway  │──▶│  Lambda (handler.py)    ││
│    │  │  SECURE EXTERNAL FUNC    │ │ │  (REST API)  │   │                         ││
│    │  │  + CONTEXT_HEADERS       │ │ │              │   │  1. Validate passphrase ││
│    │  │  + IMMUTABLE (cacheable) │ │ │  Headers:    │   │  2. KMS Decrypt()       ││
│    │  └──────────────────────────┘ │ │  sf-context-*│   │  3. Return Base64 key   ││
│    │                               │ │              │   │                         ││
│    │  ┌──────────────────────────┐ │ │              │   │  ┌───────────────────┐  ││
│    │◀─│  AES key (Base64)        │◀┼─│              │◀──│  │ KMS CMK           │  ││
│    │  └──────────────────────────┘ │ │              │   │  │ (decrypt data key)│  ││
│    │                               │ └──────────────┘   │  └───────────────────┘  ││
│    ▼                               │                    └─────────────────────────┘│
│  ┌────────────────────────┐        │                                                │
│  │  DECRYPT_RAW(          │        │                                                │
│  │    ciphertext,         │        │                                                │
│  │    key,                │        │        ── OR ──                                 │
│  │    iv,                 │        │                                                │
│  │    'AES-CBC'           │        │                                                │
│  │  )                     │        │  ┌──────────────┐   ┌─────────────────────────┐│
│  └────────────┬───────────┘        │  │ API Gateway  │──▶│  Lambda                 ││
│               │                    │  │              │   │  (crypto_handler.py)    ││
│               ▼                    │  │  Headers:    │   │                         ││
│          plaintext                 │  │  X-Operation │   │  1. KMS Decrypt key     ││
│                                    │  │  X-Data-Elem │   │  2. AES-CBC encrypt     ││
│  KEY RETRIEVAL pattern:            │  │              │   │     or decrypt          ││
│  Key transits Snowflake            │  │              │   │  3. Return result       ││
│                                    │  │              │   │                         ││
│  SERVER-SIDE CRYPTO pattern:       │  │              │   │  Key NEVER leaves       ││
│  Key stays in Lambda               │  └──────────────┘   │  Lambda environment     ││
│                                    │                    └─────────────────────────┘│
└────────────────────────────────────┴────────────────────────────────────────────────┘
```

### HYOK Key Wrapping Data Flow (Approach 04)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                     KEY_IN_SESSION — Full Lifecycle                                   │
│                                                                                      │
│  ① Session Activation (once per session)                                             │
│  ─────────────────────────────────────────                                           │
│                                                                                      │
│  CALL sp_hyok_activate_session('pass')                                               │
│    │                                                                                 │
│    ├─ 1. External function call ─────────────────────────────────────────┐            │
│    │     hyok_fetch_key('pass')                                          │            │
│    │                                                                     ▼            │
│    │                                              ┌─────────────────────────────┐     │
│    │                                              │  API GW → Lambda → KMS      │     │
│    │                                              │  Returns: kms_secret (B64)  │     │
│    │     ◀────────────────────────────────────────│                             │     │
│    │                                              └─────────────────────────────┘     │
│    │                                                                                 │
│    ├─ 2. Key derivation (pure SQL, no network)                                       │
│    │     SHA256(kms_secret || '|' || CURRENT_SESSION() || '|' || CURRENT_USER())     │
│    │       │                                                                         │
│    │       ▼                                                                         │
│    │     wrapped_tmk (32 bytes, Base64)                                              │
│    │                                                                                 │
│    ├─ 3. Store in session                                                            │
│    │     SET HYOK_TMK = '<wrapped_tmk>'                                              │
│    │                                                                                 │
│    ▼                                                                                 │
│  Session ready — GETVARIABLE('HYOK_TMK') available                                   │
│                                                                                      │
│  ② Query Execution (zero outbound calls)                                             │
│  ────────────────────────────────────────                                             │
│                                                                                      │
│  SELECT * FROM employees_encrypted;                                                  │
│    │                                                                                 │
│    ▼  Masking policy (decrypt_hyok_session) fires:                                   │
│  ┌──────────────────────────────────────────────────┐                                │
│  │ IS_ROLE_IN_SESSION('ACCOUNTADMIN')? ──── No ───▶ '** HYOK key not loaded **'      │
│  │       │ Yes                                      │                                │
│  │       ▼                                          │                                │
│  │ GETVARIABLE('HYOK_TMK') IS NOT NULL? ── No ───▶ │                                │
│  │       │ Yes                                      │                                │
│  │       ▼                                          │                                │
│  │ decrypt_cbc(val, GETVARIABLE('HYOK_TMK'))        │                                │
│  │       │                                          │                                │
│  │       ▼                                          │                                │
│  │    plaintext                                     │                                │
│  └──────────────────────────────────────────────────┘                                │
│                                                                                      │
│  ③ Session Teardown                                                                  │
│  ──────────────────                                                                  │
│                                                                                      │
│  UNSET HYOK_TMK;  ──▶  Key purged from session. Queries return masked values.        │
└──────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────┐
│                     KEY_PER_QUERY — Full Lifecycle                                    │
│                                                                                      │
│  SELECT * FROM employees_encrypted;                                                  │
│                                                                                      │
│  ┌─── Compile Phase (Step 1) ───────────────────────────────────────────────────┐    │
│  │                                                                               │    │
│  │  Masking policy fires → calls udf_hyok_fetch_wrapped_key()                    │    │
│  │    │                                                                          │    │
│  │    ├── hyok_fetch_key('MY_PASSPHRASE')                                        │    │
│  │    │     │                                                                    │    │
│  │    │     ▼                                                                    │    │
│  │    │   API GW → Lambda → KMS → returns kms_secret                             │    │
│  │    │     │                                                                    │    │
│  │    │     ▼                                                                    │    │
│  │    ├── derive_session_key(kms_secret, session_salt)                            │    │
│  │    │     │                                                                    │    │
│  │    │     ▼                                                                    │    │
│  │    │   SHA256(kms_secret || '|' || session || '|' || user)                    │    │
│  │    │     │                                                                    │    │
│  │    │     ▼                                                                    │    │
│  │    └── wrapped_tmk becomes a PLAN CONSTANT                                    │    │
│  │                                                                               │    │
│  │  Time: ~1.2s (Lambda 38ms + KMS + compile overhead)                           │    │
│  └───────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│  ┌─── Execution Phase (Step 2) ─────────────────────────────────────────────────┐    │
│  │                                                                               │    │
│  │  For each row in TableScan:                                                   │    │
│  │    DECRYPT_RAW(ciphertext, plan_constant_tmk, iv, 'AES-CBC/PAD:PKCS')        │    │
│  │                                                                               │    │
│  │  Pure CPU — no network calls, no Lambda invocations                           │    │
│  │  Time: ~9-12s for 50M rows / 7 cols on L warehouse                            │    │
│  │  Column scaling: sub-linear (TMK fetched once, reused for all columns)        │    │
│  └───────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Security Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                              TRUST BOUNDARY DIAGRAM                                  │
│                                                                                      │
│  ┌─ SNOWFLAKE (Compute & Storage) ─────────────────────────────────────────────┐     │
│  │                                                                              │     │
│  │  ┌─ User Session ──────────────────────────────────────────────────────┐     │     │
│  │  │                                                                      │     │     │
│  │  │  Session Variables     GETVARIABLE('HYOK_TMK')                       │     │     │
│  │  │  ┌──────────────┐    (key in session memory,                        │     │     │
│  │  │  │ SET key=...  │     wiped on UNSET or disconnect)                  │     │     │
│  │  │  └──────────────┘                                                    │     │     │
│  │  │         ⚠ Key visible in QUERY_HISTORY for approach 01               │     │     │
│  │  └──────────────────────────────────────────────────────────────────────┘     │     │
│  │                                                                              │     │
│  │  ┌─ SQL Runtime ──────────────────────────────────────────────────────┐      │     │
│  │  │                                                                     │      │     │
│  │  │  ENCRYPT_RAW / DECRYPT_RAW                                          │      │     │
│  │  │  Key exists in memory during query execution only                   │      │     │
│  │  │  SECURE UDFs / functions hide definition from non-owners            │      │     │
│  │  │  Masking policies enforce role-based access                         │      │     │
│  │  └─────────────────────────────────────────────────────────────────────┘      │     │
│  │                                                                              │     │
│  │  ┌─ Masking Policy Layer ─────────────────────────────────────────────┐      │     │
│  │  │                                                                     │      │     │
│  │  │  IS_ROLE_IN_SESSION() → gate                                        │      │     │
│  │  │  GETVARIABLE()        → session key (04-session)                    │      │     │
│  │  │  ext_func()           → per-query key (03, 04-per-query)            │      │     │
│  │  │  get_aes_key()        → UDF vault key (02)                          │      │     │
│  │  │  $var                 → session variable (01)                        │      │     │
│  │  └─────────────────────────────────────────────────────────────────────┘      │     │
│  └──────────────────────────────────────────────────────────────────────────────┘     │
│                                          │                                           │
│                                   HTTPS (TLS 1.2+)                                   │
│                                          │                                           │
│  ┌─ CLOUD PROVIDER (AWS / Azure) ────────┴─────────────────────────────────────┐     │
│  │                                                                              │     │
│  │  ┌─ API Gateway / APIM ──────────────────────────────────────────────┐      │     │
│  │  │  IAM role assumption (AWS) or Azure AD auth                        │      │     │
│  │  │  IP allowlisting (optional)                                        │      │     │
│  │  │  Request/response logged (CloudTrail / Azure Monitor)              │      │     │
│  │  └────────────────────────────────────────────────────────────────────┘      │     │
│  │                                                                              │     │
│  │  ┌─ Lambda / Azure Function ─────────────────────────────────────────┐      │     │
│  │  │  Passphrase validation                                              │      │     │
│  │  │  Audit logging (sf-context-* headers, query ID)                     │      │     │
│  │  │  Key cached in warm-start memory (not persisted)                    │      │     │
│  │  │                                                                     │      │     │
│  │  │  Server-side crypto mode: encrypt/decrypt happens HERE              │      │     │
│  │  │  Key retrieval mode: decrypted key returned to Snowflake            │      │     │
│  │  └────────────────────────────────────────────────────────────────────┘      │     │
│  │                                                                              │     │
│  │  ┌─ KMS / Key Vault ────────────────────────────────────────────────┐       │     │
│  │  │  Master key (CMK) never leaves HSM                                │       │     │
│  │  │  Data key encrypted at rest, decrypted by CMK on demand           │       │     │
│  │  │  Rotation managed by cloud provider                               │       │     │
│  │  │  All decrypt operations logged (CloudTrail / Key Vault audit)     │       │     │
│  │  └───────────────────────────────────────────────────────────────────┘       │     │
│  └──────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                      │
│  KEY EXPOSURE BY APPROACH:                                                            │
│  ┌─────────────┬────────────────┬──────────────────┬─────────────────────────────┐   │
│  │  Approach   │  In Snowflake  │  In Transit      │  In Cloud Provider          │   │
│  ├─────────────┼────────────────┼──────────────────┼─────────────────────────────┤   │
│  │ 01 Session  │ ✗ query hist   │ N/A              │ N/A                         │   │
│  │ 02 UDF      │ ✗ UDF body     │ N/A              │ N/A                         │   │
│  │ 03 Key Ret  │ ✗ runtime mem  │ ✗ TLS encrypted  │ ✓ HSM-protected             │   │
│  │ 03 Srv Cry  │ ✓ never        │ ✓ never          │ ✓ Lambda memory only        │   │
│  │ 04 HYOK     │ ✗ derived key  │ ✗ raw secret TLS │ ✓ HSM-protected             │   │
│  └─────────────┴────────────────┴──────────────────┴─────────────────────────────┘   │
│  ✗ = key present    ✓ = key NOT present / protected                                  │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Masking Policy Decision Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                      MASKING POLICY EXECUTION FLOW                           │
│                                                                              │
│  SELECT col FROM table                                                       │
│    │                                                                         │
│    ▼                                                                         │
│  ┌──────────────────────────────────────┐                                    │
│  │  Column has masking policy attached? │                                    │
│  └──────────┬───────────────────────────┘                                    │
│        No   │   Yes                                                          │
│        │    │                                                                │
│        │    ▼                                                                │
│        │  ┌───────────────────────────────┐                                  │
│        │  │ OR: Table/column has TAG with │                                  │
│        │  │ masking policy attached?      │                                  │
│        │  └──────────┬────────────────────┘                                  │
│        │        No   │   Yes                                                 │
│        │        │    │                                                       │
│        ▼        ▼    ▼                                                       │
│  raw value   ┌──────────────────────────────────────────────────────┐        │
│  returned    │          MASKING POLICY EVALUATES                     │        │
│              │                                                      │        │
│              │  ┌──────────────────────────────────────────┐        │        │
│              │  │  IS_ROLE_IN_SESSION('ACCOUNTADMIN')?     │        │        │
│              │  └─────────┬─────────────────┬──────────────┘        │        │
│              │       No   │            Yes  │                       │        │
│              │       │    │                 │                       │        │
│              │       ▼    │                 ▼                       │        │
│              │  '** masked **'   ┌─────────────────────┐           │        │
│              │                   │  Which key source?   │           │        │
│              │                   └──┬──────┬──────┬─────┘           │        │
│              │                      │      │      │                │        │
│              │           ┌──────────┘      │      └──────────┐     │        │
│              │           ▼                 ▼                 ▼     │        │
│              │   ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │        │
│              │   │ 01/02: hard- │  │ 03/04 session│  │ 03/04    │ │        │
│              │   │ coded key or │  │ GETVARIABLE  │  │ ext func │ │        │
│              │   │ UDF call     │  │ ('HYOK_TMK') │  │ per-query│ │        │
│              │   └──────┬───────┘  └──────┬───────┘  └────┬─────┘ │        │
│              │          │                 │               │       │        │
│              │          │           ┌─────┴─────┐         │       │        │
│              │          │           │ NULL?     │         │       │        │
│              │          │           ├─ Yes: masked        │       │        │
│              │          │           └─ No: key ready      │       │        │
│              │          │                 │               │       │        │
│              │          ▼                 ▼               ▼       │        │
│              │  ┌──────────────────────────────────────────────┐  │        │
│              │  │         decrypt_cbc(val, key)                │  │        │
│              │  │         → DECRYPT_RAW → plaintext            │  │        │
│              │  └──────────────────────────────────────────────┘  │        │
│              └───────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Lambda Processing Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    LAMBDA INTERNAL PROCESSING                                │
│                                                                              │
│  ┌─ handler.py (Key Retrieval) ─────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  event.body = {"data": [[0, "MY_PASSPHRASE"]]}                        │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  Extract: sf-context-current-user, sf-context-current-account         │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  ┌───────────────────────────────┐                                    │   │
│  │  │ Validate passphrase           │── Fail ──▶ [row_id, null]          │   │
│  │  └───────────┬───────────────────┘                                    │   │
│  │         Pass │                                                        │   │
│  │              ▼                                                        │   │
│  │  ┌───────────────────────────────┐                                    │   │
│  │  │ Warm-start cache hit?         │── Yes ──▶ Return cached key        │   │
│  │  └───────────┬───────────────────┘                                    │   │
│  │           No │                                                        │   │
│  │              ▼                                                        │   │
│  │  ┌───────────────────────────────┐                                    │   │
│  │  │ KMS Decrypt(                  │                                    │   │
│  │  │   CiphertextBlob,             │                                    │   │
│  │  │   KeyId = CMK ARN             │                                    │   │
│  │  │ )                             │                                    │   │
│  │  └───────────┬───────────────────┘                                    │   │
│  │              │ response["Plaintext"]                                   │   │
│  │              ▼                                                        │   │
│  │  ┌───────────────────────────────┐                                    │   │
│  │  │ Cache + Base64 encode         │                                    │   │
│  │  └───────────┬───────────────────┘                                    │   │
│  │              ▼                                                        │   │
│  │  Return: {"data": [[0, "base64-aes-key"]]}                            │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─ crypto_handler.py (Server-Side Crypto) ─────────────────────────────┐   │
│  │                                                                       │   │
│  │  event.body = {"data": [[0, "plaintext_or_cipher"]]}                  │   │
│  │  event.headers = { X-Operation: "encrypt"|"decrypt",                  │   │
│  │                     X-Data-Element: "name"|"address"|"phone" }        │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  KMS Decrypt → AES key bytes (cached on warm start)                   │   │
│  │    │                                                                  │   │
│  │    ├── encrypt:                                                       │   │
│  │    │   random IV → AES-CBC encrypt → BASE64(IV ‖ ciphertext)          │   │
│  │    │                                                                  │   │
│  │    └── decrypt:                                                       │   │
│  │        BASE64 decode → split IV/CT → AES-CBC decrypt → plaintext      │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  Return: {"data": [[0, "result"]]}                                    │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─ key_wrapping_handler.py (HYOK) ─────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  event.body = {"data": [[0, "MY_PASSPHRASE"]]}                        │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  Extract: sf-context-current-user, sf-context-current-account,        │   │
│  │           sf-external-function-current-query-id                        │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  ┌───────────────────────────────┐                                    │   │
│  │  │ Validate passphrase           │── Fail ──▶ LOG WARNING + error     │   │
│  │  └───────────┬───────────────────┘                                    │   │
│  │         Pass │                                                        │   │
│  │              ▼                                                        │   │
│  │  KMS Decrypt → raw secret (Base64, cached)                            │   │
│  │    │                                                                  │   │
│  │    ▼                                                                  │   │
│  │  Return: {"data": [[0, "base64-raw-secret"]]}                         │   │
│  │                                                                       │   │
│  │  Snowflake then does the SHA-256 derivation:                          │   │
│  │    derive_session_key(secret, session_salt) → wrapped TMK             │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─ AUDIT CORRELATION ──────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  CloudWatch Log:                                                      │   │
│  │    hyok_key_fetch user=JSMITH account=XY12345 query=01b3e... rows=1   │   │
│  │                                                                       │   │
│  │           ↕ correlate via sf-external-function-current-query-id        │   │
│  │                                                                       │   │
│  │  Snowflake QUERY_HISTORY:                                             │   │
│  │    QUERY_ID=01b3e...  USER_NAME=JSMITH  QUERY_TEXT=SELECT * FROM ...  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Encrypt-on-Write vs Decrypt-on-Read Pipeline

```
┌──────────────────────────────────────────────────────────────────────────────┐
│            TWO INTEGRATION PATTERNS FOR MASKING POLICIES                     │
│                                                                              │
│  ═══ Pattern A: Encrypt-on-Write, Decrypt-on-Read ═══                        │
│                                                                              │
│  Source Table                 Encrypted Table              Query Result       │
│  ┌──────────┐   INSERT +     ┌──────────────┐   SELECT +  ┌──────────┐      │
│  │ John Doe │──encrypt_cbc──▶│ a4Ff29x...   │──decrypt───▶│ John Doe │      │
│  │ 555-0100 │   (batch ETL)  │ 7bKm31y...   │  masking    │ 555-0100 │      │
│  │ NYC      │                │ pQ9nR2z...   │  policy     │ NYC      │      │
│  └──────────┘                └──────────────┘             └──────────┘      │
│                                                                              │
│  Best for: Data at rest must be encrypted. Decrypt only for authorized.      │
│  Used in: 01, 02, 03-key-retrieval, 04                                       │
│                                                                              │
│  ═══ Pattern B: Encrypt-on-Read (Transparent Masking) ═══                    │
│                                                                              │
│  Source Table                                              Query Result       │
│  ┌──────────┐   SELECT + encrypt masking policy            ┌──────────────┐  │
│  │ John Doe │──────────────────────────────────────────────▶│ a4Ff29x...   │  │
│  │ 555-0100 │   (plaintext stored, encrypted on read)      │ 7bKm31y...   │  │
│  │ NYC      │                                              │ pQ9nR2z...   │  │
│  └──────────┘                                              └──────────────┘  │
│                                                                              │
│  Best for: Dynamic encryption for data sharing / export without modifying    │
│            the underlying table. Original data remains plaintext.            │
│  Used in: Tag-based encrypt_pg policy, ext_encrypt_name policy               │
│                                                                              │
│  ═══ Pattern C: Server-Side Crypto via External Function ═══                 │
│                                                                              │
│  Source Table            Lambda / Azure Function            Query Result      │
│  ┌──────────┐   SELECT  ┌─────────────────────────┐       ┌──────────────┐  │
│  │ John Doe │──────────▶│ AES-CBC encrypt in cloud │──────▶│ a4Ff29x...   │  │
│  │          │  ext func │ Key stays in Lambda/KV   │       │              │  │
│  └──────────┘           └─────────────────────────┘       └──────────────┘  │
│                                                                              │
│  Best for: Maximum security — key never enters Snowflake at all.             │
│  Trade-off: Higher latency (network per batch), more infrastructure.         │
│  Used in: 03-server-side-crypto (ext_encrypt_name, ext_decrypt_name, etc.)   │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Performance Benchmarks

Benchmarks from a HYOK load test: **50M rows, 7 encrypted columns, AES-256-GCM**, Singapore (ap-southeast-1). KEY_PER_QUERY-EXTFUNC mode, full-scan aggregation, no optimization.

### Headline Numbers

| Metric | Value |
|--------|-------|
| Per-query latency (session, L WH) | **~2s** |
| Per-query latency (ext func, L WH) | **~3-7s** |
| Lambda median warm start | **38ms** |
| AWS share of total query time | **<3%** |

> Compilation overhead (not AWS) is the dominant cost — Lambda + KMS adds <3% of total query time.

### Warehouse Scaling (KEY_PER_QUERY-EXTFUNC)

| Warehouse | 1 Col | 3 Cols | 5 Cols | 7 Cols |
|-----------|-------|--------|--------|--------|
| **XS** | 20.3s | 29.4s | 37.1s | 45.2s |
| **S** | 15.5s | 20.0s | 26.4s | 32.1s |
| **M** | 8.0s | 11.2s | 15.6s | 18.5s |
| **L** | 3.8s | 6.2s | 8.5s | 10.3s |

### Key Findings

- **Column scaling is sub-linear**: 1→7 cols = **2.4x** (not 7x) — TMK is fetched once and reused
- **Warehouse scaling is linear**: L→M = 2x, L→S = 4x — `DECRYPT_RAW` is CPU-bound
- **BI projections** (LIMIT 500) = **1.2-3.4s** on M/L — interactive for dashboards
- **Compilation dominates** small result sets: 58-63% of total time for projections
- **Region parity confirmed**: Singapore matches US-West-2 baseline

## BI Integration Patterns

| Pattern | Session Affinity? | HYOK Approach | Tools |
|---------|-------------------|---------------|-------|
| Per-Query ExtFunc | Not required | KEY_PER_QUERY-EXTFUNC | Sigma, Tableau, any BI |
| Session Init SQL | Required | KEY_IN_SESSION | Tableau (Init SQL), dbt |
| CLI / Notebook | Native | KEY_IN_SESSION | SnowSQL, Python, Jupyter |

> **Default to KEY_PER_QUERY-EXTFUNC for all BI tools** — it works regardless of session model.

### The Sigma Session Problem

Sigma Computing does **not** maintain Snowflake session affinity across queries/widgets. Each visible element runs as its own SQL statement in a potentially different session. This means:

- Session variables set in one query (via `SET` or a stored procedure) are **not reliably available** in the next query
- `KEY_IN_SESSION` requires session affinity → **unreliable in Sigma**
- `KEY_PER_QUERY-EXTFUNC` is the **only reliable approach** for tools that don't maintain sessions

### Audit Trail

With KEY_PER_QUERY-EXTFUNC, every query generates exactly one Lambda invocation logged in CloudWatch. The `sf-external-function-current-query-id` header allows correlating Lambda logs with Snowflake's `QUERY_HISTORY` for complete audit traceability. Red flags:

- **NO QUERY ID** — Lambda was invoked without a Snowflake query ID → possible direct API Gateway access (unauthorized)
- **QH MISS** — Query ID present but not found in `QUERY_HISTORY` → may have aged out or time range mismatch

## Cipher Format & Postgres pgcrypto Compatibility

All approaches produce the same wire format:

```
BASE64( IV_16_bytes || ciphertext_bytes )
```

This format is **directly compatible with PostgreSQL's `pgcrypto` extension**. Data encrypted in Snowflake can be decrypted in Postgres and vice versa, using the same AES-256 key. This enables seamless cross-platform encryption workflows — for example, encrypting data in Snowflake and decrypting it in a Postgres application database, or migrating encrypted data between the two without re-encryption.

### Decrypt Snowflake ciphertext in Postgres

```sql
-- Enable pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Snowflake-produced ciphertext (BASE64 of iv || ciphertext)
-- Decode, split IV (first 16 bytes) and ciphertext (remainder), then decrypt.
SELECT convert_from(
    decrypt_iv(
        substring(decode('<snowflake_base64_ciphertext>', 'base64') FROM 17),  -- ciphertext (skip 16-byte IV)
        decode('<base64_aes_key>', 'base64'),                                  -- AES-256 key
        substring(decode('<snowflake_base64_ciphertext>', 'base64') FOR 16),   -- IV (first 16 bytes)
        'aes-cbc/pad:pkcs'
    ),
    'UTF8'
);
```

### Encrypt in Postgres, decrypt in Snowflake

```sql
-- In Postgres: encrypt with pgcrypto and prepend the IV
SELECT encode(
    iv || encrypt_iv(
        convert_to('Hello from Postgres', 'UTF8'),
        decode('<base64_aes_key>', 'base64'),
        iv,
        'aes-cbc/pad:pkcs'
    ),
    'base64'
)
FROM (SELECT gen_random_bytes(16) AS iv) AS t;

-- In Snowflake: decrypt the Postgres-produced ciphertext
SELECT decrypt_cbc('<postgres_base64_ciphertext>', '<base64_aes_key>');
-- => 'Hello from Postgres'
```

### Compatibility notes

| Aspect | Snowflake | Postgres pgcrypto |
|--------|-----------|-------------------|
| Algorithm | AES-CBC via `ENCRYPT_RAW` / `DECRYPT_RAW` | AES-CBC via `encrypt_iv` / `decrypt_iv` |
| Padding | PKCS#7 (default) | `pad:pkcs` |
| IV | Random 16 bytes, prepended to ciphertext | Must be explicitly prepended |
| Key size | 256-bit (32 bytes, Base64-encoded) | 256-bit (32 bytes) |
| Wire format | `BASE64(IV \|\| ciphertext)` | Same when constructed as shown above |
| Encoding | UTF-8 plaintext | UTF-8 plaintext |

The same format works with any language or framework that supports AES-256-CBC with PKCS#7 padding (Python `cryptography`, Node.js `crypto`, Java `javax.crypto`, Go `crypto/aes`, etc.).

## Quick Start

1. Open a Snowflake worksheet.
2. Set your database and schema context.
3. Run any of the three SQL files end-to-end.

### Minimal example (session variable approach)

```sql
SET aes_cbc_key = '<your-base64-aes-256-key>';

SELECT encrypt_cbc_random_iv('Hello, World!', $aes_cbc_key);

SELECT decrypt_cbc(
    encrypt_cbc_random_iv('Hello, World!', $aes_cbc_key),
    $aes_cbc_key
);
-- => 'Hello, World!'
```

### Minimal example (UDF key vault approach)

```sql
SELECT encrypt_cbc_random_iv('Hello, World!', get_aes_key('YOUR_PASSPHRASE'));

SELECT decrypt_cbc(
    encrypt_cbc_random_iv('Hello, World!', get_aes_key('YOUR_PASSPHRASE')),
    get_aes_key('YOUR_PASSPHRASE')
);
-- => 'Hello, World!'
```

### Minimal example (external function approach)

```sql
SELECT encrypt_cbc_random_iv('Hello, World!', get_aes_key_aws('MY_PASSPHRASE'));

SELECT decrypt_cbc(
    encrypt_cbc_random_iv('Hello, World!', get_aes_key_aws('MY_PASSPHRASE')),
    get_aes_key_aws('MY_PASSPHRASE')
);
-- => 'Hello, World!'

-- Or use per-column external crypto (key never leaves the cloud):
SELECT ext_encrypt_name('John');
SELECT ext_decrypt_name(ext_encrypt_name('John'));
-- => 'John'
```

### Minimal example (key wrapping / HYOK approach)

```sql
-- Activate session (fetches KMS secret, derives wrapped key via SHA-256)
CALL sp_hyok_activate_session('MY_PASSPHRASE');

-- All subsequent queries use the wrapped key transparently
SELECT decrypt_cbc(enc_name, GETVARIABLE('HYOK_TMK')) FROM employees_encrypted;

-- Or with masking policy applied, just SELECT:
SELECT * FROM employees_encrypted;

-- Wipe key when done
UNSET HYOK_TMK;
```

## Objects Created

### Core UDFs (all approaches)

| Object | Type | Purpose |
|--------|------|---------|
| `encrypt_cbc_random_iv` | SQL UDF | Encrypt with random IV |
| `decrypt_cbc` | SQL UDF | Decrypt ciphertext |
| `return_cipher_iv` | SQL UDTF | Split ciphertext into IV + payload |
| `FAKE` | Python UDF | Generate fake employee data |

### Approach-Specific

| Object | Type | Approach | Purpose |
|--------|------|----------|---------|
| `encrypt_cbc_iv` | SQL UDF | 01 | Encrypt with fixed IV |
| `get_aes_key` | SECURE SQL UDF | 02 | Passphrase-protected key vault |
| `get_aes_key_aws` | SECURE EXTERNAL FUNCTION | 03 | Key from AWS KMS |
| `get_aes_key_azure` | SECURE EXTERNAL FUNCTION | 03 | Key from Azure Key Vault |
| `ext_encrypt_name` | SECURE EXTERNAL FUNCTION | 03 | Server-side name encryption |
| `ext_decrypt_name` | SECURE EXTERNAL FUNCTION | 03 | Server-side name decryption |
| `ext_encrypt_address` | SECURE EXTERNAL FUNCTION | 03 | Server-side address encryption |
| `ext_decrypt_address` | SECURE EXTERNAL FUNCTION | 03 | Server-side address decryption |
| `ext_encrypt_phone` | SECURE EXTERNAL FUNCTION | 03 | Server-side phone encryption |
| `ext_decrypt_phone` | SECURE EXTERNAL FUNCTION | 03 | Server-side phone decryption |
| `hyok_fetch_key` | SECURE EXTERNAL FUNCTION | 04 | Fetch KMS secret for key wrapping |
| `derive_session_key` | SQL UDF | 04 | SHA-256 key derivation (secret + salt → AES key) |
| `sp_hyok_activate_session` | SQL Stored Procedure | 04 | One-call session activation |
| `udf_hyok_fetch_wrapped_key` | SECURE SQL UDF | 04 | Per-query wrapped key retrieval |

### Masking Policies & Tags

| Object | Type | Purpose |
|--------|------|---------|
| `encrypt_pg` / `encrypt_pg_v2` / `encrypt_pg_ext` | Masking Policy | Encrypt on read |
| `decrypt_pg` / `decrypt_pg_v2` / `decrypt_pg_ext` | Masking Policy | Decrypt on read |
| `encrypt_name_ext` / `decrypt_name_ext` | Masking Policy | Per-column external crypto |
| `ENCRYPTME2` / `ENCRYPTME_V2` | Tag | Apply encrypt policy to tables |
| `DECRYPTME_V2` / `DECRYPTME_EXT` | Tag | Apply decrypt policy to tables |
| `decrypt_hyok_session` | Masking Policy | 04: Decrypt via session variable |
| `decrypt_hyok_per_query` | Masking Policy | 04: Decrypt via per-query ext func |

## Security Notes

- **Replace the sample AES key** before any real use. Generate a new 256-bit key:
  ```sql
  SELECT BASE64_ENCODE(RANDOM_BYTES(32));
  ```
- The `SECURE` keyword on external functions prevents non-owners from viewing the endpoint URL, headers, and API integration name via `SHOW FUNCTIONS` or `GET_DDL`.
- `IMMUTABLE` allows Snowflake to cache external function results within a query, reducing the number of API calls. However, be aware that cached results may persist in the query result cache.
- Masking policies enforce role-based access; non-`ACCOUNTADMIN` roles see `** masked **`.
- Always audit which roles can call key-retrieval functions.
- For the external function approach, use `CONTEXT_HEADERS` to log who is requesting keys and from which account.
- Consider IP allowlisting on your API Gateway / API Management to restrict access to Snowflake's egress IPs.
- Rotate keys in KMS / Key Vault independently of Snowflake — no Snowflake objects need to change.

## Prerequisites

- Snowflake account with `ACCOUNTADMIN` or sufficient privileges
- Python UDF support (enabled by default on most accounts)
- `faker` and `simplejson` packages (available in Snowflake's Anaconda channel)
- For approach 03:
  - **AWS**: Lambda, API Gateway, KMS, IAM role with trust policy
  - **Azure**: Azure Function, API Management, Key Vault, Azure AD app registration

## License

This project is licensed under the [MIT License](LICENSE).

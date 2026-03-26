# AES-CBC Encryption & Decryption for Snowflake

Column-level AES-256-CBC encryption and decryption using Snowflake's native `ENCRYPT_RAW` / `DECRYPT_RAW` functions. Produces ciphertext in **Postgres pgcrypto-compatible format**: `BASE64(iv_raw_16_bytes || ciphertext_raw)`.

## Features

- AES-256-CBC encryption with random IV per row
- Optional fixed-IV mode for deterministic / cross-system testing
- Tag-based and column-level masking policies for transparent encrypt-on-read
- Decrypt-on-read masking policies for authorized roles
- Fake data generation via Python UDF (Faker)
- Stage-based bulk export workflow
- Two key management strategies (see below)

## Repository Layout

```
.
├── README.md
├── LICENSE
├── sql/
│   ├── 01_session_variable_approach.sql   # Key stored in a session variable
│   └── 02_udf_key_vault_approach.sql      # Key stored in a SECURE IMMUTABLE UDF
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

## Cipher Format

Both approaches produce the same wire format:

```
BASE64( IV_16_bytes || ciphertext_bytes )
```

This is compatible with Postgres `pgcrypto` AES-CBC and can be decoded in any language that supports standard Base64 and AES-CBC.

## Quick Start

1. Open a Snowflake worksheet.
2. Set your database and schema context.
3. Run either SQL file end-to-end.

### Minimal example (session variable approach)

```sql
SET aes_cbc_key = '<your-base64-aes-256-key>';

SELECT encrypt_cbc_random_iv('Hello, World!', $aes_cbc_key);
-- => 'dG9rZW4x...'  (Base64 ciphertext, different each call)

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

## Objects Created

| Object | Type | Purpose |
|--------|------|---------|
| `encrypt_cbc_random_iv` | SQL UDF | Encrypt with random IV |
| `decrypt_cbc` | SQL UDF | Decrypt ciphertext |
| `return_cipher_iv` | SQL UDTF | Split ciphertext into IV + payload |
| `encrypt_cbc_iv` | SQL UDF | Encrypt with fixed IV (session var approach only) |
| `get_aes_key` | SECURE SQL UDF | Passphrase-protected key vault (UDF approach only) |
| `FAKE` | Python UDF | Generate fake employee data |
| `encrypt_pg` / `encrypt_pg_v2` | Masking Policy | Encrypt on read |
| `decrypt_pg` / `decrypt_pg_v2` | Masking Policy | Decrypt on read |
| `ENCRYPTME2` / `ENCRYPTME_V2` | Tag | Apply encrypt policy to tables |
| `DECRYPTME_V2` | Tag | Apply decrypt policy to tables |

## Security Notes

- **Replace the sample AES key** before any real use. Generate a new 256-bit key:
  ```sql
  SELECT BASE64_ENCODE(RANDOM_BYTES(32));
  ```
- The `SECURE` keyword on `get_aes_key` prevents non-owners from viewing the function body via `SHOW FUNCTIONS` or `GET_DDL`.
- Masking policies enforce role-based access; non-`ACCOUNTADMIN` roles see `** masked **`.
- Always audit which roles can call `get_aes_key` or access the session variable.

## Prerequisites

- Snowflake account with `ACCOUNTADMIN` or sufficient privileges
- Python UDF support (enabled by default on most accounts)
- `faker` and `simplejson` packages (available in Snowflake's Anaconda channel)

## License

This project is licensed under the [MIT License](LICENSE).

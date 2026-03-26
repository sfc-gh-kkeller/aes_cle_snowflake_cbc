-- =============================================================================
-- 04 - KEY WRAPPING APPROACH (Hold Your Own Key / HYOK)
-- =============================================================================
-- Demonstrates session-key wrapping via SHA-256 key derivation.
-- Two key delivery patterns:
--   A) KEY_IN_SESSION  - key fetched once at connect, stored in session variable
--   B) KEY_PER_QUERY   - key fetched transparently per query via external function
--
-- Architecture:
--   Step 1 (compile phase): External function calls Lambda → KMS → returns secret
--   Step 2 (execution):     SHA256(secret || session_context) → wrapped TMK
--                           DECRYPT_RAW uses the wrapped TMK (pure SQL, CPU-only)
--
-- The key wrapping layer adds defense-in-depth: even if the external function
-- response is intercepted, the raw KMS secret alone cannot decrypt data without
-- the session-specific derivation context.
-- =============================================================================

USE ROLE ACCOUNTADMIN;
CREATE DATABASE IF NOT EXISTS HYOK_DB;
CREATE SCHEMA IF NOT EXISTS HYOK_DB.ENCRYPTION;
USE SCHEMA HYOK_DB.ENCRYPTION;

-- =============================================================================
-- PART A: API Integration & External Functions
-- =============================================================================

CREATE OR REPLACE API INTEGRATION hyok_aws_api_integration
    API_PROVIDER         = aws_api_gateway
    API_AWS_ROLE_ARN     = 'arn:aws:iam::<account_id>:role/snowflake-hyok-role'
    API_ALLOWED_PREFIXES = ('https://<api-id>.execute-api.<region>.amazonaws.com/prod/')
    ENABLED              = TRUE;

CREATE OR REPLACE SECURE EXTERNAL FUNCTION hyok_fetch_key(passphrase VARCHAR)
    RETURNS VARCHAR
    IMMUTABLE
    API_INTEGRATION  = hyok_aws_api_integration
    MAX_BATCH_ROWS   = 1
    CONTEXT_HEADERS  = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://<api-id>.execute-api.<region>.amazonaws.com/prod/hyok-key';

-- =============================================================================
-- PART B: Key Wrapping via SHA-256 Derivation
-- =============================================================================

-- Derive a session-bound wrapped key from the KMS secret + a session-specific salt.
-- SHA-256 produces a 256-bit (32-byte) key suitable for AES-256.

CREATE OR REPLACE FUNCTION derive_session_key(kms_secret VARCHAR, session_salt VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
    IMMUTABLE
AS
$$
    BASE64_ENCODE(SHA2_BINARY(kms_secret || '|' || session_salt, 256))
$$;

-- The session salt can be any session-unique value. Examples:
--   CURRENT_SESSION()           - unique per connection
--   CURRENT_USER() || CURRENT_TIMESTAMP()::VARCHAR  - user + time bound
--   A nonce from the external function response

-- =============================================================================
-- PART C: KEY_IN_SESSION Pattern (key fetched once at connect)
-- =============================================================================

-- Step 1: Activation stored procedure (run once at session start)
-- This procedure:
--   1. Calls the external function to get the KMS secret
--   2. Derives a session-bound wrapped key via SHA-256
--   3. Stores the wrapped key in a session variable

CREATE OR REPLACE PROCEDURE sp_hyok_activate_session(passphrase VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
    EXECUTE AS CALLER
AS
$$
BEGIN
    LET kms_secret VARCHAR := (SELECT hyok_fetch_key(:passphrase));
    LET session_salt VARCHAR := (SELECT CURRENT_SESSION() || '|' || CURRENT_USER());
    LET wrapped_key VARCHAR := (SELECT derive_session_key(:kms_secret, :session_salt));
    EXECUTE IMMEDIATE 'SET HYOK_TMK = ''' || :wrapped_key || '''';
    RETURN 'Session activated. Wrapped TMK set.';
END;
$$;

-- Usage:
-- CALL sp_hyok_activate_session('MY_PASSPHRASE');
-- All subsequent queries use GETVARIABLE('HYOK_TMK') — zero outbound calls.

-- =============================================================================
-- PART D: KEY_PER_QUERY Pattern (key fetched transparently per query)
-- =============================================================================

-- A UDF that wraps the external function call + key derivation into a single
-- expression usable inside masking policies.

CREATE OR REPLACE SECURE FUNCTION udf_hyok_fetch_wrapped_key()
    RETURNS VARCHAR
    LANGUAGE SQL
    IMMUTABLE
AS
$$
    derive_session_key(
        hyok_fetch_key('MY_PASSPHRASE'),
        CURRENT_SESSION() || '|' || CURRENT_USER()
    )
$$;

-- This is called once per query at compile time (MAX_BATCH_ROWS=1 on the ext func),
-- then the result is used as a plan constant for all DECRYPT_RAW calls in execution.

-- =============================================================================
-- PART E: Encrypt / Decrypt UDFs using AES-256-CBC
-- =============================================================================

CREATE OR REPLACE FUNCTION encrypt_cbc_random_iv(plaintext VARCHAR, key_b64 VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
    IMMUTABLE
AS
$$
    BASE64_ENCODE(
        RANDOM_BYTES(16) ||
        ENCRYPT_RAW(
            TO_BINARY(plaintext, 'UTF-8'),
            BASE64_DECODE_BINARY(key_b64),
            RANDOM_BYTES(16),
            'AES-CBC/PAD:PKCS'
        )
    )
$$;

CREATE OR REPLACE FUNCTION decrypt_cbc(ciphertext_b64 VARCHAR, key_b64 VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
    IMMUTABLE
AS
$$
    TO_VARCHAR(
        DECRYPT_RAW(
            SUBSTR(BASE64_DECODE_BINARY(ciphertext_b64), 17),
            BASE64_DECODE_BINARY(key_b64),
            SUBSTR(BASE64_DECODE_BINARY(ciphertext_b64), 1, 16),
            'AES-CBC/PAD:PKCS'
        ),
        'UTF-8'
    )
$$;

-- =============================================================================
-- PART F: Masking Policies
-- =============================================================================

-- Decrypt policy using KEY_IN_SESSION (GETVARIABLE)
CREATE OR REPLACE MASKING POLICY decrypt_hyok_session
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN')
             AND GETVARIABLE('HYOK_TMK') IS NOT NULL
        THEN decrypt_cbc(val, GETVARIABLE('HYOK_TMK'))
        ELSE '** HYOK key not loaded **'
    END;

-- Decrypt policy using KEY_PER_QUERY (external function per query)
CREATE OR REPLACE MASKING POLICY decrypt_hyok_per_query
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN')
        THEN decrypt_cbc(val, udf_hyok_fetch_wrapped_key())
        ELSE '** access denied **'
    END;

-- =============================================================================
-- PART G: Demo Table & Test Data
-- =============================================================================

CREATE OR REPLACE TABLE employees_encrypted (
    row_id       NUMBER AUTOINCREMENT,
    enc_name     VARCHAR,
    enc_email    VARCHAR,
    enc_phone    VARCHAR,
    enc_salary   VARCHAR,
    enc_ssn      VARCHAR,
    enc_address  VARCHAR,
    enc_dob      VARCHAR,
    dept         VARCHAR,
    created_at   TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Encrypt sample data using the session key
-- First activate the session:
-- CALL sp_hyok_activate_session('MY_PASSPHRASE');

INSERT INTO employees_encrypted (enc_name, enc_email, enc_phone, enc_salary, enc_ssn, enc_address, enc_dob, dept)
SELECT
    encrypt_cbc_random_iv('John Smith',           GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('john@example.com',     GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('+1-555-0100',          GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('85000',                GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('123-45-6789',          GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('123 Main St, NYC',     GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('1990-01-15',           GETVARIABLE('HYOK_TMK')),
    'Engineering';

INSERT INTO employees_encrypted (enc_name, enc_email, enc_phone, enc_salary, enc_ssn, enc_address, enc_dob, dept)
SELECT
    encrypt_cbc_random_iv('Jane Doe',              GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('jane@example.com',      GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('+1-555-0200',           GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('92000',                 GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('987-65-4321',           GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('456 Oak Ave, LA',       GETVARIABLE('HYOK_TMK')),
    encrypt_cbc_random_iv('1985-07-22',            GETVARIABLE('HYOK_TMK')),
    'Marketing';

-- =============================================================================
-- PART H: Apply Masking Policies
-- =============================================================================

-- Apply session-based decrypt policy (recommended for CLI / notebooks)
ALTER TABLE employees_encrypted MODIFY COLUMN enc_name    SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_email   SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_phone   SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_salary  SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_ssn     SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_address SET MASKING POLICY decrypt_hyok_session;
ALTER TABLE employees_encrypted MODIFY COLUMN enc_dob     SET MASKING POLICY decrypt_hyok_session;

-- To switch to per-query (for BI tools like Sigma), replace the policy:
-- ALTER TABLE employees_encrypted MODIFY COLUMN enc_name
--     SET MASKING POLICY decrypt_hyok_per_query FORCE;

-- =============================================================================
-- PART I: Query Examples
-- =============================================================================

-- KEY_IN_SESSION: activate once, then query freely
CALL sp_hyok_activate_session('MY_PASSPHRASE');

SELECT row_id, enc_name, enc_email, enc_salary, dept
FROM employees_encrypted;

-- Aggregation over encrypted salary (50M rows @ L warehouse ≈ 10.3s for 7 cols)
SELECT dept, SUM(TRY_TO_NUMBER(enc_salary)) AS total_salary
FROM employees_encrypted
GROUP BY dept;

-- KEY_PER_QUERY: no setup needed, masking policy handles everything
-- (requires decrypt_hyok_per_query policy to be applied)
-- SELECT * FROM employees_encrypted;  -- external function called once per query

-- =============================================================================
-- PART J: Session Wipe (security hygiene)
-- =============================================================================

-- Clear the session key when done
UNSET HYOK_TMK;

-- Verify it's gone
SELECT GETVARIABLE('HYOK_TMK');  -- returns NULL

-- =============================================================================
-- PART K: Two-Step Query Plan Explanation
-- =============================================================================
-- When using KEY_PER_QUERY, the Snowflake query profile shows TWO steps:
--
--   Step 1 (Compile): SecureFunction nodes — the external function call
--     - POLICY_HYOK_EXTFUNC(TABLE_KEK_E...)
--     - Total: ~1.2s (Remote disk I/O 50%, Initialization 50%)
--     - This is the Lambda + KMS round-trip
--
--   Step 2 (Execute): TableScan + Aggregate + Result
--     - Processing: 97.4%, Local disk I/O: 1.2%
--     - Total: ~12s for 50M rows / 7 cols on L warehouse
--     - No network calls — DECRYPT_RAW is pure CPU
--
-- Key insight: The external function call happens ONCE at compile time.
-- The key is then used as a plan constant for all DECRYPT_RAW operations.
-- This is why column scaling is sub-linear (2.4x for 7 cols, not 7x).

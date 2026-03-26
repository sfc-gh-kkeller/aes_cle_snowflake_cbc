-- =============================================================================
-- AES-CBC Encryption & Decryption – External Function + Cloud KMS Approach
-- =============================================================================
-- This worksheet demonstrates how to replace the local UDF key vault with
-- a SECURE EXTERNAL FUNCTION that retrieves the AES key from a cloud KMS
-- (AWS KMS via Lambda, or Azure Key Vault via Azure Function).
--
-- The key NEVER resides in Snowflake — it is fetched at query time from
-- the cloud provider's key management service.
--
-- Architecture:
--
--   Snowflake  ──▶  API Gateway  ──▶  Lambda / Azure Function  ──▶  KMS / Key Vault
--       │                                       │
--       │◀──────────  AES key (encrypted in transit) ──────────│
--
-- This file contains:
--   1. API integration setup (AWS and Azure)
--   2. External function definitions
--   3. Per-column external functions for encrypt/decrypt
--   4. Masking policies using external key retrieval
--   5. Full end-to-end demo with mock data
--
-- NOTE: The Lambda/Azure Function sample code is in the companion directories:
--       aws_lambda/   and   azure_function/
-- =============================================================================


-- #############################################################################
-- PART A: AWS – API Gateway + Lambda + KMS
-- #############################################################################


-- =============================================================================
-- STEP A1: Create the API Integration (AWS)
-- =============================================================================
-- This tells Snowflake how to reach your API Gateway endpoint.
-- The api_aws_role_arn is the IAM role Snowflake assumes to invoke the gateway.
-- Run DESCRIBE INTEGRATION after creation to get the
-- API_AWS_EXTERNAL_ID and API_AWS_IAM_USER_ARN needed for the trust policy.
-- =============================================================================

CREATE OR REPLACE API INTEGRATION kms_api_aws
    API_PROVIDER         = aws_api_gateway
    API_AWS_ROLE_ARN     = 'arn:aws:iam::123456789012:role/snowflake-kms-role'
    API_ALLOWED_PREFIXES = ('https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/')
    ENABLED              = TRUE
    COMMENT              = 'Integration for AES key retrieval from AWS KMS via Lambda';

DESCRIBE INTEGRATION kms_api_aws;

-- After DESCRIBE, note:
--   API_AWS_IAM_USER_ARN   → add to your IAM role trust policy
--   API_AWS_EXTERNAL_ID    → add as sts:ExternalId condition


-- =============================================================================
-- STEP A2: External Function – Get AES Key from AWS KMS
-- =============================================================================
-- The Lambda behind this endpoint:
--   1. Receives the passphrase from Snowflake
--   2. Validates the passphrase
--   3. Calls KMS Decrypt on the encrypted key material
--   4. Returns the Base64-encoded AES-256 key
--
-- Marked SECURE so the endpoint URL and headers are hidden.
-- Marked IMMUTABLE so Snowflake can cache the result within a query.
-- CONTEXT_HEADERS pass audit metadata to the Lambda for logging.
-- =============================================================================

CREATE OR REPLACE SECURE EXTERNAL FUNCTION get_aes_key_aws(passphrase VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Retrieves AES-256 key from AWS KMS via Lambda. Requires valid passphrase.'
    API_INTEGRATION = kms_api_aws
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/get-aes-key';


-- =============================================================================
-- STEP A3: Per-Column External Functions (Encrypt / Decrypt)
-- =============================================================================
-- If you want the cloud service to perform encryption/decryption itself
-- (instead of just returning the key), you can create per-column external
-- functions. This keeps the key entirely server-side — Snowflake never sees it.
--
-- Each function targets a specific data element type so the backend can apply
-- format-preserving or type-specific logic if needed.
-- =============================================================================

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_encrypt_name(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Encrypts name values via external service (AES-CBC, key never leaves KMS).'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'name',
        'X-Operation'    = 'encrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_decrypt_name(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Decrypts name values via external service.'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'name',
        'X-Operation'    = 'decrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_encrypt_address(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Encrypts address values via external service.'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'address',
        'X-Operation'    = 'encrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_decrypt_address(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Decrypts address values via external service.'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'address',
        'X-Operation'    = 'decrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_encrypt_phone(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Encrypts phone values via external service.'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'phone',
        'X-Operation'    = 'encrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';

CREATE OR REPLACE SECURE EXTERNAL FUNCTION ext_decrypt_phone(val VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Decrypts phone values via external service.'
    API_INTEGRATION = kms_api_aws
    HEADERS = (
        'X-Data-Element' = 'phone',
        'X-Operation'    = 'decrypt'
    )
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prod/crypto';


-- #############################################################################
-- PART B: AZURE – API Management + Azure Function + Key Vault
-- #############################################################################


-- =============================================================================
-- STEP B1: Create the API Integration (Azure)
-- =============================================================================

CREATE OR REPLACE API INTEGRATION kms_api_azure
    API_PROVIDER                  = azure_api_management
    AZURE_TENANT_ID               = 'a]123e4567-e89b-12d3-a456-426614174000'
    AZURE_AD_APPLICATION_ID       = 'b1234567-abcd-4321-efgh-123456789abc'
    API_ALLOWED_PREFIXES          = ('https://my-apim.azure-api.net/snowflake/')
    ENABLED                       = TRUE
    COMMENT                       = 'Integration for AES key retrieval from Azure Key Vault';

DESCRIBE INTEGRATION kms_api_azure;

-- After DESCRIBE, note:
--   AZURE_CONSENT_URL        → open in browser to grant consent
--   AZURE_MULTI_TENANT_APP_NAME → add to your Azure AD app registration


-- =============================================================================
-- STEP B2: External Function – Get AES Key from Azure Key Vault
-- =============================================================================

CREATE OR REPLACE SECURE EXTERNAL FUNCTION get_aes_key_azure(passphrase VARCHAR)
    RETURNS VARCHAR
    NOT NULL
    IMMUTABLE
    COMMENT = 'Retrieves AES-256 key from Azure Key Vault via Azure Function.'
    API_INTEGRATION = kms_api_azure
    CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
    AS 'https://my-apim.azure-api.net/snowflake/get-aes-key';


-- #############################################################################
-- PART C: USING THE EXTERNAL KEY WITH LOCAL ENCRYPT/DECRYPT UDFs
-- #############################################################################
-- This approach retrieves the key from the cloud KMS but performs the actual
-- AES-CBC encrypt/decrypt inside Snowflake using ENCRYPT_RAW / DECRYPT_RAW.
-- The key transits through Snowflake but is never stored.
-- =============================================================================


-- =============================================================================
-- STEP C1: Encryption & Decryption UDFs (same as approach 02)
-- =============================================================================

CREATE OR REPLACE FUNCTION encrypt_cbc_random_iv(inputtext VARCHAR, key VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
$$
SELECT BASE64_ENCODE(
    AS_BINARY(GET(enc, 'iv')) ||
    AS_BINARY(GET(enc, 'ciphertext'))
)
FROM (
    SELECT ENCRYPT_RAW(
        TO_BINARY(inputtext, 'UTF-8'),
        BASE64_DECODE_BINARY(key),
        NULL,
        NULL,
        'AES-CBC'
    ) AS enc
)
$$;

CREATE OR REPLACE FUNCTION decrypt_cbc(cipher VARCHAR, key VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
$$
TO_VARCHAR(
    DECRYPT_RAW(
        TO_BINARY(SUBSTR(HEX_ENCODE(TO_BINARY(cipher, 'BASE64')), 33), 'HEX'),
        BASE64_DECODE_BINARY(key),
        TO_BINARY(LEFT(HEX_ENCODE(TO_BINARY(cipher, 'BASE64')), 32), 'HEX'),
        NULL,
        'AES-CBC'
    ),
    'UTF-8'
)
$$;


-- =============================================================================
-- STEP C2: Test – Encrypt & Decrypt Using External Key (AWS)
-- =============================================================================

SELECT encrypt_cbc_random_iv('Hello, World!', get_aes_key_aws('MY_PASSPHRASE'));

SELECT decrypt_cbc(
    encrypt_cbc_random_iv('Hello, World!', get_aes_key_aws('MY_PASSPHRASE')),
    get_aes_key_aws('MY_PASSPHRASE')
);


-- =============================================================================
-- STEP C3: Test – Encrypt & Decrypt Using External Key (Azure)
-- =============================================================================

SELECT encrypt_cbc_random_iv('Hello, World!', get_aes_key_azure('MY_PASSPHRASE'));

SELECT decrypt_cbc(
    encrypt_cbc_random_iv('Hello, World!', get_aes_key_azure('MY_PASSPHRASE')),
    get_aes_key_azure('MY_PASSPHRASE')
);


-- #############################################################################
-- PART D: MASKING POLICIES WITH EXTERNAL KEY RETRIEVAL
-- #############################################################################


-- =============================================================================
-- STEP D1: Encrypt-on-Read Masking Policy (External Key)
-- =============================================================================

CREATE OR REPLACE MASKING POLICY encrypt_pg_ext
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            encrypt_cbc_random_iv(val, get_aes_key_aws('MY_PASSPHRASE'))
        ELSE '** masked **'
    END;


-- =============================================================================
-- STEP D2: Decrypt-on-Read Masking Policy (External Key)
-- =============================================================================

CREATE OR REPLACE MASKING POLICY decrypt_pg_ext
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            decrypt_cbc(val, get_aes_key_aws('MY_PASSPHRASE'))
        ELSE '** masked **'
    END;


-- =============================================================================
-- STEP D3: Masking Policy Using Fully-External Crypto (Per-Column)
-- =============================================================================
-- When the external service handles encryption/decryption itself,
-- the masking policy simply delegates to the external function.
-- The key never leaves the cloud KMS.
-- =============================================================================

CREATE OR REPLACE MASKING POLICY encrypt_name_ext
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN ext_encrypt_name(val)
        ELSE '** masked **'
    END;

CREATE OR REPLACE MASKING POLICY decrypt_name_ext
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN ext_decrypt_name(val)
        ELSE '** masked **'
    END;


-- #############################################################################
-- PART E: END-TO-END DEMO
-- #############################################################################


-- =============================================================================
-- STEP E1: Create Tables & Generate Fake Data
-- =============================================================================

CREATE OR REPLACE TABLE employee_ext_src (
    emp_id     VARCHAR,
    firstname  VARCHAR,
    lastname   VARCHAR,
    address    VARCHAR,
    postalcode VARCHAR,
    phone      VARCHAR
);

CREATE OR REPLACE TABLE employee_ext_enc (
    emp_id     VARCHAR,
    firstname  VARCHAR,
    lastname   VARCHAR,
    address    VARCHAR,
    postalcode VARCHAR,
    phone      VARCHAR
);

CREATE OR REPLACE FUNCTION FAKE(locale VARCHAR, provider VARCHAR, parameters VARIANT)
    RETURNS VARIANT
    LANGUAGE PYTHON
    VOLATILE
    RUNTIME_VERSION = '3.11'
    PACKAGES = ('faker', 'simplejson')
    HANDLER = 'fake'
AS
$$
import simplejson as json
from faker import Faker
def fake(locale, provider, parameters):
    if type(parameters).__name__ == 'sqlNullWrapper':
        parameters = {}
    fake = Faker(locale=locale)
    return json.loads(json.dumps(fake.format(formatter=provider, **parameters), default=str))
$$;

CREATE OR REPLACE VIEW fake_data_v3 AS
SELECT
    FAKE('en_US', 'ean',            {'length': 8})::VARCHAR AS emp_id,
    FAKE('en_US', 'first_name',     NULL)::VARCHAR          AS firstname,
    FAKE('en_US', 'last_name',      NULL)::VARCHAR          AS lastname,
    FAKE('en_US', 'street_address', NULL)::VARCHAR          AS address,
    FAKE('en_US', 'postalcode',     NULL)::VARCHAR          AS postalcode,
    FAKE('en_US', 'phone_number',   NULL)::VARCHAR          AS phone
FROM TABLE(GENERATOR(ROWCOUNT => 200));

INSERT INTO employee_ext_src SELECT * FROM fake_data_v3;

SELECT * FROM employee_ext_src LIMIT 5;


-- =============================================================================
-- STEP E2: Encrypt All Columns Using External Key
-- =============================================================================

TRUNCATE TABLE employee_ext_enc;

INSERT INTO employee_ext_enc
SELECT
    encrypt_cbc_random_iv(emp_id,     get_aes_key_aws('MY_PASSPHRASE')),
    encrypt_cbc_random_iv(firstname,  get_aes_key_aws('MY_PASSPHRASE')),
    encrypt_cbc_random_iv(lastname,   get_aes_key_aws('MY_PASSPHRASE')),
    encrypt_cbc_random_iv(address,    get_aes_key_aws('MY_PASSPHRASE')),
    encrypt_cbc_random_iv(postalcode, get_aes_key_aws('MY_PASSPHRASE')),
    encrypt_cbc_random_iv(phone,      get_aes_key_aws('MY_PASSPHRASE'))
FROM employee_ext_src;

SELECT * FROM employee_ext_enc LIMIT 5;


-- =============================================================================
-- STEP E3: Apply Decrypt-on-Read via Tag
-- =============================================================================

CREATE OR REPLACE TAG DECRYPTME_EXT;

ALTER TAG DECRYPTME_EXT SET MASKING POLICY decrypt_pg_ext;
ALTER TABLE employee_ext_enc SET TAG DECRYPTME_EXT = 'YUP';

SELECT * FROM employee_ext_enc LIMIT 5;

ALTER TAG DECRYPTME_EXT UNSET MASKING POLICY decrypt_pg_ext;


-- =============================================================================
-- STEP E4: Alternative – Per-Column External Crypto (No Key in Snowflake)
-- =============================================================================
-- Apply encrypt masking policy that delegates entirely to the external service.

ALTER TABLE employee_ext_src MODIFY COLUMN firstname SET MASKING POLICY encrypt_name_ext;
ALTER TABLE employee_ext_src MODIFY COLUMN lastname  SET MASKING POLICY encrypt_name_ext;

SELECT firstname, lastname FROM employee_ext_src LIMIT 5;

ALTER TABLE employee_ext_src MODIFY COLUMN firstname UNSET MASKING POLICY;
ALTER TABLE employee_ext_src MODIFY COLUMN lastname  UNSET MASKING POLICY;


-- =============================================================================
-- STEP E5: Verification
-- =============================================================================

SELECT COUNT(*) FROM employee_ext_src;
SELECT COUNT(*) FROM employee_ext_enc;


-- =============================================================================
-- STEP E6: Cleanup (Optional)
-- =============================================================================

-- DROP TABLE employee_ext_src;
-- DROP TABLE employee_ext_enc;
-- DROP VIEW  fake_data_v3;
-- DROP FUNCTION get_aes_key_aws(VARCHAR);
-- DROP FUNCTION get_aes_key_azure(VARCHAR);
-- DROP FUNCTION ext_encrypt_name(VARCHAR);
-- DROP FUNCTION ext_decrypt_name(VARCHAR);
-- DROP FUNCTION ext_encrypt_address(VARCHAR);
-- DROP FUNCTION ext_decrypt_address(VARCHAR);
-- DROP FUNCTION ext_encrypt_phone(VARCHAR);
-- DROP FUNCTION ext_decrypt_phone(VARCHAR);
-- DROP FUNCTION encrypt_cbc_random_iv(VARCHAR, VARCHAR);
-- DROP FUNCTION decrypt_cbc(VARCHAR, VARCHAR);
-- DROP FUNCTION FAKE(VARCHAR, VARCHAR, VARIANT);
-- DROP MASKING POLICY encrypt_pg_ext;
-- DROP MASKING POLICY decrypt_pg_ext;
-- DROP MASKING POLICY encrypt_name_ext;
-- DROP MASKING POLICY decrypt_name_ext;
-- DROP TAG DECRYPTME_EXT;
-- DROP API INTEGRATION kms_api_aws;
-- DROP API INTEGRATION kms_api_azure;


-- #############################################################################
-- APPENDIX: SETUP CHECKLIST
-- #############################################################################
--
-- AWS Setup Steps:
--   1. Create a Lambda function (see aws_lambda/handler.py)
--   2. Grant the Lambda role access to KMS:
--        kms:Decrypt on arn:aws:kms:<region>:<account>:key/<key-id>
--   3. Create an API Gateway (REST API) with a resource + POST method
--      pointing to the Lambda, using AWS_IAM auth
--   4. In Snowflake, CREATE API INTEGRATION (Step A1 above)
--   5. DESCRIBE INTEGRATION → get IAM_USER_ARN and EXTERNAL_ID
--   6. Update the IAM role trust policy to allow Snowflake to assume it:
--        {
--          "Version": "2012-10-17",
--          "Statement": [{
--            "Effect": "Allow",
--            "Principal": { "AWS": "<API_AWS_IAM_USER_ARN>" },
--            "Action": "sts:AssumeRole",
--            "Condition": {
--              "StringEquals": {
--                "sts:ExternalId": "<API_AWS_EXTERNAL_ID>"
--              }
--            }
--          }]
--        }
--   7. CREATE EXTERNAL FUNCTION (Step A2 above)
--   8. Test: SELECT get_aes_key_aws('MY_PASSPHRASE');
--
-- Azure Setup Steps:
--   1. Create an Azure Function (see azure_function/function_app.py)
--   2. Grant the Function's managed identity access to Key Vault:
--        Key Vault Secrets User (or Key Vault Crypto User)
--   3. Create an API Management instance fronting the Function
--   4. Register an Azure AD app for Snowflake
--   5. In Snowflake, CREATE API INTEGRATION (Step B1 above)
--   6. DESCRIBE INTEGRATION → get AZURE_CONSENT_URL
--   7. Open the consent URL in a browser and grant admin consent
--   8. CREATE EXTERNAL FUNCTION (Step B2 above)
--   9. Test: SELECT get_aes_key_azure('MY_PASSPHRASE');
--
-- External Function Request/Response Format:
--   Snowflake sends:
--     POST { "data": [[0, "MY_PASSPHRASE"], [1, "MY_PASSPHRASE"], ...] }
--   Your service returns:
--     { "data": [[0, "base64-aes-key"], [1, "base64-aes-key"], ...] }
--
-- CONTEXT_HEADERS:
--   When CONTEXT_HEADERS = (CURRENT_USER, CURRENT_TIMESTAMP, CURRENT_ACCOUNT)
--   is specified, Snowflake sends additional HTTP headers:
--     sf-context-current-user:      the Snowflake username
--     sf-context-current-timestamp: query execution timestamp
--     sf-context-current-account:   the Snowflake account identifier
--   Use these for audit logging and access control in your backend.
--
-- #############################################################################

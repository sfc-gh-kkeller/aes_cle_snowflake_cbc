-- =============================================================================
-- AES-CBC Encryption & Decryption – UDF-Based Key Management
-- =============================================================================
-- Variant that stores the AES key inside a SECURE IMMUTABLE SQL UDF protected
-- by a passphrase. The key is never exposed in session variables — callers
-- must know the passphrase to retrieve it.
-- =============================================================================


-- =============================================================================
-- STEP 1: Key Vault UDF (SECURE + IMMUTABLE)
-- =============================================================================
-- Returns the AES-256 key only when the correct passphrase is supplied.
-- Marked SECURE so the body is hidden from non-owners.
-- Marked IMMUTABLE so Snowflake can cache the result.
-- =============================================================================

CREATE OR REPLACE SECURE FUNCTION get_aes_key(password VARCHAR)
    RETURNS VARCHAR
    IMMUTABLE
AS
$$
    CASE
        WHEN password = 'KEVIN'
            THEN 'qg0q8m+kwmjcIIXkhZF2P1krwi+h/ry3CXJhqiZJT6M='
        ELSE NULL
    END
$$;

-- Should return the key
SELECT get_aes_key('KEVIN');

-- Should return NULL
SELECT get_aes_key('wrong');


-- =============================================================================
-- STEP 2: Create Tables
-- =============================================================================

CREATE OR REPLACE TABLE employee_src (
    emp_id     VARCHAR,
    firstname  VARCHAR,
    lastname   VARCHAR,
    address    VARCHAR,
    postalcode VARCHAR,
    phone      VARCHAR
);

CREATE OR REPLACE TABLE employee_enc (
    emp_id     VARCHAR,
    firstname  VARCHAR,
    lastname   VARCHAR,
    address    VARCHAR,
    postalcode VARCHAR,
    phone      VARCHAR
);


-- =============================================================================
-- STEP 3: Fake Data Generator (Python UDF using Faker)
-- =============================================================================

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

CREATE OR REPLACE VIEW fake_data_v2 AS
SELECT
    FAKE('en_US', 'ean',            {'length': 8})::VARCHAR AS emp_id,
    FAKE('en_US', 'first_name',     NULL)::VARCHAR          AS firstname,
    FAKE('en_US', 'last_name',      NULL)::VARCHAR          AS lastname,
    FAKE('en_US', 'street_address', NULL)::VARCHAR          AS address,
    FAKE('en_US', 'postalcode',     NULL)::VARCHAR          AS postalcode,
    FAKE('en_US', 'phone_number',   NULL)::VARCHAR          AS phone
FROM TABLE(GENERATOR(ROWCOUNT => 200));

SELECT * FROM fake_data_v2 LIMIT 10;

INSERT INTO employee_src SELECT * FROM fake_data_v2;

SELECT * FROM employee_src LIMIT 5;


-- =============================================================================
-- STEP 4: Encryption Function (Random IV)
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

SELECT encrypt_cbc_random_iv('test', get_aes_key('KEVIN'));
SELECT encrypt_cbc_random_iv('test', get_aes_key('KEVIN'));


-- =============================================================================
-- STEP 5: Decryption Function
-- =============================================================================

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

SELECT decrypt_cbc(encrypt_cbc_random_iv('test', get_aes_key('KEVIN')), get_aes_key('KEVIN'));
SELECT decrypt_cbc(encrypt_cbc_random_iv('Bonjour', get_aes_key('KEVIN')), get_aes_key('KEVIN'));


-- =============================================================================
-- STEP 6: Helper – Split Cipher into Components (Table Function)
-- =============================================================================

CREATE OR REPLACE FUNCTION return_cipher_iv(cipher VARCHAR)
    RETURNS TABLE(ciphertext VARCHAR, iv VARCHAR)
AS
$$
SELECT
    BASE64_ENCODE(TO_BINARY(SUBSTR(h, 33), 'HEX')) AS ciphertext,
    BASE64_ENCODE(TO_BINARY(LEFT(h, 32), 'HEX')) AS iv
FROM (SELECT HEX_ENCODE(TO_BINARY(cipher, 'BASE64')) AS h)
$$;

SELECT * FROM TABLE(return_cipher_iv(encrypt_cbc_random_iv('test', get_aes_key('KEVIN'))));


-- =============================================================================
-- STEP 7: Masking Policy – Encrypt on Read (Tag-Based)
-- =============================================================================
-- The passphrase 'KEVIN' is hardcoded inside the masking policy.
-- Users cannot see this because get_aes_key is SECURE.
-- =============================================================================

CREATE OR REPLACE MASKING POLICY encrypt_pg_v2
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            encrypt_cbc_random_iv(val, get_aes_key('KEVIN'))
        ELSE '** masked **'
    END;

CREATE OR REPLACE TAG ENCRYPTME_V2;

ALTER TAG ENCRYPTME_V2 SET MASKING POLICY encrypt_pg_v2;
ALTER TABLE employee_src SET TAG ENCRYPTME_V2 = 'YUP';

SELECT emp_id FROM employee_src LIMIT 3;

ALTER TAG ENCRYPTME_V2 UNSET MASKING POLICY encrypt_pg_v2;


-- =============================================================================
-- STEP 8: Masking Policy – Encrypt Column Directly
-- =============================================================================

ALTER TABLE employee_src MODIFY COLUMN firstname SET MASKING POLICY encrypt_pg_v2;

SELECT firstname FROM employee_src LIMIT 5;

ALTER TABLE employee_src MODIFY COLUMN firstname UNSET MASKING POLICY;


-- =============================================================================
-- STEP 9: Populate employee_enc with Encrypted Data
-- =============================================================================

TRUNCATE TABLE employee_enc;

INSERT INTO employee_enc
SELECT
    encrypt_cbc_random_iv(emp_id,     get_aes_key('KEVIN')),
    encrypt_cbc_random_iv(firstname,  get_aes_key('KEVIN')),
    encrypt_cbc_random_iv(lastname,   get_aes_key('KEVIN')),
    encrypt_cbc_random_iv(address,    get_aes_key('KEVIN')),
    encrypt_cbc_random_iv(postalcode, get_aes_key('KEVIN')),
    encrypt_cbc_random_iv(phone,      get_aes_key('KEVIN'))
FROM employee_src;

SELECT * FROM employee_enc LIMIT 10;


-- =============================================================================
-- STEP 10: Decryption Masking Policy – Tag-Based (Decrypt on Read)
-- =============================================================================

CREATE OR REPLACE MASKING POLICY decrypt_pg_v2
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            decrypt_cbc(val, get_aes_key('KEVIN'))
        ELSE '** masked **'
    END;

CREATE OR REPLACE TAG DECRYPTME_V2;

ALTER TAG DECRYPTME_V2 SET MASKING POLICY decrypt_pg_v2;
ALTER TABLE employee_enc SET TAG DECRYPTME_V2 = 'YUP';

SELECT * FROM employee_enc LIMIT 5;

ALTER TAG DECRYPTME_V2 UNSET MASKING POLICY decrypt_pg_v2;


-- =============================================================================
-- STEP 11: Quick Verification
-- =============================================================================

SELECT COUNT(*) FROM employee_src;
SELECT COUNT(*) FROM employee_enc;


-- =============================================================================
-- STEP 12: Cleanup (Optional)
-- =============================================================================

-- DROP TABLE employee_src;
-- DROP TABLE employee_enc;
-- DROP VIEW  fake_data_v2;
-- DROP FUNCTION get_aes_key(VARCHAR);
-- DROP FUNCTION encrypt_cbc_random_iv(VARCHAR, VARCHAR);
-- DROP FUNCTION decrypt_cbc(VARCHAR, VARCHAR);
-- DROP FUNCTION return_cipher_iv(VARCHAR);
-- DROP FUNCTION FAKE(VARCHAR, VARCHAR, VARIANT);
-- DROP MASKING POLICY encrypt_pg_v2;
-- DROP MASKING POLICY decrypt_pg_v2;
-- DROP TAG ENCRYPTME_V2;
-- DROP TAG DECRYPTME_V2;


-- =============================================================================
-- APPENDIX: Stage & Export Approach (Alternative)
-- =============================================================================
-- Instead of INSERT...SELECT with UDFs, you can use a masking policy + stage
-- to encrypt data during COPY INTO. This is useful for bulk export workflows.
-- =============================================================================

-- CREATE OR REPLACE FILE FORMAT csv_format_v2
--     TYPE             = CSV
--     FIELD_DELIMITER  = ','
--     NULL_IF          = ('NULL', 'null')
--     SKIP_HEADER      = 1
--     EMPTY_FIELD_AS_NULL = TRUE
--     COMPRESSION      = GZIP;
--
-- CREATE OR REPLACE STAGE unload_stage_v2
--     FILE_FORMAT = csv_format_v2;
--
-- ALTER TAG ENCRYPTME_V2 SET MASKING POLICY encrypt_pg_v2;
-- ALTER TABLE employee_src SET TAG ENCRYPTME_V2 = 'YUP';
--
-- COPY INTO @unload_stage_v2 FROM employee_src HEADER = TRUE;
--
-- ALTER TAG ENCRYPTME_V2 UNSET MASKING POLICY encrypt_pg_v2;
--
-- LIST @unload_stage_v2;
--
-- TRUNCATE employee_enc;
--
-- COPY INTO employee_enc FROM @unload_stage_v2/data_0_0_0.csv.gz;

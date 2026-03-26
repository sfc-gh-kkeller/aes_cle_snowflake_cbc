-- =============================================================================
-- AES-CBC Encryption & Decryption – Session Variable Key Management
-- =============================================================================
-- This worksheet demonstrates:
--   1. Generating fake employee data
--   2. Encrypting data using AES-CBC with ENCRYPT_RAW (random IV per row)
--   3. Decrypting data using DECRYPT_RAW
--   4. Applying encryption/decryption via masking policies & tags
--   5. Staging and loading encrypted data
--   6. Postgres pgcrypto-compatible format: BASE64(iv_raw || ciphertext_raw)
-- =============================================================================


-- =============================================================================
-- STEP 1: Session Configuration
-- =============================================================================

SET aes_cbc_key = 'qg0q8m+kwmjcIIXkhZF2P1krwi+h/ry3CXJhqiZJT6M=';


-- =============================================================================
-- STEP 2: Create Tables
-- =============================================================================

CREATE OR REPLACE TABLE employee (
    emp_id     VARCHAR,
    firstname  VARCHAR,
    lastname   VARCHAR,
    address    VARCHAR,
    postalcode VARCHAR,
    phone      VARCHAR
);

CREATE OR REPLACE TABLE employee_fake2 (
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

CREATE OR REPLACE VIEW fake_data AS
SELECT
    FAKE('en_US', 'ean',            {'length': 8})::VARCHAR AS emp_id,
    FAKE('en_US', 'first_name',     NULL)::VARCHAR          AS firstname,
    FAKE('en_US', 'last_name',      NULL)::VARCHAR          AS lastname,
    FAKE('en_US', 'street_address', NULL)::VARCHAR          AS address,
    FAKE('en_US', 'postalcode',     NULL)::VARCHAR          AS postalcode,
    FAKE('en_US', 'phone_number',   NULL)::VARCHAR          AS phone
FROM TABLE(GENERATOR(ROWCOUNT => 200));

SELECT * FROM fake_data LIMIT 10;

INSERT INTO employee_fake2 SELECT * FROM fake_data;

SELECT * FROM employee_fake2 LIMIT 5;


-- =============================================================================
-- STEP 4: Encryption Function (Random IV)
-- =============================================================================
-- Encrypts plaintext with a random IV each call.
-- Output format: BASE64(iv_raw_16_bytes || ciphertext_raw)
-- Compatible with Postgres pgcrypto.
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
        TO_BINARY(BASE64_ENCODE(inputtext), 'BASE64'),
        BASE64_DECODE_BINARY(key),
        NULL,
        NULL,
        'AES-CBC'
    ) AS enc
)
$$;

SELECT encrypt_cbc_random_iv('test', $aes_cbc_key);
SELECT encrypt_cbc_random_iv('test', $aes_cbc_key);


-- =============================================================================
-- STEP 5: Decryption Function
-- =============================================================================
-- The encrypted string is: BASE64(iv_raw_16_bytes || ciphertext_raw)
-- First 16 bytes of decoded binary = IV, remainder = ciphertext.
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

SELECT decrypt_cbc(encrypt_cbc_random_iv('test', $aes_cbc_key), $aes_cbc_key);
SELECT decrypt_cbc(encrypt_cbc_random_iv('Bonjour', $aes_cbc_key), $aes_cbc_key);


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

SELECT * FROM TABLE(return_cipher_iv(encrypt_cbc_random_iv('test', $aes_cbc_key)));


-- =============================================================================
-- STEP 7: Masking Policy – Encrypt on Read (Tag-Based)
-- =============================================================================

CREATE OR REPLACE MASKING POLICY encrypt_pg
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            encrypt_cbc_random_iv(val, 'qg0q8m+kwmjcIIXkhZF2P1krwi+h/ry3CXJhqiZJT6M=')
        ELSE '** masked **'
    END;

CREATE OR REPLACE TAG ENCRYPTME2;

ALTER TAG ENCRYPTME2 SET MASKING POLICY encrypt_pg;
ALTER TABLE employee_fake2 SET TAG ENCRYPTME2 = 'YUP';

SELECT emp_id FROM employee_fake2 LIMIT 1;

ALTER TAG ENCRYPTME2 UNSET MASKING POLICY encrypt_pg;


-- =============================================================================
-- STEP 8: Masking Policy – Encrypt Column Directly
-- =============================================================================

ALTER TABLE employee_fake2 MODIFY COLUMN firstname SET MASKING POLICY encrypt_pg;

SELECT firstname FROM employee_fake2 LIMIT 5;

ALTER TABLE employee_fake2 MODIFY COLUMN firstname UNSET MASKING POLICY;


-- =============================================================================
-- STEP 9: Stage & Export Encrypted Data
-- =============================================================================

CREATE OR REPLACE FILE FORMAT my_csv_format
    TYPE             = CSV
    FIELD_DELIMITER  = ','
    NULL_IF          = ('NULL', 'null')
    SKIP_HEADER      = 1
    EMPTY_FIELD_AS_NULL = TRUE
    COMPRESSION      = GZIP;

CREATE OR REPLACE STAGE my_unload_stage
    FILE_FORMAT = my_csv_format;

COPY INTO @my_unload_stage FROM employee_fake2 HEADER = TRUE;

LIST @my_unload_stage;

TRUNCATE employee;

COPY INTO employee FROM @my_unload_stage/employee_fake2.csv.gz;

SELECT * FROM employee LIMIT 10;


-- =============================================================================
-- STEP 10: Decryption View
-- =============================================================================

CREATE OR REPLACE VIEW employee_decrypt AS
SELECT
    decrypt_cbc(emp_id,     $aes_cbc_key) AS emp_id,
    decrypt_cbc(firstname,  $aes_cbc_key) AS firstname,
    decrypt_cbc(lastname,   $aes_cbc_key) AS lastname,
    decrypt_cbc(address,    $aes_cbc_key) AS address,
    decrypt_cbc(postalcode, $aes_cbc_key) AS postalcode,
    decrypt_cbc(phone,      $aes_cbc_key) AS phone
FROM employee;

SELECT * FROM employee_decrypt LIMIT 10;


-- =============================================================================
-- STEP 11: Decryption Masking Policy (Decrypt on Read)
-- =============================================================================

CREATE OR REPLACE MASKING POLICY decrypt_pg
    AS (val STRING) RETURNS STRING ->
    CASE
        WHEN IS_ROLE_IN_SESSION('ACCOUNTADMIN') THEN
            decrypt_cbc(val, 'qg0q8m+kwmjcIIXkhZF2P1krwi+h/ry3CXJhqiZJT6M=')
        ELSE '** masked **'
    END;

ALTER TABLE employee MODIFY COLUMN emp_id SET MASKING POLICY decrypt_pg;

SELECT * FROM employee LIMIT 5;

ALTER TABLE employee MODIFY COLUMN emp_id UNSET MASKING POLICY;


-- =============================================================================
-- STEP 12: Quick Verification
-- =============================================================================

SELECT COUNT(*) FROM employee_fake2;
SELECT COUNT(*) FROM employee;


-- =============================================================================
-- STEP 13: Cleanup (Optional)
-- =============================================================================

-- DROP TABLE employee;
-- DROP TABLE employee_fake2;
-- DROP VIEW  employee_decrypt;
-- DROP VIEW  fake_data;
-- DROP FUNCTION encrypt_cbc_random_iv(VARCHAR, VARCHAR);
-- DROP FUNCTION encrypt_cbc_iv(VARCHAR, VARCHAR, VARCHAR);
-- DROP FUNCTION decrypt_cbc(VARCHAR, VARCHAR);
-- DROP FUNCTION return_cipher_iv(VARCHAR);
-- DROP FUNCTION FAKE(VARCHAR, VARCHAR, VARIANT);
-- DROP MASKING POLICY encrypt_pg;
-- DROP MASKING POLICY decrypt_pg;
-- DROP TAG ENCRYPTME2;
-- DROP STAGE my_unload_stage;
-- DROP FILE FORMAT my_csv_format;


-- =============================================================================
-- APPENDIX: Encryption with a Fixed IV
-- =============================================================================
-- Use encrypt_cbc_iv when you need a deterministic IV (e.g. for testing or
-- cross-system compatibility with a known IV). For production, prefer
-- encrypt_cbc_random_iv above.
-- =============================================================================

SET iv_var = '92wwrVOOtcv1SwIV';

CREATE OR REPLACE FUNCTION encrypt_cbc_iv(inputtext VARCHAR, key VARCHAR, iv_in VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
$$
BASE64_ENCODE(
    TO_BINARY(BASE64_ENCODE(iv_in), 'BASE64') ||
    AS_BINARY(GET(
        ENCRYPT_RAW(
            TO_BINARY(BASE64_ENCODE(inputtext), 'BASE64'),
            BASE64_DECODE_BINARY(key),
            TO_BINARY(BASE64_ENCODE(iv_in), 'BASE64'),
            NULL,
            'AES-CBC'
        ),
        'ciphertext'
    ))
)
$$;

SELECT encrypt_cbc_iv('test', $aes_cbc_key, $iv_var);
SELECT encrypt_cbc_iv('+1-860-881-7959x65550', $aes_cbc_key, $iv_var);

SELECT decrypt_cbc(encrypt_cbc_iv('test', $aes_cbc_key, $iv_var), $aes_cbc_key);
SELECT decrypt_cbc(encrypt_cbc_iv('Bonjour', $aes_cbc_key, $iv_var), $aes_cbc_key);

-- Pre-computed Postgres-format ciphertext examples (fixed IV):
-- 'test'    => 'OTJ3d3JWT090Y3YxU3dJVvzaiodnHealhiJFBV6kodw='
-- 'Bonjour' => 'OTJ3d3JWT090Y3YxU3dJVhOgnulA8jRpNPbWT/d29pE='
SELECT decrypt_cbc('OTJ3d3JWT090Y3YxU3dJVvzaiodnHealhiJFBV6kodw=', $aes_cbc_key);
SELECT decrypt_cbc('OTJ3d3JWT090Y3YxU3dJVhOgnulA8jRpNPbWT/d29pE=', $aes_cbc_key);

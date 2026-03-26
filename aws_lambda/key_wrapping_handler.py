"""
AWS Lambda: HYOK Key Wrapping Handler

Returns a KMS-decrypted secret that Snowflake combines with session context
via SHA-256 to derive a per-session wrapped TMK (Tenant Master Key).

Architecture:
  Snowflake → API Gateway → this Lambda → KMS Decrypt → secret returned
  Snowflake then does: SHA256(secret || session_salt) → wrapped AES-256 key

Environment variables:
  KMS_KEY_ARN          - ARN of the KMS key used to decrypt the secret
  ENCRYPTED_SECRET_B64 - Base64-encoded KMS ciphertext blob of the AES secret
  REQUIRED_PASSPHRASE  - Expected passphrase from the caller (optional gate)

The Lambda validates the passphrase, decrypts the secret via KMS, and returns
the raw secret. Snowflake's derive_session_key() UDF handles key wrapping.
"""

import base64
import hashlib
import json
import logging
import os
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

kms_client = boto3.client("kms")

ENCRYPTED_SECRET_B64 = os.environ.get("ENCRYPTED_SECRET_B64", "")
REQUIRED_PASSPHRASE = os.environ.get("REQUIRED_PASSPHRASE", "MY_PASSPHRASE")
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")


def decrypt_secret_from_kms():
    ciphertext_blob = base64.b64decode(ENCRYPTED_SECRET_B64)
    response = kms_client.decrypt(
        CiphertextBlob=ciphertext_blob,
        KeyId=KMS_KEY_ARN,
    )
    return base64.b64encode(response["Plaintext"]).decode("utf-8")


_cached_secret = None


def get_secret():
    global _cached_secret
    if _cached_secret is None:
        _cached_secret = decrypt_secret_from_kms()
    return _cached_secret


def handler(event, context):
    start = time.time()

    sf_user = event.get("headers", {}).get("sf-context-current-user", "unknown")
    sf_account = event.get("headers", {}).get("sf-context-current-account", "unknown")
    sf_query_id = event.get("headers", {}).get(
        "sf-external-function-current-query-id", "unknown"
    )

    try:
        body = json.loads(event.get("body", "{}"))
        rows = body.get("data", [])

        results = []
        for row in rows:
            row_idx = row[0]
            passphrase = row[1] if len(row) > 1 else ""

            if passphrase != REQUIRED_PASSPHRASE:
                results.append([row_idx, "ERROR: invalid passphrase"])
                logger.warning(
                    "Invalid passphrase from user=%s account=%s query=%s",
                    sf_user,
                    sf_account,
                    sf_query_id,
                )
                continue

            secret = get_secret()
            results.append([row_idx, secret])

        elapsed_ms = (time.time() - start) * 1000
        logger.info(
            "hyok_key_fetch user=%s account=%s query=%s rows=%d elapsed_ms=%.1f",
            sf_user,
            sf_account,
            sf_query_id,
            len(rows),
            elapsed_ms,
        )

        return {
            "statusCode": 200,
            "body": json.dumps({"data": results}),
        }

    except Exception as e:
        logger.error("Error: %s", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"data": [[0, f"ERROR: {str(e)}"]]}),
        }


def derive_key_server_side(secret_b64, salt):
    """
    Optional: server-side key derivation if you want the Lambda to return
    the fully wrapped key instead of the raw secret.

    SHA-256(secret || '|' || salt) → 32-byte AES-256 key → Base64

    This matches Snowflake's derive_session_key() UDF.
    """
    raw = secret_b64 + "|" + salt
    derived = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.b64encode(derived).decode("utf-8")

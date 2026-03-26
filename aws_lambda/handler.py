"""
AWS Lambda handler for Snowflake External Function – AES key retrieval from KMS.

This Lambda:
  1. Receives the Snowflake external-function request (batch of rows)
  2. Validates the passphrase sent by the caller
  3. Decrypts the AES-256 data key from KMS using the CMK
  4. Returns the Base64-encoded AES key for each valid row

Environment variables:
  KMS_KEY_ID              – ARN or alias of the KMS CMK
  ENCRYPTED_DATA_KEY_B64  – Base64-encoded ciphertext blob of the data key
  PASSPHRASE              – Expected passphrase (or use Secrets Manager instead)

IAM permissions required:
  kms:Decrypt on the KMS key specified by KMS_KEY_ID

Snowflake sends:
  POST {"data": [[0, "passphrase"], [1, "passphrase"], ...]}

Lambda returns:
  {"data": [[0, "base64-aes-key"], [1, "base64-aes-key"], ...]}
"""

import base64
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

kms_client = boto3.client("kms")

KMS_KEY_ID = os.environ["KMS_KEY_ID"]
ENCRYPTED_DATA_KEY_B64 = os.environ["ENCRYPTED_DATA_KEY_B64"]
EXPECTED_PASSPHRASE = os.environ.get("PASSPHRASE", "")

_cached_plaintext_key: str | None = None


def _get_plaintext_key() -> str:
    global _cached_plaintext_key
    if _cached_plaintext_key is not None:
        return _cached_plaintext_key

    encrypted_blob = base64.b64decode(ENCRYPTED_DATA_KEY_B64)
    response = kms_client.decrypt(
        CiphertextBlob=encrypted_blob,
        KeyId=KMS_KEY_ID,
    )
    _cached_plaintext_key = base64.b64encode(response["Plaintext"]).decode("utf-8")
    return _cached_plaintext_key


def handler(event, context):
    sf_user = event.get("headers", {}).get("sf-context-current-user", "unknown")
    sf_account = event.get("headers", {}).get("sf-context-current-account", "unknown")
    logger.info("Request from user=%s account=%s", sf_user, sf_account)

    try:
        body = json.loads(event.get("body", "{}"))
        rows = body.get("data", [])
    except (json.JSONDecodeError, AttributeError):
        return _error_response(400, "Invalid request body")

    results = []
    for row in rows:
        row_id = row[0]
        passphrase = row[1] if len(row) > 1 else ""

        if passphrase != EXPECTED_PASSPHRASE:
            results.append([row_id, None])
            continue

        try:
            key_b64 = _get_plaintext_key()
            results.append([row_id, key_b64])
        except Exception as exc:
            logger.error("KMS decrypt failed: %s", exc)
            results.append([row_id, None])

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"data": results}),
    }


def _error_response(status_code: int, message: str) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"data": [[0, None]], "error": message}),
    }

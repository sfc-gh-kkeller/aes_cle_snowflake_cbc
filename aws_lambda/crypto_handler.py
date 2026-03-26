"""
AWS Lambda handler for Snowflake External Function – per-column crypto.

This Lambda performs AES-CBC encryption or decryption server-side so that
the AES key NEVER leaves the Lambda execution environment.

Headers sent by Snowflake (configured in the external function definition):
  X-Data-Element  – "name", "address", "phone", etc.
  X-Operation     – "encrypt" or "decrypt"

Environment variables:
  KMS_KEY_ID              – ARN or alias of the KMS CMK
  ENCRYPTED_DATA_KEY_B64  – Base64-encoded ciphertext blob of the data key

Snowflake sends:
  POST {"data": [[0, "plaintext_or_cipher"], [1, "..."], ...]}

Lambda returns:
  {"data": [[0, "cipher_or_plaintext"], [1, "..."], ...]}
"""

import base64
import json
import logging
import os

import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

kms_client = boto3.client("kms")

KMS_KEY_ID = os.environ["KMS_KEY_ID"]
ENCRYPTED_DATA_KEY_B64 = os.environ["ENCRYPTED_DATA_KEY_B64"]

_cached_key_bytes: bytes | None = None

BLOCK_SIZE = 128
IV_LENGTH = 16


def _get_key_bytes() -> bytes:
    global _cached_key_bytes
    if _cached_key_bytes is not None:
        return _cached_key_bytes

    encrypted_blob = base64.b64decode(ENCRYPTED_DATA_KEY_B64)
    response = kms_client.decrypt(
        CiphertextBlob=encrypted_blob,
        KeyId=KMS_KEY_ID,
    )
    _cached_key_bytes = response["Plaintext"]
    return _cached_key_bytes


def _encrypt(plaintext: str, key: bytes) -> str:
    iv = os.urandom(IV_LENGTH)
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode("utf-8")


def _decrypt(ciphertext_b64: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:IV_LENGTH]
    ct = raw[IV_LENGTH:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def handler(event, context):
    headers = event.get("headers", {})
    operation = headers.get("x-operation", headers.get("X-Operation", "encrypt"))
    data_element = headers.get("x-data-element", headers.get("X-Data-Element", "unknown"))

    sf_user = headers.get("sf-context-current-user", "unknown")
    logger.info("op=%s element=%s user=%s", operation, data_element, sf_user)

    try:
        body = json.loads(event.get("body", "{}"))
        rows = body.get("data", [])
    except (json.JSONDecodeError, AttributeError):
        return {"statusCode": 400, "body": json.dumps({"error": "Bad request"})}

    key = _get_key_bytes()
    results = []

    for row in rows:
        row_id = row[0]
        value = row[1] if len(row) > 1 else ""

        try:
            if operation == "encrypt":
                results.append([row_id, _encrypt(value, key)])
            elif operation == "decrypt":
                results.append([row_id, _decrypt(value, key)])
            else:
                results.append([row_id, None])
        except Exception as exc:
            logger.error("Crypto error row=%s: %s", row_id, exc)
            results.append([row_id, None])

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"data": results}),
    }

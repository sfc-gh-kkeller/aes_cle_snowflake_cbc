"""
Azure Function handler for Snowflake External Function – per-column crypto.

Performs AES-CBC encryption/decryption server-side so the key never leaves Azure.

Headers from Snowflake:
  X-Data-Element  – "name", "address", "phone", etc.
  X-Operation     – "encrypt" or "decrypt"

Environment variables:
  KEY_VAULT_URL   – e.g. https://my-keyvault.vault.azure.net
  SECRET_NAME     – name of the secret holding the Base64 AES key
"""

import base64
import json
import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

logger = logging.getLogger(__name__)

KEY_VAULT_URL = os.environ["KEY_VAULT_URL"]
SECRET_NAME = os.environ["SECRET_NAME"]

credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

_cached_key_bytes: bytes | None = None

BLOCK_SIZE = 128
IV_LENGTH = 16


def _get_key_bytes() -> bytes:
    global _cached_key_bytes
    if _cached_key_bytes is not None:
        return _cached_key_bytes
    secret = secret_client.get_secret(SECRET_NAME)
    _cached_key_bytes = base64.b64decode(secret.value)
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


app = func.FunctionApp()


@app.function_name("CryptoHandler")
@app.route(route="crypto", methods=["POST"])
def crypto_handler(req: func.HttpRequest) -> func.HttpResponse:
    operation = req.headers.get("x-operation", "encrypt")
    data_element = req.headers.get("x-data-element", "unknown")
    sf_user = req.headers.get("sf-context-current-user", "unknown")
    logger.info("op=%s element=%s user=%s", operation, data_element, sf_user)

    try:
        body = req.get_json()
        rows = body.get("data", [])
    except (ValueError, AttributeError):
        return func.HttpResponse(
            json.dumps({"error": "Bad request"}),
            status_code=400,
            mimetype="application/json",
        )

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

    return func.HttpResponse(
        json.dumps({"data": results}),
        status_code=200,
        mimetype="application/json",
    )

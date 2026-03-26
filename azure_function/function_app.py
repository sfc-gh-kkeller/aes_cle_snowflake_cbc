"""
Azure Function handler for Snowflake External Function – AES key from Key Vault.

This function:
  1. Receives the Snowflake external-function request (batch of rows)
  2. Validates the passphrase
  3. Fetches the AES-256 key from Azure Key Vault using managed identity
  4. Returns the Base64-encoded key for each valid row

Environment variables / App Settings:
  KEY_VAULT_URL   – e.g. https://my-keyvault.vault.azure.net
  SECRET_NAME     – name of the secret holding the Base64 AES key
  PASSPHRASE      – expected passphrase (or use Key Vault for this too)

Azure RBAC required:
  Key Vault Secrets User on the specified vault (for the Function's managed identity)

Snowflake sends (via API Management):
  POST {"data": [[0, "passphrase"], [1, "passphrase"], ...]}

Function returns:
  {"data": [[0, "base64-aes-key"], [1, "base64-aes-key"], ...]}
"""

import json
import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)

KEY_VAULT_URL = os.environ["KEY_VAULT_URL"]
SECRET_NAME = os.environ["SECRET_NAME"]
EXPECTED_PASSPHRASE = os.environ.get("PASSPHRASE", "")

credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

_cached_key: str | None = None


def _get_key() -> str:
    global _cached_key
    if _cached_key is not None:
        return _cached_key
    secret = secret_client.get_secret(SECRET_NAME)
    _cached_key = secret.value
    return _cached_key


app = func.FunctionApp()


@app.function_name("GetAesKey")
@app.route(route="get-aes-key", methods=["POST"])
def get_aes_key(req: func.HttpRequest) -> func.HttpResponse:
    sf_user = req.headers.get("sf-context-current-user", "unknown")
    sf_account = req.headers.get("sf-context-current-account", "unknown")
    logger.info("Request from user=%s account=%s", sf_user, sf_account)

    try:
        body = req.get_json()
        rows = body.get("data", [])
    except (ValueError, AttributeError):
        return func.HttpResponse(
            json.dumps({"error": "Invalid request body"}),
            status_code=400,
            mimetype="application/json",
        )

    results = []
    for row in rows:
        row_id = row[0]
        passphrase = row[1] if len(row) > 1 else ""

        if passphrase != EXPECTED_PASSPHRASE:
            results.append([row_id, None])
            continue

        try:
            results.append([row_id, _get_key()])
        except Exception as exc:
            logger.error("Key Vault fetch failed: %s", exc)
            results.append([row_id, None])

    return func.HttpResponse(
        json.dumps({"data": results}),
        status_code=200,
        mimetype="application/json",
    )

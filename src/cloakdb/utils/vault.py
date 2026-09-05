"""Pluggable KMS and Secret Vault Providers for enterprise key management."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any


class SecretProvider(ABC):
    """Abstract base class for external cryptographic secret and salt retrieval."""

    @abstractmethod
    def get_secret(self, key_id: str, **kwargs: Any) -> str:
        """Retrieves plaintext secret string by key or path identifier."""
        raise NotImplementedError


class EnvSecretProvider(SecretProvider):
    """Retrieves secrets from environment variables with fallback support."""

    def __init__(self, default_env_var: str = "SECRET_SALT"):
        self.default_env_var = default_env_var

    def get_secret(self, key_id: str | None = None, **kwargs: Any) -> str:
        env_var = key_id or self.default_env_var
        val = os.getenv(env_var)
        if not val:
            fallback = kwargs.get("default")
            if fallback:
                return str(fallback)
            raise ValueError(
                f"Secret environment variable '{env_var}' is not set. "
                "Ensure you configure your cryptographic salt in your environment."
            )
        return val


class VaultSecretProvider(SecretProvider):
    """Retrieves secrets from HashiCorp Vault KV v2 secret engine."""

    def __init__(
        self,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        mount_point: str = "secret",
    ):
        self.vault_addr: str = vault_addr or os.getenv("VAULT_ADDR") or "http://127.0.0.1:8200"
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN", "")
        self.mount_point = mount_point

    def get_secret(self, key_id: str, secret_key: str = "salt", **kwargs: Any) -> str:
        """Fetches secret from Vault KV v2 endpoint at mount_point/data/{key_id}."""
        if not self.vault_token:
            raise ValueError(
                "VAULT_TOKEN must be configured to fetch secrets from HashiCorp Vault."
            )

        import json
        import urllib.error
        import urllib.request

        url = f"{self.vault_addr.rstrip('/')}/v1/{self.mount_point}/data/{key_id}"
        req = urllib.request.Request(
            url,
            headers={
                "X-Vault-Token": self.vault_token,
                "Content-Type": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                secret_data = data.get("data", {}).get("data", {})
                if secret_key not in secret_data:
                    raise KeyError(f"Key '{secret_key}' not found in Vault secret '{key_id}'.")
                return str(secret_data[secret_key])
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to connect to Vault at {self.vault_addr}: {e}") from e


class AwsKmsSecretProvider(SecretProvider):
    """Decrypts ciphertext keys using AWS KMS Decrypt API."""

    def __init__(self, region_name: str | None = None):
        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def get_secret(self, key_id: str, ciphertext_b64: str | None = None, **kwargs: Any) -> str:
        """Decrypts a base64-encoded ciphertext blob using AWS KMS."""
        try:
            import base64

            import boto3

            client = boto3.client("kms", region_name=self.region_name)
            raw_cipher = base64.b64decode(ciphertext_b64 or key_id)
            resp = client.decrypt(CiphertextBlob=raw_cipher)
            return str(resp["Plaintext"].decode("utf-8"))
        except ImportError as e:
            raise RuntimeError(
                "boto3 is required for AWS KMS secret retrieval. Install with `pip install boto3`."
            ) from e


def get_secret_provider(provider_type: str = "env", **kwargs: Any) -> SecretProvider:
    """Factory function resolving SecretProvider implementations."""
    p_type = provider_type.lower().strip()
    if p_type in ("env", "environment"):
        return EnvSecretProvider(**kwargs)
    elif p_type in ("vault", "hashicorp"):
        return VaultSecretProvider(**kwargs)
    elif p_type in ("kms", "aws_kms", "aws"):
        return AwsKmsSecretProvider(**kwargs)
    else:
        raise ValueError(
            f"Unsupported secret provider type: '{provider_type}'. Supported: 'env', 'vault', 'kms'."
        )

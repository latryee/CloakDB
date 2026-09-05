"""Tests for KMS and Secret Vault Providers."""

from __future__ import annotations

import pytest

from cloakdb.utils.vault import (
    AwsKmsSecretProvider,
    EnvSecretProvider,
    VaultSecretProvider,
    get_secret_provider,
)


def test_env_secret_provider(monkeypatch):
    """Test retrieving secret from environment variable and fallback."""
    monkeypatch.setenv("TEST_SALT_VAR", "super_secret_salt_value_1234567890")
    provider = EnvSecretProvider(default_env_var="TEST_SALT_VAR")

    assert provider.get_secret() == "super_secret_salt_value_1234567890"

    # Test fallback
    monkeypatch.delenv("TEST_SALT_VAR", raising=False)
    assert provider.get_secret(default="fallback_salt") == "fallback_salt"

    # Test missing raises ValueError
    with pytest.raises(ValueError, match="Secret environment variable 'TEST_SALT_VAR' is not set"):
        provider.get_secret()


def test_vault_provider_missing_token():
    """Test VaultSecretProvider raises ValueError when token is missing."""
    provider = VaultSecretProvider(vault_token="")
    with pytest.raises(ValueError, match="VAULT_TOKEN must be configured"):
        provider.get_secret("my-secret")


def test_get_secret_provider_factory():
    """Test factory resolution of providers."""
    p_env = get_secret_provider("env")
    assert isinstance(p_env, EnvSecretProvider)

    p_vault = get_secret_provider("vault", vault_token="test_token")
    assert isinstance(p_vault, VaultSecretProvider)

    p_kms = get_secret_provider("kms")
    assert isinstance(p_kms, AwsKmsSecretProvider)

    with pytest.raises(ValueError, match="Unsupported secret provider"):
        get_secret_provider("unsupported_provider")

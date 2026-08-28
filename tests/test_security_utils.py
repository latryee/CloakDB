"""Unit tests for security utility functions including database connection URL redaction."""

from __future__ import annotations

from cloakdb.utils.security import redact_connection_url


def test_redact_connection_url_with_password():
    url = "postgresql://dbuser:s3cr3t_p@ss!@localhost:5432/production_db"
    redacted = redact_connection_url(url)
    assert "s3cr3t_p@ss!" not in redacted
    assert redacted == "postgresql://dbuser:***@localhost:5432/production_db"


def test_redact_connection_url_without_password():
    url = "postgresql://readonly_user@localhost:5432/analytics_db"
    assert redact_connection_url(url) == "postgresql://readonly_user@localhost:5432/analytics_db"

    url_host_only = "postgresql://localhost:5432/mydb"
    assert redact_connection_url(url_host_only) == "postgresql://localhost:5432/mydb"


def test_redact_connection_url_with_query_string():
    url = "mysql+pymysql://admin:supersecret@10.0.1.25:3306/crm?ssl_ca=/etc/ssl/cert.pem&connect_timeout=10"
    redacted = redact_connection_url(url)
    assert "supersecret" not in redacted
    assert (
        redacted
        == "mysql+pymysql://admin:***@10.0.1.25:3306/crm?ssl_ca=/etc/ssl/cert.pem&connect_timeout=10"
    )


def test_redact_connection_url_file_path():
    assert redact_connection_url("dump.sql") == "dump.sql"
    assert redact_connection_url("/var/data/customers.csv") == "/var/data/customers.csv"
    assert (
        redact_connection_url("C:\\Users\\Lati\\Desktop\\dump.sql")
        == "C:\\Users\\Lati\\Desktop\\dump.sql"
    )
    assert redact_connection_url("sqlite:///local_cache.db") == "sqlite:///local_cache.db"

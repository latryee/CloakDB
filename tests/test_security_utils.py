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


def test_redact_connection_url_with_url_encoded_characters():
    # Password containing %40 for '@'
    url1 = "postgresql://dbuser:p%40ssword123@localhost:5432/production_db"
    redacted1 = redact_connection_url(url1)
    assert "p%40ssword123" not in redacted1
    assert redacted1 == "postgresql://dbuser:***@localhost:5432/production_db"

    # Password containing %3A (':'), %2F ('/'), %23 ('#'), %3F ('?'), %26 ('&'), %25 ('%')
    url2 = "mysql://admin:p%3A%2F%23%3F%26%25secret@db.internal:3306/crm?ssl=true"
    redacted2 = redact_connection_url(url2)
    assert "p%3A%2F%23%3F%26%25secret" not in redacted2
    assert redacted2 == "mysql://admin:***@db.internal:3306/crm?ssl=true"

    # Both username and password containing URL-encoded characters (e.g. user%40corp.org:p%40ss%3Awd)
    url3 = "postgresql://user%40corp.org:p%40ss%3Awd@db-cluster.aws:5432/prod"
    redacted3 = redact_connection_url(url3)
    assert "p%40ss%3Awd" not in redacted3
    assert redacted3 == "postgresql://user%40corp.org:***@db-cluster.aws:5432/prod"

    # MSSQL ODBC URL with encoded password and complex connection parameters
    url4 = "mssql+pyodbc://sa:P%40ssw0rd!@10.0.0.5:1433/sales?driver=ODBC+Driver+17+for+SQL+Server"
    redacted4 = redact_connection_url(url4)
    assert "P%40ssw0rd!" not in redacted4
    assert (
        redacted4
        == "mssql+pyodbc://sa:***@10.0.0.5:1433/sales?driver=ODBC+Driver+17+for+SQL+Server"
    )


def test_hkdf_derive_key_and_keyed_mac():
    from cloakdb.utils.security import hkdf_derive_key, keyed_mac_hash

    salt = "secret-salt-1234567890123456789012"
    key1 = hkdf_derive_key(salt, info="users.email", length=32)
    key2 = hkdf_derive_key(salt, info="users.email", length=32)
    assert len(key1) == 32
    assert key1 == key2

    key_diff = hkdf_derive_key(salt, info="orders.id", length=32)
    assert key_diff != key1

    mac = keyed_mac_hash(key1, "sensitive payload")
    assert isinstance(mac, str) and len(mac) == 64


def test_zeroize_memory():
    from cloakdb.utils.security import zeroize_memory

    # Bytearray zeroization
    b = bytearray(b"super_secret_key_material")
    assert zeroize_memory(b) is True
    assert all(byte == 0 for byte in b)

    # Dict zeroization
    d = {"key": bytearray(b"secret"), "val": 123}
    assert zeroize_memory(d) is True
    assert len(d) == 0

    # List zeroization
    lst = [1, 2, 3]
    assert zeroize_memory(lst) is True
    assert len(lst) == 0

    # None target
    assert zeroize_memory(None) is True

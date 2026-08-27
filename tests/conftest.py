"""Pytest fixtures, sample database dumps, and mock data."""

import pytest
from pathlib import Path

SAMPLE_POSTGRES_DUMP = """
-- PostgreSQL database dump
-- Dumped from database version 15.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';

CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    full_name character varying(255),
    phone character varying(50),
    credit_card character varying(30),
    salary numeric(10,2),
    created_at timestamp without time zone DEFAULT now()
);

COPY public.users (id, email, full_name, phone, credit_card, salary, created_at) FROM stdin;
1\tjohn.doe@example.com\tJohn Doe\t+1-555-0199\t4532015012345678\t85000.00\t2023-01-15 10:00:00
2\talice.smith@company.org\tAlice Smith\t+1-555-0142\t5425233430109823\t92000.50\t2023-02-20 14:30:00
3\tbob.wilson@domain.net\tBob Wilson\t+1-555-0188\t378282246310005\t78000.00\t2023-03-05 09:15:00
4\t\\N\t\\N\t\\N\t\\N\t\\N\t2023-04-01 00:00:00
\\.

CREATE TABLE public.orders (
    id integer NOT NULL,
    user_id integer NOT NULL,
    order_total numeric(10,2),
    shipping_address text
);

INSERT INTO public.orders (id, user_id, order_total, shipping_address) VALUES 
(101, 1, 149.99, '742 Evergreen Terrace, Springfield'),
(102, 2, 299.50, '221B Baker Street, London'),
(103, 1, 49.00, '742 Evergreen Terrace, Springfield');
"""

SAMPLE_MYSQL_DUMP = """
-- MySQL dump 10.13  Distrib 8.0.32
CREATE TABLE `customers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `ssn` varchar(20) DEFAULT NULL,
  `secret_token` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `customers` (`id`, `email`, `ssn`, `secret_token`) VALUES 
(1, 'customer1@test.com', '123-45-6789', 'secret_abc_123'),
(2, 'customer2@test.com', '987-65-4321', 'secret_xyz_789');
"""

SAMPLE_CSV = """id,email,full_name,salary,phone
1,john.doe@example.com,John Doe,85000,+1-555-0199
2,alice.smith@company.org,Alice Smith,92000,+1-555-0142
3,bob.wilson@domain.net,Bob Wilson,78000,+1-555-0188
"""


@pytest.fixture
def postgres_dump_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample_postgres.sql"
    f.write_text(SAMPLE_POSTGRES_DUMP, encoding="utf-8")
    return f


@pytest.fixture
def mysql_dump_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample_mysql.sql"
    f.write_text(SAMPLE_MYSQL_DUMP, encoding="utf-8")
    return f


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample_users.csv"
    f.write_text(SAMPLE_CSV, encoding="utf-8")
    return f

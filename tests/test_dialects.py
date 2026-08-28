"""Tests for extended SQL dialect parsing (T-SQL and Oracle)."""

import io

from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.sql_dump import SQLDumpStreamParser


def test_tsql_bracket_syntax_and_nstrings():
    tsql_dump = """
USE [MasterDB];
GO
SET IDENTITY_INSERT [dbo].[Customers] ON;
GO

INSERT INTO [dbo].[Customers] ([CustomerID], [Email], [FullName], [SecretNote]) VALUES
(1001, N'bruce@wayne.com', N'Bruce Wayne', N'Batman identity'),
(1002, N'clark@dailyplanet.com', N'Clark Kent', N'Superman identity');

SET IDENTITY_INSERT [dbo].[Customers] OFF;
GO
"""

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="dialect-test-salt"),
        tables={
            "Customers": TableRule(
                columns={
                    "Email": ColumnRule(
                        strategy="constant", params={"value_to_set": "masked@domain.com"}
                    ),
                    "SecretNote": ColumnRule(strategy="nullify"),
                }
            )
        },
    )

    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(tsql_dump)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    assert "USE [MasterDB];" in output
    assert "SET IDENTITY_INSERT [dbo].[Customers] ON;" in output
    assert "GO" in output
    assert "bruce@wayne.com" not in output
    assert "clark@dailyplanet.com" not in output
    assert "'masked@domain.com'" in output
    assert "NULL" in output


def test_oracle_sql_dump_syntax():
    oracle_dump = """
REM  Script: HR Schema Export
PROMPT Creating Table EMPLOYEES
SET DEFINE OFF;

INSERT INTO "HR"."EMPLOYEES" ("EMPLOYEE_ID", "EMAIL", "SALARY") VALUES (101, 'john.doe@oracle.com', 85000);
INSERT INTO "HR"."EMPLOYEES" ("EMPLOYEE_ID", "EMAIL", "SALARY") VALUES (102, 'jane.smith@oracle.com', 95000);

COMMIT;
"""

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="dialect-test-salt"),
        tables={
            "EMPLOYEES": TableRule(
                columns={
                    "EMAIL": ColumnRule(
                        strategy="constant", params={"value_to_set": "anon@oracle.com"}
                    ),
                    "SALARY": ColumnRule(strategy="constant", params={"value_to_set": 0}),
                }
            )
        },
    )

    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(oracle_dump)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    assert "REM  Script: HR Schema Export" in output
    assert "PROMPT Creating Table EMPLOYEES" in output
    assert "SET DEFINE OFF;" in output
    assert "COMMIT;" in output
    assert "john.doe@oracle.com" not in output
    assert "'anon@oracle.com'" in output
    assert "(101, 'anon@oracle.com', 0)" in output

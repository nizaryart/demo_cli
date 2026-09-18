import os
import sqlite3
import pytest

from demo_cli.preview import _extract_sql, _preview_queries, preview, preview_sqlite
from demo_cli.targets import Target


def test_extract_sql_bare_queries():
    assert _extract_sql("DELETE FROM users WHERE id < 10") == "DELETE FROM users WHERE id < 10"
    assert _extract_sql("UPDATE users SET name = 'bob'") == "UPDATE users SET name = 'bob'"
    assert _extract_sql("TRUNCATE TABLE logs") == "TRUNCATE TABLE logs"


def test_extract_sql_cli_wrappers():
    assert _extract_sql('sqlite3 app.db "DELETE FROM users WHERE id < 10"') == "DELETE FROM users WHERE id < 10"
    assert _extract_sql("sqlite3 -batch app.db 'UPDATE users SET active = 0'") == "UPDATE users SET active = 0"
    assert _extract_sql('psql postgres://localhost/db -c "DELETE FROM orders"') == "DELETE FROM orders"
    assert _extract_sql('psql -c "DELETE FROM orders" postgres://localhost/db') == "DELETE FROM orders"


def test_preview_queries_generation():
    count_q, prev_q = _preview_queries("DELETE FROM users WHERE id < 10")
    assert count_q == "SELECT COUNT(*) FROM users WHERE id < 10"
    assert prev_q == "SELECT * FROM users WHERE id < 10 LIMIT 5"

    count_q, prev_q = _preview_queries("sqlite3 app.db 'DELETE FROM \"public.users\" WHERE id = 1;'")
    assert count_q == 'SELECT COUNT(*) FROM "public.users" WHERE id = 1'
    assert prev_q == 'SELECT * FROM "public.users" WHERE id = 1 LIMIT 5'

    count_q, prev_q = _preview_queries("psql $URL -c 'TRUNCATE TABLE logs;'")
    assert count_q == "SELECT COUNT(*) FROM logs"
    assert prev_q == "SELECT * FROM logs LIMIT 5"

    assert _preview_queries("SELECT * FROM users") == (None, None)
    assert _preview_queries("echo hello world") == (None, None)


@pytest.fixture
def test_db(tmp_path):
    db_path = str(tmp_path / "app.db")
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    users = [(1, "Alice", "admin"), (2, "Bob", "user"), (3, "Charlie", "user"), (4, "Diana", "user")]
    con.executemany("INSERT INTO users VALUES (?, ?, ?)", users)
    con.commit()
    con.close()
    return db_path


def test_preview_sqlite_execution(test_db):
    target = Target("sqlite", test_db, test_db)

    # 1. Bare SQL
    count, rows, cols = preview("DELETE FROM users WHERE id <= 2", target)
    assert count == 2
    assert cols == ["id", "name", "role"]
    assert len(rows) == 2
    assert rows[0] == (1, "Alice", "admin")

    # 2. CLI wrapper
    cli_cmd = f'sqlite3 {test_db} "DELETE FROM users WHERE role = \'user\'"'
    count, rows, cols = preview(cli_cmd, target)
    assert count == 3
    assert cols == ["id", "name", "role"]
    assert len(rows) == 3

    # 3. CLI update
    cli_update = f"sqlite3 {test_db} 'UPDATE users SET name = \"anon\" WHERE id = 1'"
    count, rows, cols = preview(cli_update, target)
    assert count == 1
    assert cols == ["id", "name", "role"]
    assert len(rows) == 1

    # 4. Target None returns empty tuple
    assert preview("DELETE FROM users", None) == (None, [], [])


import os
import sqlite3
import pytest

from demo_cli.diff import (
    _hash_file,
    _sqlite_tables,
    _sqlite_rows,
    diff_sqlite,
    diff_file,
    diff_dir,
    DiffLine,
)


def test_hash_file_streaming(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 131072)  # 128 KB
    h = _hash_file(str(f))
    import hashlib
    expected = hashlib.sha256(b"A" * 131072).hexdigest()
    assert h == expected
    assert _hash_file(str(tmp_path / "non_existent.txt")) == "unreadable"


def test_diff_file_identical(tmp_path):
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f1.write_text("hello world\n")
    f2.write_text("hello world\n")
    res = diff_file(str(f1), str(f2))
    assert len(res) == 1
    assert res[0].text == "File is unchanged."
    assert res[0].tone == "info"


def test_diff_file_text_modified(tmp_path):
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f1.write_text("line 1\nline 2\n")
    f2.write_text("line 1\nline 2 modified\n")
    res = diff_file(str(f1), str(f2))
    tones = [r.tone for r in res]
    assert "add" in tones
    assert "del" in tones


def test_diff_file_binary_modified(tmp_path):
    f1 = tmp_path / "b1.bin"
    f2 = tmp_path / "b2.bin"
    f1.write_bytes(b"\x00\x01\x02\xff")
    f2.write_bytes(b"\x00\x01\x03\xff")
    res = diff_file(str(f1), str(f2))
    texts = [r.text for r in res]
    assert any("Binary file changed." in t for t in texts)


def test_diff_sqlite_quoted_tables(tmp_path):
    db1 = str(tmp_path / "db1.sqlite")
    db2 = str(tmp_path / "db2.sqlite")

    # DB1 has special table name with spaces
    con1 = sqlite3.connect(db1)
    con1.execute('CREATE TABLE "order details" (id INT, item TEXT)')
    con1.execute('INSERT INTO "order details" VALUES (1, "apples")')
    con1.execute('INSERT INTO "order details" VALUES (2, "oranges")')
    con1.commit()
    con1.close()

    # DB2 has updated item and dropped one
    con2 = sqlite3.connect(db2)
    con2.execute('CREATE TABLE "order details" (id INT, item TEXT)')
    con2.execute('INSERT INTO "order details" VALUES (1, "apples")')
    con2.execute('INSERT INTO "order details" VALUES (3, "bananas")')
    con2.commit()
    con2.close()

    res = diff_sqlite(db1, db2)
    texts = [r.text for r in res]
    assert any("-1 +1 rows" in t for t in texts)
    assert any("oranges" in t for t in texts)
    assert any("bananas" in t for t in texts)


def test_diff_dir_changes(tmp_path):
    d1 = tmp_path / "snap"
    d2 = tmp_path / "current"
    d1.mkdir()
    d2.mkdir()

    (d1 / "kept.txt").write_text("same")
    (d2 / "kept.txt").write_text("same")

    (d1 / "deleted.txt").write_text("del")

    (d2 / "added.txt").write_text("new")

    res = diff_dir(str(d1), str(d2))
    texts = [r.text for r in res]
    assert "added.txt: added" in texts
    assert "deleted.txt: deleted" in texts


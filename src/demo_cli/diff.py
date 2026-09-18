"""Diff a target against its latest recovery point: what actually changed.

Returns a list of typed `DiffLine`s so the renderer can colour them; the diff
logic itself stays presentation-free and testable.
"""
from __future__ import annotations

import difflib
import hashlib
import os
import sqlite3
from dataclasses import dataclass
from typing import List

from . import recovery

# tone: "add" | "del" | "mod" | "meta" | "info"


@dataclass
class DiffLine:
    text: str
    tone: str = "info"


def _info(t):
    return DiffLine(t, "info")


def _hash_file(path: str) -> str:
    """Compute SHA256 of path by streaming in chunks, avoiding RAM exhaustion and descriptor leaks."""
    try:
        with open(path, "rb") as f:
            if hasattr(hashlib, "file_digest"):
                return hashlib.file_digest(f, "sha256").hexdigest()
            h = hashlib.sha256()
            while chunk := f.read(65536):
                h.update(chunk)
            return h.hexdigest()
    except Exception:
        return "unreadable"


# ---- sqlite ----

def _sqlite_tables(path: str) -> List[str]:
    con = sqlite3.connect(path)
    try:
        return [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    finally:
        con.close()


def _sqlite_rows(path: str, table: str, max_rows: int = 50000):
    con = sqlite3.connect(path)
    try:
        safe_table = table.replace('"', '""')
        cur = con.execute(f'SELECT * FROM "{safe_table}" LIMIT {max_rows}')
        rows = [tuple(r) for r in cur.fetchall()]
    finally:
        con.close()
    return rows


def diff_sqlite(before: str, after: str, limit: int = 8) -> List[DiffLine]:
    out: List[DiffLine] = []
    try:
        tb, ta = set(_sqlite_tables(before)), set(_sqlite_tables(after))
    except Exception:
        return [DiffLine("Could not open one of the databases for diff.", "del")]
    for t in sorted(ta - tb):
        out.append(DiffLine(f"{t}: table created", "add"))
    for t in sorted(tb - ta):
        out.append(DiffLine(f"{t}: table dropped", "del"))
    for t in sorted(tb & ta):
        try:
            rb, ra = _sqlite_rows(before, t), _sqlite_rows(after, t)
        except Exception:
            continue
        sb, sa = set(rb), set(ra)
        removed = [r for r in rb if r not in sa]
        added = [r for r in ra if r not in sb]
        if not removed and not added:
            continue
        out.append(DiffLine(f"{t}: -{len(removed)} +{len(added)} rows", "mod"))
        for r in removed[:limit]:
            out.append(DiffLine("    - " + " | ".join(str(x) for x in r), "del"))
        for r in added[:limit]:
            out.append(DiffLine("    + " + " | ".join(str(x) for x in r), "add"))
    if not out:
        out.append(DiffLine("No row-level changes detected.", "info"))
    return out


# ---- dir / file ----

def _manifest(root: str):
    manifest = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # The shared constant, not a fourth copy of it. IGNORED_DIRS' own
        # comment: "Three separate copies had already drifted apart before
        # this was unified; adding an entry must fix every platform at once."
        # This was the fourth. No behaviour change today - the names were
        # identical - which is precisely why it would have drifted unnoticed.
        dirnames[:] = [d for d in dirnames if d not in recovery.IGNORED_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            manifest[rel] = _hash_file(full)
    return manifest


def _text_diff(before_path: str, after_path: str, rel: str) -> List[DiffLine]:
    try:
        with open(before_path, encoding="utf-8") as f:
            a = f.read().splitlines()
        with open(after_path, encoding="utf-8") as f:
            b = f.read().splitlines()
    except Exception:
        return []
    out: List[DiffLine] = []
    for ln in difflib.unified_diff(a, b, fromfile="before/" + rel, tofile="after/" + rel, lineterm=""):
        if ln.startswith("+") and not ln.startswith("+++"):
            out.append(DiffLine("    " + ln, "add"))
        elif ln.startswith("-") and not ln.startswith("---"):
            out.append(DiffLine("    " + ln, "del"))
        elif ln.startswith("@@"):
            out.append(DiffLine("    " + ln, "meta"))
    return out[:40]


def diff_dir(snap: str, current: str) -> List[DiffLine]:
    before, after = _manifest(snap), _manifest(current)
    out: List[DiffLine] = []
    for k in sorted(set(after) - set(before)):
        out.append(DiffLine(f"{k}: added", "add"))
    for k in sorted(set(before) - set(after)):
        out.append(DiffLine(f"{k}: deleted", "del"))
    for k in sorted(k for k in set(before) & set(after) if before[k] != after[k]):
        out.append(DiffLine(f"{k}: modified", "mod"))
        out += _text_diff(os.path.join(snap, k), os.path.join(current, k), k)
    if not out:
        out.append(DiffLine("No file changes detected.", "info"))
    return out


def diff_file(snap: str, current: str) -> List[DiffLine]:
    if not os.path.exists(snap) or not os.path.exists(current):
        return [DiffLine("Missing file for diff.", "del")]
    out = _text_diff(snap, current, os.path.basename(current))
    if out:
        return out
    h1 = _hash_file(snap)
    h2 = _hash_file(current)
    if h1 == h2:
        return [DiffLine("File is unchanged.", "info")]
    if h1 == "unreadable" or h2 == "unreadable":
        return [DiffLine("File unreadable for diff.", "del")]
    return [DiffLine(f"before sha256 {h1[:16]}", "meta"),
            DiffLine(f"after  sha256 {h2[:16]}", "meta"),
            DiffLine("Binary file changed.", "mod")]


def diff_entry(entry: dict) -> List[DiffLine]:
    kind = entry.get("kind", "sqlite")
    rp, target = entry["recovery_point"], entry["target"]
    if kind == "sqlite":
        return diff_sqlite(rp, target)
    if kind == "dir":
        return diff_dir(rp, target)
    if kind == "file":
        return diff_file(rp, target)
    if kind == "postgres":
        return [DiffLine("Postgres diff compares dumps; restore into a scratch DB to inspect rows.", "info"),
                DiffLine(f"dump {os.path.basename(rp)}", "meta")]
    return [DiffLine("Unsupported target kind for diff.", "del")]

r"""last_hash reads the tail, not the whole ledger.

The chain's head is read once per append, and it used to be read by scanning
the entire file line by line - so appending n receipts cost O(n^2), and the
cost landed in the PRE-EXECUTION path, where the user waits for it. Measured
on a real 888-byte receipt line (2026-09-10):

     entries      file    last_hash    append_receipt
         100    0.1 MB      0.62 ms           5.66 ms
      10,000    8.6 MB        83 ms             86 ms
      50,000     43 MB       459 ms            541 ms

No receipt was ever wrong; this was never a correctness fault. But a guard
that gets slower the longer you have trusted it is a guard people turn off.

_tail_hash had the identical contract and was flat at ~0.15 ms across every
one of those sizes. It was written for the PEER chain during the 2026-09-09
review, for this exact reason, and nobody pointed the main chain at it.

These tests are in two halves. The first proves the two agree on every input
where they could plausibly disagree - a chain link that is silently GENESIS
is a BROKEN CHAIN, so equivalence is the safety property. The second proves
the cost is actually bounded, without timing anything.
"""
import inspect
import json
import os

import pytest

from demo_cli import receipts as R


def _write(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(r if isinstance(r, str) else json.dumps(r))
            f.write("\n")


def _row(h, pad=0):
    return {"receipt_hash": h, "receipt_id": h[:8], "action_raw": "x" * pad}


# ------------------------------------------------- the two must agree

def test_the_same_answer_on_an_ordinary_ledger(tmp_path):
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}") for i in range(20)])
    assert R.last_hash(str(p)) == f"{19:064x}"
    assert R.last_hash(str(p)) == R._tail_hash(str(p))


def test_a_missing_file_is_genesis(tmp_path):
    p = str(tmp_path / "nope.jsonl")
    assert R.last_hash(p) == R.GENESIS == R._tail_hash(p)


def test_an_empty_file_is_genesis(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text("", encoding="utf-8")
    assert R.last_hash(str(p)) == R.GENESIS == R._tail_hash(str(p))


def test_a_torn_last_line_falls_back_to_the_one_before(tmp_path):
    """A write interrupted before its newline. The chain must link to the
    last GOOD receipt, not to GENESIS - which would read as "the chain
    started here" and silently sever it."""
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}") for i in range(5)])
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"receipt_hash": "aaaa", "act')
    assert R.last_hash(str(p)) == f"{4:064x}"
    assert R.last_hash(str(p)) == R._tail_hash(str(p))


def test_many_torn_lines_still_find_the_last_good_one(tmp_path):
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}") for i in range(3)]
           + ["{broken" + "x" * 200] * 400)
    assert R.last_hash(str(p)) == f"{2:064x}"


def test_blank_lines_are_skipped(tmp_path):
    p = tmp_path / "r.jsonl"
    _write(p, [_row("a" * 64), "", "   ", ""])
    assert R.last_hash(str(p)) == "a" * 64


def test_a_file_of_nothing_but_garbage_is_genesis(tmp_path):
    """GENESIS means the file holds no parseable receipt, and nothing else."""
    p = tmp_path / "r.jsonl"
    _write(p, ["not json"] * 50)
    assert R.last_hash(str(p)) == R.GENESIS


def test_a_last_line_larger_than_the_window_is_still_found(tmp_path):
    """The window is 64 KB. A receipt whose action_raw runs past that is not
    hypothetical - redact() does not truncate - and a fixed window returned
    GENESIS for it, which is the bug the widening loop was added for."""
    p = tmp_path / "r.jsonl"
    _write(p, [_row("b" * 64, pad=100_000)])   # one line past the window
    assert R.last_hash(str(p)) == "b" * 64


def test_a_good_line_buried_under_megabytes_of_torn_ones(tmp_path):
    """Widening has to keep going until it finds one or reaches the start.
    Stopping early would report GENESIS and break the chain."""
    p = tmp_path / "r.jsonl"
    # still comfortably past the 64 KB window, at ~900 KB rather than 2.7 MB
    _write(p, [_row("c" * 64)] + ["{torn" + "z" * 900] * 1000)
    assert R.last_hash(str(p)) == "c" * 64


def test_the_delegation_is_what_makes_these_agree():
    assert "_tail_hash" in inspect.getsource(R.last_hash)


# ------------------------------------------- and the cost must be bounded

class _CountingOpen:
    """Wraps the module's `open` and totals every byte actually read."""

    def __init__(self):
        self.read = 0
        self._real = open

    def __call__(self, *a, **k):
        f = self._real(*a, **k)
        outer = self

        class _F:
            def __getattr__(self, n):
                return getattr(f, n)

            def read(self, *ra):
                data = f.read(*ra)
                outer.read += len(data)
                return data

            def __iter__(self):
                for line in f:
                    outer.read += len(line)
                    yield line

            def __enter__(self):
                return self

            def __exit__(self, *e):
                return f.__exit__(*e)
        return _F()


# SIZED AGAINST THE WINDOW, NOT AGAINST A ROUND NUMBER. These first wrote a
# 20 MB ledger twice, which proves nothing a 2 MB one does not: _tail_hash
# reads 64 KB, so 2 MB is thirty-two windows and the margin is already an
# order of magnitude. The Windows box ran out of disk on them (2026-09-13) -
# ~45 MB per run, and pytest keeps three runs of temp directories. A test
# that needs a big file should ask how big, and answer with the constant that
# actually decides the outcome.
LEDGER_ROWS = 2_200            # ~2 MB at 800 bytes of padding
WINDOW = 65_536                # _tail_hash's starting read


def test_reading_the_head_does_not_read_the_ledger(tmp_path, monkeypatch):
    """The point, pinned without a stopwatch. A ledger many times the read
    window must still cost a window, not a file - so appending stays flat
    instead of growing with everything the guard has ever recorded."""
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}", pad=800) for i in range(LEDGER_ROWS)])
    size = os.path.getsize(p)
    assert size > 20 * WINDOW, "the fixture is too small to prove anything"

    counter = _CountingOpen()
    monkeypatch.setattr(R, "open", counter, raising=False)
    assert R.last_hash(str(p)) == f"{LEDGER_ROWS - 1:064x}"
    assert counter.read < 3 * WINDOW, \
        f"read {counter.read} bytes of a {size} byte file"


def test_the_counter_would_notice_a_full_scan(tmp_path, monkeypatch):
    """The test above passes trivially if the wrapper counts nothing. This
    reads the same file the old way and shows the counter reacts."""
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}", pad=800) for i in range(LEDGER_ROWS)])
    size = os.path.getsize(p)

    counter = _CountingOpen()
    monkeypatch.setattr(R, "open", counter, raising=False)
    with R.open(str(p), encoding="utf-8") as f:
        for _ in f:
            pass
    # NOT `>= size`. getsize counts bytes ON DISK, and a newline written in
    # text mode is \r\n on Windows - two bytes - while reading it back in
    # text mode yields \n, one. So the counter legitimately totals one byte
    # per line LESS than the file's size: 2,043,800 against 2,046,000 for
    # 2,200 rows, which is exactly LEDGER_ROWS (Windows, 2026-09-14).
    # Comparing against the tail budget instead makes the pair symmetric -
    # one reads under it, the other far over - and says the same thing the
    # same way on both platforms.
    assert counter.read > 3 * WINDOW, \
        f"read only {counter.read} bytes of a {size} byte file"


def test_appending_to_a_long_ledger_still_chains_correctly(tmp_path):
    """End to end: the head that gets written is the real one."""
    p = tmp_path / "r.jsonl"
    _write(p, [_row(f"{i:064x}", pad=800) for i in range(1_000)])
    rec = R.Receipt(action_raw="rm -rf ./out", action_type="rm_rf",
                    target_environment="development", decision="REVERSIBLE",
                    reason="snapshot taken", mode="enforce")
    R.append_receipt(str(p), rec)
    assert rec.prev_receipt_hash == f"{999:064x}"
    assert R.last_hash(str(p)) == rec.receipt_hash

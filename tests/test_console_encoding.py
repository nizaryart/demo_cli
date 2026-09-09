"""`demo_cli check` crashed on a Windows console. Found 2026-09-09 on hardware.

    File "...\\render.py", line 76, in _print
        print("\\n".join(lines))
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'

PowerShell's default code page is cp1252. render.py prints a right-arrow in
the feedback prompt, and `print()` raised from inside the renderer - so a
primary command was unusable on a primary platform, for a decoration.

Two reasons it survived this long, both worth remembering:
  * doctor's hook self-test drives the hook path, which renders elsewhere, so
    every green doctor run on Windows told us nothing about this;
  * the Linux suite runs on a UTF-8 console, where the glyph encodes fine.
A test that only ever runs where the bug cannot occur is not coverage.

These tests force the failing encoding rather than relying on the platform, so
they fail on Linux too if the fix is removed.
"""
import io
import sys

import pytest

from demo_cli import render


def _cp1252_capture(monkeypatch):
    """stdout that behaves like a legacy Windows console: cp1252, strict."""
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252", errors="strict",
                              write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    return buf


def test_printing_a_glyph_the_console_cannot_encode_does_not_raise(monkeypatch):
    buf = _cp1252_capture(monkeypatch)
    render._print(["before → after"])          # must not raise
    assert b"before -> after" in buf.getvalue()


@pytest.mark.parametrize("glyph,plain", [
    ("→", "->"), ("·", "-"), ("»", ">"),
    ("•", "*"), ("—", "-"),
])
def test_each_glyph_has_a_named_fallback(monkeypatch, glyph, plain):
    """A row of question marks is technically not a crash and is still a bad
    answer. Every glyph this module uses gets a spelling.

    Forced through an ASCII console rather than cp1252 on purpose: cp1252
    happens to contain ·, », • and —, so only the arrow would exercise the
    table there and four of these five would pass without testing anything.
    """
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(
        buf, encoding="ascii", errors="strict", write_through=True))
    render._print([f"x{glyph}y"])
    assert plain.encode("ascii") in buf.getvalue()


def test_an_unforeseen_glyph_still_does_not_crash(monkeypatch):
    """The fallback table covers what we use today. Anything else must
    degrade, not escape - the point is that the renderer cannot take the
    command down."""
    buf = _cp1252_capture(monkeypatch)
    render._print(["中文 and \U0001f600"])   # must not raise
    assert buf.getvalue()


def test_a_utf8_console_is_untouched(monkeypatch):
    """The fallback is a fallback. Where the console can spell the glyph, it
    gets the glyph."""
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(
        buf, encoding="utf-8", errors="strict", write_through=True))
    render._print(["before → after"])
    assert "→".encode("utf-8") in buf.getvalue()


def test_the_renderer_does_not_promise_what_it_cannot_know(monkeypatch):
    """The verify report had its own copy of "a torn write, not an alteration
    - nothing was edited". receipts.py stopped saying it because it cannot
    know it; this copy kept saying it, so the corrected verdict printed the
    uncorrected sentence underneath."""
    from demo_cli.receipts import VerifyResult
    buf = _cp1252_capture(monkeypatch)
    v = VerifyResult(ok=True, entries=3, damaged_lines=[3], segments=1,
                     head="a" * 64, ledger="/x/receipts.jsonl")
    render.render_verify(v, "test")
    out = buf.getvalue().decode("cp1252")
    # Asserted on the OUTPUT, not the source: the source now carries a comment
    # explaining the removed phrasing, and grepping the source would match it.
    assert "not an alteration" not in out
    assert "nothing was edited" not in out
    assert "cannot be established" in out

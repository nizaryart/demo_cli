r"""The Codex hook must not fail open on a byte-order mark.

A parse failure in run_pretooluse steps aside - the command runs unguarded -
so anything that breaks the parse silently removes protection. Windows
produces a BOM readily: piping a string to a native process from PowerShell
delivered TWO of them (2026-09-13):

    b'\xef\xbb\xbf\xef\xbb\xbf{"hook_event_name":"PreToolUse",...}'

and it does not announce itself. Through a cp1252 locale those bytes decode
to `ï»¿`, so json says "Expecting value: line 1 column 1 (char 0)" instead of
its own "Unexpected UTF-8 BOM" - which is why this was first misdiagnosed as
something other than a BOM.

Codex itself sends clean UTF-8 and the real host was never affected. Fixed
anyway: the cost is one lstrip, and a Windows BOM has already broken this
project's config parsing once.
"""
import io
import json

import pytest

from demo_cli.hooks import codex as C

BOM = "﻿"
PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
           "tool_input": {"command": "echo hello"}, "cwd": ".",
           "session_id": "s1"}


def _run(text, capsys):
    rc = C.run_pretooluse(io.StringIO(text), io.StringIO())
    return rc, capsys.readouterr().err


def test_a_clean_payload_is_parsed(capsys):
    rc, err = _run(json.dumps(PAYLOAD), capsys)
    assert rc == 0
    assert "could not parse" not in err


def test_one_bom_does_not_step_aside(capsys):
    rc, err = _run(BOM + json.dumps(PAYLOAD), capsys)
    assert "could not parse" not in err, err


def test_the_two_boms_powershell_actually_sent(capsys):
    rc, err = _run(BOM + BOM + json.dumps(PAYLOAD), capsys)
    assert "could not parse" not in err, err


def test_the_mojibake_spelling_is_the_same_bytes():
    r"""Sanity-check the diagnosis itself: \xef\xbb\xbf read as cp1252 IS the
    mojibake seen on the French Windows console, and read as utf-8 IS U+FEFF.
    One byte sequence, two spellings, which is the whole reason the error
    message pointed away from the cause."""
    raw = b"\xef\xbb\xbf"
    assert raw.decode("cp1252") == "ï»¿"
    assert raw.decode("utf-8") == BOM


def test_a_bom_in_the_middle_is_left_alone():
    """Only leading marks are stripped. A U+FEFF inside a command is data -
    removing it would silently change what gets classified."""
    assert C._strip_bom(BOM + 'x' + BOM) == 'x' + BOM


def test_empty_input_is_still_silent(capsys):
    """No payload is Codex asking nothing of us, not an error."""
    rc, err = _run("", capsys)
    assert rc == 0
    assert "could not parse" not in err


def test_a_bom_and_nothing_else_is_not_an_error(capsys):
    rc, err = _run(BOM, capsys)
    assert rc == 0
    assert "could not parse" not in err, err


def test_genuinely_broken_input_still_says_so(capsys):
    """The fix must not turn a real parse failure into silence."""
    rc, err = _run("{not json", capsys)
    assert rc == 0
    assert "could not parse" in err


def test_the_debug_flag_shows_the_payload_that_failed(capsys, monkeypatch):
    """It used to print only AFTER a successful parse, so setting it on a real
    failure produced nothing at all - and the payload had to be captured by
    piping into a separate python before anyone could see it."""
    monkeypatch.setenv("DEMO_CLI_HOOK_DEBUG", "1")
    rc, err = _run("ï»¿{oops", capsys)
    assert "unparseable payload" in err
    assert "oops" in err

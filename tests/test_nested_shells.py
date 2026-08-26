"""`powershell -Command "..."` is the command inside the quotes.

Observed live on Windows, 2026-08-26. Claude Code's Bash tool is GIT BASH -
`pwd` returns /c/Users/... - so PowerShell never arrives as the tool's own
dialect. It arrives NESTED. Asked to use Remove-Item, the agent ran:

    Bash(powershell.exe -Command "Remove-Item test.txt")

_PS_REMOVE_RE is anchored at the start, the command starts with
`powershell.exe`, and seven correct PowerShell rules sat dormant while the
delete went through. The filesystem guard caught it; the string layer never
saw it.

Third instance of one shape in this project: THE RULES WERE RIGHT AND THE
PLUMBING NEVER ASKED THEM (see also `mv` missing from the shell-guard
pre-filter, and dispatch running on the line instead of the segment).
"""
import base64
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import (POSIX, POWERSHELL, classify_pipeline,
                               effective_command, unwrap_nested)


def encoded(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


# --------------------------------------------------------------------------
# Unwrapping, one level
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,inner", [
    ('powershell.exe -Command "Remove-Item x"', "Remove-Item x"),
    ('powershell -Command "Remove-Item x"', "Remove-Item x"),
    ('powershell -c "Remove-Item x"', "Remove-Item x"),
    ('pwsh -Command "Remove-Item x"', "Remove-Item x"),
    ('PowerShell.EXE -COMMAND "Remove-Item x"', "Remove-Item x"),
])
def test_a_powershell_payload_is_unwrapped_as_powershell(cmd, inner):
    assert unwrap_nested(cmd) == (inner, POWERSHELL)


@pytest.mark.parametrize("cmd,inner", [
    ('bash -c "rm x"', "rm x"),
    ('sh -c "rm x"', "rm x"),
    ("/bin/bash -c 'rm x'", "rm x"),
    ('cmd /c "del /f x"', "del /f x"),
    ('cmd.exe /k "del /f x"', "del /f x"),
])
def test_posix_and_cmd_payloads_are_unwrapped_as_posix(cmd, inner):
    assert unwrap_nested(cmd) == (inner, POSIX)


def test_an_encoded_command_is_DECODED_not_executed():
    """base64 is mechanical: nothing runs, nothing is guessed. It is the one
    obfuscation a pre-execution guard can honestly see through, and the most
    common one in practice."""
    cmd = f"powershell -EncodedCommand {encoded('Remove-Item secret.txt')}"
    assert unwrap_nested(cmd) == ("Remove-Item secret.txt", POWERSHELL)


@pytest.mark.parametrize("flag", ["-e", "-enc", "-EncodedCommand"])
def test_the_abbreviated_encoded_flags_are_recognised(flag):
    assert unwrap_nested(f"powershell {flag} {encoded('Remove-Item x')}") \
        == ("Remove-Item x", POWERSHELL)


def test_undecodable_base64_is_not_guessed_at():
    assert unwrap_nested("powershell -EncodedCommand not!valid!base64") is None


# --------------------------------------------------------------------------
# What must NOT unwrap
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo powershell -c "rm x"',        # the word appears, it is not the verb
    "rm x",
    "ls -la",
    "powershell -NoProfile",            # no payload at all
    'grep "bash -c" file.txt',
])
def test_a_command_that_is_not_a_nested_shell_is_untouched(cmd):
    assert unwrap_nested(cmd) is None
    assert effective_command(cmd) == (cmd, POSIX)


def test_nesting_is_bounded():
    """`a -c "b -c 'c -c ...'"` must terminate rather than recurse forever."""
    deep = 'bash -c "' * 12 + "rm x" + '"' * 12
    inner, _ = effective_command(deep)
    assert "rm x" in inner


# --------------------------------------------------------------------------
# End to end: classification AND operand extraction must agree
# --------------------------------------------------------------------------

@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.txt").write_text("data")
    return tmp_path


@pytest.mark.parametrize("cmd", [
    'powershell.exe -Command "Remove-Item test.txt"',
    'powershell -c "Clear-Content test.txt"',
    'pwsh -Command "Remove-Item -Path test.txt"',
    'bash -c "rm test.txt"',
])
def test_a_nested_destructive_command_is_classified_and_resolved(files, cmd):
    """Both halves, together. If only the classifier unwrapped, it would call
    the command destructive while the operand extractor searched text that no
    longer describes the action - and the guard would escalate a command it
    could have snapshotted."""
    assert classify_pipeline(cmd).is_destructive
    assert recovery.extract_path_operand(cmd) == "test.txt"


def test_an_encoded_delete_is_classified_and_resolved(files):
    cmd = f"powershell -EncodedCommand {encoded('Remove-Item test.txt')}"
    assert classify_pipeline(cmd).is_destructive
    assert recovery.extract_path_operand(cmd) == "test.txt"


def test_the_guard_snapshots_a_nested_delete(files):
    """The whole point: this is the exact command the agent ran on Windows."""
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    r = Guard(Config(mode="enforce", project_root=str(files))).evaluate(
        'powershell.exe -Command "Remove-Item test.txt"',
        agent_id="t", session_id="t")
    assert r.receipt.decision == "REVERSIBLE"
    assert r.receipt.recovery_point


def test_a_nested_safe_command_stays_safe(files):
    assert not classify_pipeline('powershell -Command "Get-Content test.txt"').is_destructive


# --------------------------------------------------------------------------
# The frontier, stated as a test so nobody assumes otherwise
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "Remo`ve-Item test.txt",
    "R`e`move-Item test.txt",
    "`Remove-Item test.txt",
])
def test_backtick_obfuscation_IS_caught(files, payload):
    """The most likely real bypass of the PowerShell rules, and a mechanical
    one: PowerShell's grammar says a backtick before an ordinary character
    means that character, so removing it is reading, not evaluating."""
    cmd = f'powershell -c "{payload}"'
    assert classify_pipeline(cmd).is_destructive
    assert recovery.extract_path_operand(cmd) == "test.txt"


@pytest.mark.parametrize("payload", [
    "&('Remove-Item') test.txt",        # call operator on a string
    "iex 'Remove-Item test.txt'",       # invoke-expression
    "$c='Remove-Item'; & $c test.txt",  # built at runtime
])
def test_expression_obfuscation_is_NOT_caught_and_never_will_be(files, payload):
    """THE FRONTIER, written down so nobody assumes otherwise.

    Resolving these means EVALUATING a PowerShell expression, which a
    pre-execution guard must never do - the moment it evaluates the thing it
    is guarding, it has stopped being one. They belong to the behavioural
    layer, and on Windows the WinFsp guard catches them at the filesystem
    where the spelling no longer exists.

    An earlier version of this test used `R''emove-Item`, a BASH-ism that is
    not even valid PowerShell - so it asserted we miss something that would
    not have run. Fourth time an assumption from the wrong dialect got into a
    test here.
    """
    assert not classify_pipeline(f'powershell -c "{payload}"').is_destructive


# --------------------------------------------------------------------------
# The backtick normaliser on its own
# --------------------------------------------------------------------------

from demo_cli.classify import strip_ps_escapes


@pytest.mark.parametrize("raw,expected", [
    ("Remo`ve-Item x", "Remove-Item x"),
    ("R`e`m`o`v`e-Item x", "Remove-Item x"),
    ("Remove-Item x", "Remove-Item x"),
])
def test_literal_escapes_are_removed(raw, expected):
    assert strip_ps_escapes(raw) == expected


def test_escape_sequences_inside_double_quotes_are_preserved():
    """`n is a newline, not the letter n. Turning "a`nb" into "anb" would
    corrupt the very string being examined."""
    assert strip_ps_escapes('Write-Host "a`nb"') == 'Write-Host "a`nb"'


def test_single_quoted_content_is_untouched():
    """PowerShell does no escaping at all inside single quotes."""
    assert strip_ps_escapes("Remove-Item 'a`b'") == "Remove-Item 'a`b'"


def test_a_backtick_in_a_bare_word_is_literal_even_for_escape_letters():
    """`v is a vertical tab ONLY inside double quotes. In a bare command name
    it is the letter v - which is exactly what the first implementation got
    wrong, and exactly why Remo`ve-Item slipped through."""
    assert strip_ps_escapes("Remo`ve-Item x") == "Remove-Item x"
    assert strip_ps_escapes("Remo`nve x") == "Remonve x"

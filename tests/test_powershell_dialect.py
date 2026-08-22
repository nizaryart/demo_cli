"""PowerShell dialect handling in the string classifier.

These run on EVERY platform, not only Windows. The code under test is pure text
parsing, and a PowerShell command is just a string - Linux cannot *run*
`Remove-Item`, but it can certainly reason about the characters. Only code that
*executes* on Windows (file locking, snapshots) needs a Windows machine.

PowerShell differs from POSIX shells in ways this classifier was never told about:

    escape character      POSIX  \\x        PowerShell  `x
    line continuation     POSIX  \\<eol>    PowerShell  `<eol>
    backslash means       POSIX  escape     PowerShell  PATH SEPARATOR

Each test below states the PowerShell truth, so a failure is a precise
description of the gap rather than a vague suspicion.
"""
from demo_cli import recovery
from demo_cli.classify import (POSIX, POWERSHELL, classify_pipeline,
                               join_continuations, redirect_target, split_segments)

# One PowerShell command written across two lines. The trailing backtick is a
# line continuation - PowerShell joins these before executing anything.
PS_CONTINUATION = "Remove-Item `\n  -Recurse -Force C:\\build"


# --------------------------------------------------------------------------
# Line continuation
# --------------------------------------------------------------------------

def test_backtick_continuation_is_a_single_command():
    """A trailing backtick joins the lines; it is not a command separator."""
    segments = split_segments(PS_CONTINUATION, POWERSHELL)
    assert len(segments) == 1, f"split into {len(segments)}: {segments}"
    assert "Remove-Item" in segments[0]
    assert "C:\\build" in segments[0]


def test_backtick_continuation_still_resolves_its_path(tmp_path):
    """The path lives on the second line. If the command is split, the operand
    extractor loses it and we snapshot nothing - a real delete goes uncovered.

    Uses a path that really exists: extract_path_operand deliberately refuses to
    name a target it cannot find on disk, so a fictional C:\\ path would return
    None here for a reason unrelated to line continuations."""
    victim = tmp_path / "build"
    victim.mkdir()
    cmd = f"Remove-Item `\n  -Recurse -Force {victim}"
    operand = recovery.extract_path_operand(cmd, POWERSHELL)
    assert operand is not None, "no target resolved - nothing would be snapshotted"
    assert operand.endswith("build")


def test_backtick_continuation_is_classified_destructive():
    """Whatever the splitting does, the command must not be seen as harmless."""
    assert classify_pipeline(PS_CONTINUATION, POWERSHELL).is_destructive


def test_posix_does_not_join_on_a_backtick():
    """The joiner must be dialect-specific. A trailing backtick in bash opens a
    command substitution; folding it there could merge two commands and stop an
    anchored rule from matching."""
    assert len(split_segments(PS_CONTINUATION, POSIX)) == 2


# --------------------------------------------------------------------------
# The same bug in bash - this was never a Windows-only problem
# --------------------------------------------------------------------------

BASH_CONTINUATION = "rm -rf \\\n  /tmp/build"


def test_bash_backslash_continuation_is_a_single_command():
    assert len(split_segments(BASH_CONTINUATION, POSIX)) == 1


def test_bash_continuation_resolves_its_path(tmp_path):
    victim = tmp_path / "build"
    victim.mkdir()
    cmd = f"rm -rf \\\n  {victim}"
    assert recovery.extract_path_operand(cmd) == str(victim)


def test_powershell_does_not_join_on_a_backslash():
    """A trailing backslash in PowerShell is a literal backslash, not a join."""
    assert len(split_segments(BASH_CONTINUATION, POWERSHELL)) == 2


def test_join_is_idempotent():
    once = join_continuations(BASH_CONTINUATION, POSIX)
    assert join_continuations(once, POSIX) == once


# --------------------------------------------------------------------------
# Escaping and quoting
# --------------------------------------------------------------------------

def test_backtick_escaped_quote_does_not_confuse_the_scanner():
    """`" is an escaped quote INSIDE the string - it does not end the string."""
    cmd = 'Write-Output "he said `"hi`"" > C:\\notes.txt'
    assert redirect_target(cmd) == "C:\\notes.txt"


def test_windows_path_is_read_whole_after_a_redirect():
    """Backslashes are path separators here, not escapes."""
    assert redirect_target(r"type a.txt > C:\logs\out.txt") == r"C:\logs\out.txt"


def test_backslash_in_a_windows_path_is_not_an_escape():
    """`C:\\temp` before a redirect must not swallow the `>` that follows."""
    assert redirect_target(r"Get-Content C:\temp\in.txt > C:\temp\out.txt") == r"C:\temp\out.txt"


# --------------------------------------------------------------------------
# Real Windows paths
# --------------------------------------------------------------------------

def test_quoted_windows_path_with_spaces_is_kept_intact():
    """`C:\\Program Files\\...` is one path, not two words.

    Checked against the operand reader rather than extract_path_operand, because
    that one also requires the path to exist and a C:\\ path never will on a
    Linux test runner. This isolates the tokenising."""
    cmd = 'Remove-Item -Recurse -Force "C:\\Program Files\\MyApp"'
    assert recovery._tokenize(cmd) == ["Remove-Item", "-Recurse", "-Force",
                                       "C:\\Program Files\\MyApp"]
    assert recovery._ps_remove_item_operand(cmd) == "C:\\Program Files\\MyApp"


def test_path_with_spaces_resolves_end_to_end(tmp_path):
    """The same thing on a real directory, all the way through the extractor.
    NOT Windows-specific: any path with a space was losing its target."""
    victim = tmp_path / "my project"
    victim.mkdir()
    assert recovery.extract_path_operand(f'rm -rf "{victim}"') == str(victim)


def test_unbalanced_quotes_do_not_crash(tmp_path):
    """shlex raises on an unclosed quote. The guard must degrade, never crash."""
    assert recovery._tokenize('rm -rf "unclosed') == ["rm", "-rf", '"unclosed']


def test_unc_path_is_resolved_or_honestly_refused():
    """A network path must never resolve to the WRONG place. Either we read it
    correctly, or we return None and escalate - never a plausible-looking lie."""
    cmd = r"Remove-Item -Recurse -Force \\server\share\build"
    operand = recovery.extract_path_operand(cmd)
    assert operand is None or operand.endswith("build")


# --------------------------------------------------------------------------
# Things that should already work - included so a wrong assumption is caught
# --------------------------------------------------------------------------

def test_semicolon_separates_commands_in_powershell():
    """PowerShell 5.1 has no && or ||; `;` is how commands are chained."""
    segments = split_segments(r"Get-ChildItem; Remove-Item C:\tmp\x")
    assert len(segments) == 2


def test_pipe_separates_commands_in_powershell():
    segments = split_segments(r"Get-ChildItem | Remove-Item")
    assert len(segments) == 2


# --------------------------------------------------------------------------
# Windows line endings (CRLF)
#
# Windows ends lines with \r\n. Every parser here was written against \n, so
# the CR was silently absorbed into whatever came next. Found by asking whether
# extra spaces before a newline still worked - they did; CRLF did not.
# --------------------------------------------------------------------------

def test_crlf_continuation_powershell():
    cmd = "Remove-Item `\r\n  -Recurse -Force C:\\build"
    assert len(split_segments(cmd, POWERSHELL)) == 1


def test_crlf_continuation_bash():
    assert len(split_segments("rm -rf \\\r\n  /tmp/build", POSIX)) == 1


def test_crlf_does_not_leak_into_a_redirect_filename():
    """The killer case. redirect_target used to return 'out.txt\\r'; guard.py
    then found no such file, concluded the redirect CREATES rather than
    truncates, and allowed an overwrite of a real file with NO snapshot.
    A parsing bug and a correctness feature combining into silent data loss."""
    assert redirect_target("echo x > out.txt\r\nls") == "out.txt"


def test_crlf_overwrite_is_still_snapshotted(tmp_path):
    """End to end, at the guard: LF and CRLF must decide identically."""
    from demo_cli.config import load_config
    from demo_cli.guard import Guard
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    victim = tmp_path / "out.txt"
    victim.write_text("PRECIOUS DATA")
    guard = Guard(config=load_config(start=str(tmp_path)))
    lf = guard.evaluate(f"echo x > {victim}\nls")
    crlf = guard.evaluate(f"echo x > {victim}\r\nls")
    assert lf.classification.matched_rule == crlf.classification.matched_rule == "fs_redirect_truncate"
    assert lf.decision.decision == crlf.decision.decision == "REVERSIBLE"
    assert bool(lf.recovery_entry) and bool(crlf.recovery_entry)


# --------------------------------------------------------------------------
# Whitespace tolerance around a continuation
# --------------------------------------------------------------------------

def test_continuation_tolerates_trailing_whitespace():
    """People leave spaces and tabs after the continuation character."""
    for tail in ["", " ", "     ", "\t", " \t \t "]:
        cmd = f"rm -rf \\{tail}\n  /tmp/build"
        assert len(split_segments(cmd, POSIX)) == 1, f"failed with tail {tail!r}"


def test_continuation_across_three_lines():
    cmd = "rm -rf \\\n  /tmp/a \\\n  /tmp/b"
    segments = split_segments(cmd, POSIX)
    assert len(segments) == 1
    assert "/tmp/a" in segments[0] and "/tmp/b" in segments[0]


def test_a_backslash_mid_line_is_not_a_continuation():
    """Only end-of-line counts. A backslash inside text is just a character."""
    assert join_continuations(r"rm C:\temp\file", POSIX) == r"rm C:\temp\file"

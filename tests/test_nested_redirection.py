"""A nested shell's payload must survive a trailing redirection, and must be
found wherever the wrapper sits in the pipeline.

Both defects were found on 2026-09-02, by an agent working through a scripted
lab exercise on the `labubu` Windows project. It reported the guard as having
missed three destructive commands. Two of the three were caught by the
filesystem layer anyway, but the string layer genuinely did miss them, and the
same two bugs were then reproduced on Linux against bash and cmd.exe - so this
was never Windows-only.

BUG A - a trailing redirection was joined into the payload.

    powershell.exe -Command "Remove-Item -Force notes.txt" 2>&1

  The tokens after -Command were joined, giving

    "Remove-Item -Force notes.txt" 2>&1

  which `_strip_quotes` will not strip (it is not one matching pair), so the
  payload began with a quote character and every `^\\s*`-anchored rule stopped
  matching. The `2>&1` belongs to the OUTER shell; it was never part of the
  nested script.

BUG B - unwrapping ran once on the whole line, before splitting.

    echo hi; powershell -Command "Remove-Item x"

  The line starts with `echo`, so no wrapper was recognised and the nested
  Remove-Item was never judged at all.

WHY THE DAMAGE DIFFERED, and why the suite did not catch either:
unanchored rules (rm_rf, ps_remove_item_rf) still fired on the mangled text,
so the command was still called destructive - it only lost its operand, and
degraded to an honest ESCALATE. Anchored rules did not fire at all, which is a
silent pass. Every existing nested-shell test used the unanchored form.

The tests below therefore assert BOTH halves for every row: what the command
is (classification) and what it will touch (operand extraction). Asserting
only the first is what let this live.
"""
import os

import pytest

from demo_cli.classify import classify_pipeline
from demo_cli.recovery import extract_path_operand


# --------------------------------------------------------------------------
# Bug A: a trailing redirection must not enter the payload.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("suffix", ["", " 2>&1", " > /tmp/log", " 2> /tmp/err",
                                    " >> /tmp/log", " < /tmp/in"])
@pytest.mark.parametrize("wrapper", [
    'powershell.exe -Command "Remove-Item -Force victim.txt"{}',
    'powershell.exe -NoProfile -Command "Remove-Item -Force victim.txt"{}',
    'pwsh -c "Remove-Item -Force victim.txt"{}',
])
def test_redirection_does_not_hide_a_nested_powershell_delete(wrapper, suffix):
    c = classify_pipeline(wrapper.format(suffix))
    assert c.is_destructive, "the redirection swallowed the payload"
    assert c.matched_rule == "ps_remove_item"


@pytest.mark.parametrize("suffix", ["", " 2>&1", " > /tmp/log"])
def test_redirection_does_not_hide_a_nested_posix_delete(suffix):
    c = classify_pipeline('bash -c "rm -rf ./out"' + suffix)
    assert c.is_destructive
    assert c.matched_rule == "rm_rf"


@pytest.mark.parametrize("suffix", ["", " 2>&1"])
def test_redirection_does_not_hide_a_nested_cmd_delete(suffix):
    c = classify_pipeline(r'cmd.exe /c "del /f C:\victim\a.txt"' + suffix)
    assert c.is_destructive
    assert c.matched_rule == "del_force"


@pytest.mark.parametrize("suffix", ["", " 2>&1"])
def test_the_cmd_payload_is_unwrapped_even_when_no_rule_matches(suffix):
    """Separated from the rule assertion on purpose.

    `del` without /f or /s matches no rule - del_force is deliberately narrow
    (classify.py:97). That is a rule-coverage question, and it must not be
    able to mask an unwrapping failure. Assert on the segments, which show
    what the guard decided the command IS, independently of any verdict.
    """
    c = classify_pipeline(r'cmd.exe /c "del C:\victim\a.txt"' + suffix)
    assert c.segments == [r"del C:\victim\a.txt"]


def test_unquoted_payload_still_stops_at_the_redirection():
    """`-Command rm -rf x 2>&1` has no quotes to lean on: the payload is every
    token up to the redirection."""
    c = classify_pipeline("bash -c rm -rf ./out 2>&1")
    assert c.is_destructive
    assert c.matched_rule == "rm_rf"


def test_encoded_command_was_already_immune_and_stays_immune():
    """-EncodedCommand took exactly one token, which is why it never had bug A.
    It is the shape the other three branches were changed to match, so a
    regression here means the fix was applied in the wrong direction."""
    # base64(utf-16-le) of: Remove-Item -Force x
    payload = ("UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBGAG8AcgBjAGUAIAB4AA==")
    c = classify_pipeline(f"powershell.exe -EncodedCommand {payload} 2>&1")
    assert c.is_destructive
    assert c.matched_rule == "ps_remove_item"


# --------------------------------------------------------------------------
# Bug B: the wrapper may sit anywhere in the pipeline.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo hi; powershell.exe -Command "Remove-Item -Force victim.txt"',
    'cat notes.txt && powershell.exe -Command "Remove-Item -Force victim.txt"',
    'echo a; echo b; pwsh -c "Remove-Item -Force victim.txt"; echo c',
])
def test_a_nested_delete_is_found_in_any_pipeline_position(cmd):
    c = classify_pipeline(cmd)
    assert c.is_destructive, "unwrapping only looked at the first segment"
    assert c.matched_rule == "ps_remove_item"


def test_the_exact_command_from_the_labubu_run():
    """Task 6, verbatim from the receipt written on 2026-09-02. Both bugs at
    once: the wrapper is the third segment AND carries a trailing 2>&1."""
    cmd = ('cat notes.txt; echo "---"; '
           'powershell.exe -Command "Remove-Item -Force notes.txt" 2>&1; '
           'echo "exit=$?"')
    c = classify_pipeline(cmd)
    assert c.is_destructive
    assert c.matched_rule == "ps_remove_item"


def test_nested_posix_shell_in_a_later_segment():
    c = classify_pipeline('echo hi; bash -c "rm -rf ./out"')
    assert c.is_destructive
    assert c.matched_rule == "rm_rf"


# --------------------------------------------------------------------------
# The operand half. A command that is flagged but whose target cannot be
# resolved escalates instead of snapshotting - honest, but a downgrade.
# --------------------------------------------------------------------------

@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / "victim.txt").write_text("x")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "a.txt").write_text("y")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize("cmd,expected", [
    ('bash -c "rm -rf ./out"',                            "./out"),
    ('bash -c "rm -rf ./out" 2>&1',                       "./out"),
    ('echo hi; bash -c "rm -rf ./out"',                   "./out"),
    ('echo hi; bash -c "rm -rf ./out" 2>&1',              "./out"),
    ('powershell.exe -Command "Remove-Item -Force victim.txt"',      "victim.txt"),
    ('powershell.exe -Command "Remove-Item -Force victim.txt" 2>&1', "victim.txt"),
    ('echo hi; pwsh -c "Remove-Item -Force victim.txt" 2>&1',        "victim.txt"),
])
def test_the_operand_survives_the_wrapper(lab, cmd, expected):
    assert extract_path_operand(cmd) == expected


def test_two_redirecting_segments_still_escalate(lab):
    """One target snapshotted while the other is truncated unrecorded is the
    partial-recovery lie. Redirection is judged per segment now, so this has
    to keep returning None."""
    (lab / "a.txt").write_text("a")
    (lab / "b.txt").write_text("b")
    assert extract_path_operand("echo x > a.txt; echo y > b.txt") is None


def test_a_single_redirect_still_resolves(lab):
    (lab / "a.txt").write_text("a")
    assert extract_path_operand("echo x > a.txt") == os.path.abspath("a.txt")


# --------------------------------------------------------------------------
# What the ^ anchors are protecting. The tempting one-line "fix" for bug A was
# to drop them; these are the false positives that would have arrived with it.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo "Remove-Item is destructive"',
    'grep -r "Set-Content" ./docs',
    'echo "Clear-Content wipes a file"',
])
def test_a_verb_inside_a_string_is_still_not_a_command(cmd):
    assert not classify_pipeline(cmd).is_destructive


def test_the_unanchored_posix_rules_still_false_positive():
    """Not a wish - a record of the standing trade.

    `rm_rf` is unanchored by design (classify.py:39), so `echo "run rm -rf
    later"` is flagged. That over-fires, and the cost was accepted for the
    coverage. It is ALSO why the two nested-shell bugs survived: unanchored
    rules kept firing on the mangled payload, so the command still looked
    destructive and only its operand went missing.

    Pinned here so that if someone anchors these rules later, this test fails
    and they are told what else that changes.
    """
    assert classify_pipeline('echo "run rm -rf later"').matched_rule == "rm_rf"

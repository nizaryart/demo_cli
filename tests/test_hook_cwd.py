r"""The hook must resolve the agent's relative paths against the AGENT's
directory, not its own.

THE DEFECT. All three adapters read `cwd` from the payload, use it for
load_config(start=cwd), and then let every path resolve against the hook
PROCESS's working directory. guard.evaluate takes no cwd; guard.evaluate_file_edit
calls os.path.abspath(file_path) directly (guard.py:391).

Reproduced on real code: project P, agent working in P/sub, a file of the
same name in both. The tool printed "recovery point captured before this
ran", wrote REVERSIBLE, and the snapshot held the bystander at P while the
agent deleted P/sub. `undo` would restore the wrong file.

That is commit 14dda64's sentence one level up - "a recovery point holding
the wrong tree, reported REVERSIBLE". That fix handled a `cd` INSIDE a
command line; it never questioned the process's own directory as a base.

ASSERT CONTENT, NEVER THE DECISION ALONE. The buggy behaviour is ALREADY
"REVERSIBLE" - it captures the wrong file enthusiastically - so a test that
checks the decision passes against the bug. Six tests in this project have
been found passing for the wrong reason; this defect is unusually good at
producing them.
"""
import glob
import io
import json
import os

import pytest

from demo_cli.hooks.claude_code import run_pretooluse as cc_hook
from demo_cli.hooks.codex import run_pretooluse as codex_hook

REAL = "THE REAL DATA the agent acts on"
BYSTANDER = "an innocent bystander at the project root"


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Project P with a subdirectory, and the same filename in both.

    The two directories are in ONE project on purpose: guard.py:199 refuses a
    target outside cfg.project_root, so a cross-project mismatch already
    escalates. Inside one project both candidates are legitimately in scope
    and that check cannot discriminate - which is the only shape where this
    defect bites.
    """
    proj = tmp_path / "P"
    sub = proj / "sub"
    sub.mkdir(parents=True)
    (proj / ".demo_cli.toml").write_text('mode = "enforce"\n')
    for name in ("data.db", "notes.txt"):
        (proj / name).write_text(BYSTANDER)
        (sub / name).write_text(REAL)
    monkeypatch.chdir(proj)          # the HOOK runs at the project root
    return proj, sub                 # the AGENT works one level down


def _captured(proj):
    """Contents of every file snapshot under the project."""
    out = []
    for s in glob.glob(str(proj / ".demo_cli" / "recovery" / "*.bak")):
        with open(s, encoding="utf-8", errors="replace") as f:
            out.append(f.read())
    return out


def _receipts(proj):
    p = proj / ".demo_cli" / "receipts.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


# ------------------------------------------------------------- shell path

def test_a_relative_operand_snapshots_the_agents_file(lab):
    """The reproduction. Fails against HEAD: the snapshot holds BYSTANDER."""
    proj, sub = lab
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm data.db"},
        "cwd": str(sub), "session_id": "s"})), out)

    held = _captured(proj)
    assert held, "nothing was captured at all"
    assert REAL in held, (
        "the recovery point holds the WRONG file - this is an unearned "
        f"REVERSIBLE: {held}")
    assert BYSTANDER not in held, "the bystander was copied instead"


def test_the_receipt_names_the_agents_file(lab):
    proj, sub = lab
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm data.db"},
        "cwd": str(sub), "session_id": "s"})), out)
    # STRICT. The first version of this assertion was
    #     str(sub) in recovery_point  OR  "sub" in json.dumps(receipt)
    # and it PASSED AGAINST THE BUG - the bare substring "sub" turns up
    # somewhere in a receipt whatever happened. Caught by running it before
    # the fix existed, which is the only reason it is not the seventh test in
    # this project to pass for the wrong reason.
    last = _receipts(proj)[-1]
    assert last["decision"] == "REVERSIBLE"
    target = last.get("context", {}).get("target") or last.get("recovery_point") or ""
    assert str(sub) in json.dumps(last), (
        "no field in the receipt names the directory the agent was actually "
        f"standing in: {last}")


# --------------------------------------------------------- file-edit path

def test_a_relative_file_edit_snapshots_the_agents_file(lab):
    """FINDING A from the 2026-09-14 design review, and the reason the first
    version of this fix would have shipped broken.

    guard.evaluate_file_edit does its own os.path.abspath(file_path), so
    wrapping only the shell call leaves Edit / Write / MultiEdit /
    NotebookEdit resolving against the hook's directory. A partial fix that
    reads as complete - the fifth time in this project a claim landed in one
    of two places.
    """
    proj, sub = lab
    out = io.StringIO()
    cc_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Edit",
        "tool_input": {"file_path": "notes.txt"},
        "cwd": str(sub), "session_id": "s"})), out)

    held = _captured(proj)
    assert held, "the file edit captured nothing"
    assert REAL in held, f"the edit snapshotted the wrong file: {held}"
    assert BYSTANDER not in held


# ------------------------------------------------------ the directory itself

def test_the_working_directory_is_restored(lab):
    """The hook is NOT always a one-shot process - cli.py:449 calls
    run_pretooluse in-process inside doctor's self-test. A caller that
    survives the call must get its directory back."""
    proj, sub = lab
    before = os.getcwd()
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm data.db"},
        "cwd": str(sub), "session_id": "s"})), out)
    assert os.getcwd() == before


def test_the_directory_is_restored_even_when_the_guard_raises(lab, monkeypatch):
    """try/finally, not two statements. An exception here would otherwise
    leave a long-lived caller standing in the agent's directory, with every
    later resolution wrong and nothing reporting it."""
    proj, sub = lab
    from demo_cli.guard import Guard
    monkeypatch.setattr(Guard, "evaluate",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    before = os.getcwd()
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm data.db"},
        "cwd": str(sub), "session_id": "s"})), out)
    assert os.getcwd() == before


def test_an_unreachable_agent_directory_escalates(lab):
    """WHEN WE CANNOT STAND WHERE THE AGENT STANDS, WE DO NOT GUESS.

    chdir fails only when the directory is gone or unreadable - rare, and a
    state in which nobody can resolve a relative operand correctly. Falling
    back to our own directory would be "resolved is not the same as found" a
    third time: we would hold the information that the base is unreliable and
    discard it.
    """
    proj, sub = lab
    gone = str(proj / "does-not-exist")
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm data.db"},
        "cwd": gone, "session_id": "s"})), out)
    raw = out.getvalue()
    assert raw, "an unresolvable base must not pass silently"
    assert json.loads(raw)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _captured(proj) == [], "nothing may be captured on a base we do not trust"


def test_an_absolute_operand_is_unaffected_by_the_agents_directory(lab):
    """The fix must not make absolute paths depend on cwd."""
    proj, sub = lab
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": f"rm {proj / 'data.db'}"},
        "cwd": str(sub), "session_id": "s"})), out)
    assert BYSTANDER in _captured(proj), "an absolute path named the root file"


# --------------------------------------------------------------------------
# The widening this causes, pinned as a decision
#
# FINDING B from the 2026-09-14 design review. Resolving against the agent's
# directory moves the multi-path collapse root from the project root down to
# the subdirectory - and guard.py:207 refuses `ap == root` (the project root)
# but not a subdirectory. So commands that escalated ONLY because their
# collapse hit the project root now resolve and snapshot.
#
# These are pinned because the suite did not move when the fix was probed.
# That was evidence of a COVERAGE HOLE, not of safety, and reading it the
# other way is how the next person gets misled.

def test_a_multi_file_rm_in_a_subdirectory_is_now_captured(lab):
    """ESCALATE -> REVERSIBLE. A deliberate change, not a side effect.

    Earned, which is the only reason it is acceptable: the captured directory
    is a genuine superset of what is deleted. An unearned REVERSIBLE here
    would be the defect this whole file exists to close, reintroduced by its
    own fix.
    """
    proj, sub = lab
    (sub / "a.txt").write_text("A")
    (sub / "b.txt").write_text("B")
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm a.txt b.txt"},
        "cwd": str(sub), "session_id": "s"})), out)

    last = _receipts(proj)[-1]
    assert last["decision"] == "REVERSIBLE", last
    snapdirs = glob.glob(str(proj / ".demo_cli" / "recovery" / "*.snapdir"))
    assert snapdirs, "REVERSIBLE was claimed with no directory capture"
    held = set(os.listdir(snapdirs[0]))
    assert {"a.txt", "b.txt"} <= held, f"the capture misses a deleted file: {held}"


def test_the_project_root_is_still_refused(lab):
    """The rule that produced the old ESCALATE is UNCHANGED - it refuses the
    project root as a capture surface, because deep-copying the whole tree on
    every two-file rm is "neither honest nor cheap". Only the base moved. An
    agent standing AT the root still escalates."""
    proj, _sub = lab
    (proj / "a.txt").write_text("A")
    (proj / "b.txt").write_text("B")
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm a.txt b.txt"},
        "cwd": str(proj), "session_id": "s"})), out)
    assert _receipts(proj)[-1]["decision"] == "ESCALATE"


def test_the_home_directory_collapse_still_escalates(lab):
    """459e74f - abspath("~/a") is "<cwd>/~/a", and two of those share the
    prefix "<cwd>/~", whose dirname is the working directory. That fix must
    survive the base moving under it."""
    proj, sub = lab
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm -f ~/x1 ~/x2"},
        "cwd": str(sub), "session_id": "s"})), out)
    assert _receipts(proj)[-1]["decision"] == "ESCALATE"
    assert _captured(proj) == []


def test_the_size_cap_still_degrades_honestly(lab, monkeypatch):
    """The widening makes a subdirectory a capture surface, and a
    subdirectory can be node_modules. The cap bounds CORRECTNESS - past it,
    escalate with nothing captured rather than claim a partial copy."""
    proj, sub = lab
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0")
    (sub / "a.txt").write_text("A")
    (sub / "b.txt").write_text("B")
    (sub / "big.bin").write_bytes(b"x" * 200_000)
    out = io.StringIO()
    codex_hook(io.StringIO(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm a.txt b.txt"},
        "cwd": str(sub), "session_id": "s"})), out)
    last = _receipts(proj)[-1]
    assert last["decision"] == "ESCALATE", last
    assert last["recovery_point"] is None


def test_a_failed_restore_is_loud(tmp_path, monkeypatch):
    """Nothing may swallow this.

    The hook is not always a one-shot process - cli.py calls run_pretooluse
    in-process inside doctor's self-test, itself already inside a chdir - so
    a silently failed restore leaves a surviving caller standing in the
    agent's directory, with every later resolution wrong and nothing saying
    so. That is precisely the class this module closes, recreated by its own
    fix, which is why it raises rather than warns.

    Reverting it broke NOTHING until this test existed (2026-09-14).
    """
    from demo_cli.guard import agent_directory
    target = tmp_path / "elsewhere"
    target.mkdir()
    real = os.chdir
    calls = []

    def _chdir(path):
        calls.append(str(path))
        if len(calls) > 1:                      # the restore, not the entry
            raise OSError(13, "permission denied")
        real(path)

    monkeypatch.setattr(os, "chdir", _chdir)
    with pytest.raises(RuntimeError, match="working directory is now wrong"):
        with agent_directory(str(target)):
            pass
    monkeypatch.undo()
    real(str(tmp_path))


def test_entering_is_reported_separately_from_failing_to_leave(tmp_path):
    """Two different failures, two different types. "I cannot get there" is
    an escalation the adapters turn into a deny; "I cannot get back" is a
    broken process and must not be mistaken for one."""
    from demo_cli.guard import AgentDirectoryUnreachable, agent_directory
    with pytest.raises(AgentDirectoryUnreachable):
        with agent_directory(str(tmp_path / "never-existed")):
            pass

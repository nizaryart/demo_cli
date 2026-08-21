"""Codex PreToolUse adapter: same core, different host contract.

Locks the four decisions that make this adapter different from the Claude Code
one - no `ask`, apply_patch not gated, argv-list unwrapping, fail-open - and the
install path into .codex/hooks.json.
"""
import glob
import io
import json
import os

from demo_cli.decide import CONTEXT_MISMATCH, ESCALATE, REVERSIBLE
from demo_cli.hooks.codex import (HOOK_COMMAND, _command_text, _decide_permission,
                                  _patch_targets, install_into_hooks_json,
                                  run_pretooluse, settings_snippet)


def _run(payload, tmp_path, mode="enforce"):
    (tmp_path / ".demo_cli.toml").write_text(f'mode = "{mode}"\n')
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    return rc, out.getvalue()


def _shell(command, tmp_path):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": str(tmp_path),
            "session_id": "s1", "turn_id": "t1"}


def _decision(raw):
    return json.loads(raw)["hookSpecificOutput"]["permissionDecision"]


def _snapshots(tmp_path):
    """Recovery points captured under the sandbox project."""
    return sorted(glob.glob(str(tmp_path / ".demo_cli" / "recovery" / "*.bak")) +
                  glob.glob(str(tmp_path / ".demo_cli" / "recovery" / "*.snapdir")))


def _receipts(tmp_path):
    p = tmp_path / ".demo_cli" / "receipts.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


# --------------------------------------------------------------------------
# End-to-end through the real Guard
# --------------------------------------------------------------------------

def test_codex_denies_unresolvable_rm_rf(tmp_path):
    rc, raw = _run(_shell("rm -rf /srv/data", tmp_path), tmp_path)
    assert rc == 0
    assert _decision(raw) == "deny"


def test_codex_snapshots_a_resolvable_target_and_stays_silent(tmp_path):
    # Codex rejects permissionDecision:"allow" at runtime, so the proof of an
    # allowed action is the SNAPSHOT + RECEIPT, not a reply. Silence = proceed.
    build = tmp_path / "build"
    build.mkdir()
    (build / "out.txt").write_text("artifact")
    rc, raw = _run(_shell(f"rm -rf {build}", tmp_path), tmp_path)
    assert rc == 0
    assert raw == ""
    assert _snapshots(tmp_path), "a recovery point must exist before the delete"
    assert _receipts(tmp_path)[-1]["decision"] == "REVERSIBLE"


def test_codex_safe_read_is_silent(tmp_path):
    _, raw = _run(_shell("SELECT 1", tmp_path), tmp_path)
    assert raw == ""
    assert _receipts(tmp_path)[-1]["decision"] == "ALLOW"


def test_codex_shadow_mode_emits_nothing(tmp_path):
    rc, raw = _run(_shell("rm -rf /srv/data", tmp_path), tmp_path, mode="shadow")
    assert rc == 0
    assert raw == ""          # emitting nothing is the safest "proceed"


def test_codex_never_emits_ask(tmp_path):
    # Codex parses and REJECTS "ask", marking the hook failed - which fails open.
    # Emitting it would let a command run while the receipt claimed we asked.
    for cmd in ("rm -rf /srv/data", "SELECT 1", "echo hello"):
        _, raw = _run(_shell(cmd, tmp_path), tmp_path)
        assert '"ask"' not in raw


# --------------------------------------------------------------------------
# The decision mapping, in isolation (pure)
# --------------------------------------------------------------------------

def test_escalate_maps_to_deny():
    assert _decide_permission(ESCALATE, []) == ("deny", None)


def test_reversible_maps_to_plain_allow():
    assert _decide_permission(REVERSIBLE, []) == ("allow", None)


def test_context_mismatch_maps_to_allow_with_context():
    # No `ask` on Codex: the snapshot was taken, so the honest move is to let it
    # proceed and TELL the agent, not to silently fail open pretending we asked.
    permission, context = _decide_permission(
        CONTEXT_MISMATCH, [("environment", "development", "production")])
    assert permission == "allow"
    assert context is not None
    assert "does not match" in context
    assert "production" in context


# --------------------------------------------------------------------------
# Command shape: string or argv list (finding #010a, new host)
# --------------------------------------------------------------------------

def test_argv_list_bash_wrapper_is_unwrapped():
    assert _command_text({"command": ["bash", "-lc", "rm -rf build"]}) == "rm -rf build"


def test_argv_list_without_wrapper_is_joined():
    assert _command_text({"command": ["rm", "-rf", "build"]}) == "rm -rf build"


def test_plain_string_command_is_used_as_is():
    assert _command_text({"command": "  rm -rf build  "}) == "rm -rf build"


def test_argv_list_wrapper_command_is_classified_end_to_end(tmp_path):
    payload = _shell(["bash", "-lc", "rm -rf /srv/data"], tmp_path)
    _, raw = _run(payload, tmp_path)
    assert _decision(raw) == "deny"        # the wrapper alone would match no rule


# --------------------------------------------------------------------------
# apply_patch: gated via the patch's own grammar
# --------------------------------------------------------------------------

def _patch(patch_text, tmp_path):
    return {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
            "tool_input": {"command": patch_text}, "cwd": str(tmp_path),
            "session_id": "s1", "turn_id": "t1"}


def test_patch_targets_parses_every_operation():
    text = ("*** Begin Patch\n"
            "*** Add File: /a/new.txt\n+hi\n"
            "*** Update File: /a/old.txt\n@@\n-x\n+y\n"
            "*** Delete File: /a/gone.txt\n"
            "*** Move to: /a/moved.txt\n"
            "*** End Patch")
    assert _patch_targets(text) == [
        ("Add File", "/a/new.txt"),
        ("Update File", "/a/old.txt"),
        ("Delete File", "/a/gone.txt"),
        ("Move to", "/a/moved.txt"),
    ]


def test_patch_targets_ignores_diff_body_lines():
    # `+*** Update File: x` inside a diff body is content, not an operation.
    text = "*** Begin Patch\n*** Update File: /a/f.txt\n@@\n-a\n+b\n*** End Patch"
    assert _patch_targets(text) == [("Update File", "/a/f.txt")]


def test_apply_patch_update_snapshots_the_existing_file(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("hi\n")
    text = f"*** Begin Patch\n*** Update File: {f}\n@@\n-hi\n+bye\n*** End Patch"
    rc, raw = _run(_patch(text, tmp_path), tmp_path)
    assert rc == 0
    assert raw == ""                                    # silence = proceed
    snaps = _snapshots(tmp_path)
    assert len(snaps) == 1
    assert open(snaps[0]).read() == "hi\n", "must capture the PRE-edit content"


def test_apply_patch_delete_snapshots_before_removal(tmp_path):
    f = tmp_path / "doomed.txt"
    f.write_text("precious\n")
    text = f"*** Begin Patch\n*** Delete File: {f}\n*** End Patch"
    _, raw = _run(_patch(text, tmp_path), tmp_path)
    assert raw == ""
    assert open(_snapshots(tmp_path)[0]).read() == "precious\n"


def test_apply_patch_add_only_takes_no_snapshot(tmp_path):
    # Creating a file destroys nothing - there is nothing to capture.
    text = f"*** Begin Patch\n*** Add File: {tmp_path/'brand-new.txt'}\n+hi\n*** End Patch"
    _, raw = _run(_patch(text, tmp_path), tmp_path)
    assert raw == ""
    assert _snapshots(tmp_path) == []
    assert _receipts(tmp_path)[-1]["decision"] == "ALLOW"


def test_apply_patch_multi_operation_snapshots_every_existing_file(tmp_path):
    # A single patch can carry several operations (observed live). Account for
    # ALL of them or refuse - the FIX #5 discipline.
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("A\n")
    b.write_text("B\n")
    text = (f"*** Begin Patch\n*** Update File: {a}\n@@\n-A\n+A2\n"
            f"*** Delete File: {b}\n*** End Patch")
    _, raw = _run(_patch(text, tmp_path), tmp_path)
    assert raw == ""
    assert len(_snapshots(tmp_path)) == 2, "both files, or refuse - never a subset"


def test_apply_patch_unparseable_is_denied(tmp_path):
    # A write we cannot account for gets no recovery point, so it escalates -
    # same rule decide.py applies everywhere else.
    _, raw = _run(_patch("*** Begin Patch\n(garbled)\n*** End Patch", tmp_path), tmp_path)
    assert _decision(raw) == "deny"
    assert "could not be parsed" in json.loads(raw)["hookSpecificOutput"]["permissionDecisionReason"]


def test_apply_patch_shadow_mode_still_snapshots_but_never_blocks(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("hi\n")
    text = f"*** Begin Patch\n*** Update File: {f}\n@@\n-hi\n+bye\n*** End Patch"
    rc, raw = _run(_patch(text, tmp_path), tmp_path, mode="shadow")
    assert rc == 0
    assert raw == ""                                   # never steers Codex
    assert (tmp_path / ".demo_cli" / "recovery").exists()   # but did capture


# --------------------------------------------------------------------------
# Replay of REAL payloads captured from Codex 0.147.0 (tests/fixtures/codex/)
# --------------------------------------------------------------------------

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "codex")


def test_real_payload_fixtures_are_present():
    assert len(glob.glob(os.path.join(FIXTURES, "*.json"))) == 7


def test_every_real_payload_is_handled_without_crashing(tmp_path):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
        payload = json.load(open(path, encoding="utf-8"))
        payload["cwd"] = str(tmp_path)          # retarget onto the sandbox
        out = io.StringIO()
        assert run_pretooluse(io.StringIO(json.dumps(payload)), out) == 0
        raw = out.getvalue()
        if raw:                                  # if it spoke, it spoke valid JSON
            assert json.loads(raw)["hookSpecificOutput"]["permissionDecision"] in ("allow", "deny")
            assert '"ask"' not in raw


def test_real_payload_shape_matches_what_the_adapter_assumes():
    # Locks the two facts the adapter is built on. If a Codex upgrade changes
    # either, this fails loudly instead of the adapter silently missing commands.
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
        d = json.load(open(path, encoding="utf-8"))
        assert d["tool_name"] in ("Bash", "apply_patch")
        assert isinstance(d["tool_input"]["command"], str)


def test_real_safe_command_is_silently_allowed(tmp_path):
    payload = json.load(open(os.path.join(FIXTURES, "02-Bash.json"), encoding="utf-8"))
    payload["cwd"] = str(tmp_path)
    _, raw = _run(payload, tmp_path)
    assert raw == ""
    assert _receipts(tmp_path)[-1]["decision"] == "ALLOW"


def test_adapter_never_emits_a_decision_codex_rejects(tmp_path):
    # Codex's runtime accepts ONLY "deny"; "allow" and "ask" mark the hook as
    # failed and print an error on every tool call. Lock that: any output we
    # produce must be a deny, on every real payload we have.
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
        payload = json.load(open(path, encoding="utf-8"))
        payload["cwd"] = str(tmp_path)
        out = io.StringIO()
        run_pretooluse(io.StringIO(json.dumps(payload)), out)
        raw = out.getvalue()
        if raw:
            assert _decision(raw) == "deny", f"{os.path.basename(path)} emitted a non-deny"


def test_real_rm_outside_project_root_is_denied(tmp_path):
    # The captured `rm` names an absolute path outside this project root, so no
    # recovery point can be captured for it - deny, never a false REVERSIBLE.
    payload = json.load(open(os.path.join(FIXTURES, "07-Bash.json"), encoding="utf-8"))
    payload["cwd"] = str(tmp_path)
    _, raw = _run(payload, tmp_path)
    assert _decision(raw) == "deny"


# --------------------------------------------------------------------------
# Tools we deliberately do not gate
# --------------------------------------------------------------------------

def test_mcp_tool_steps_aside(tmp_path):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_issue",
               "tool_input": {"title": "x"}, "cwd": str(tmp_path)}
    rc, raw = _run(payload, tmp_path)
    assert rc == 0
    assert raw == ""


# --------------------------------------------------------------------------
# Fail-open on our own errors
# --------------------------------------------------------------------------

def test_unparseable_stdin_steps_aside():
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO("{not json"), out)
    assert rc == 0
    assert out.getvalue() == ""


def test_empty_stdin_steps_aside():
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(""), out)
    assert rc == 0
    assert out.getvalue() == ""


def test_empty_command_steps_aside(tmp_path):
    rc, raw = _run(_shell("", tmp_path), tmp_path)
    assert rc == 0
    assert raw == ""


# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

def _handlers(pre):
    """Every handler across every PreToolUse group (Codex's nested shape)."""
    return [h for g in pre for h in (g.get("hooks") or [])]


def test_snippet_uses_codex_nested_shape():
    # The flat [{"command": ...}] form is silently IGNORED by Codex - installed,
    # reported as success, and completely inert. Lock the real shape.
    entry = settings_snippet()["hooks"]["PreToolUse"][0]
    assert "hooks" in entry, "handlers must be nested under a group"
    handler = entry["hooks"][0]
    assert handler["type"] == "command", "'type' is mandatory or Codex ignores it"
    assert handler["command"] == HOOK_COMMAND
    assert "matcher" not in entry, "no matcher = every tool, incl. apply_patch"


def test_install_writes_hooks_json(tmp_path):
    path = str(tmp_path / ".codex" / "hooks.json")
    install_into_hooks_json(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert any(h["command"] == HOOK_COMMAND and h["type"] == "command"
               for h in _handlers(data["hooks"]["PreToolUse"]))


def test_install_is_idempotent(tmp_path):
    path = str(tmp_path / ".codex" / "hooks.json")
    install_into_hooks_json(path)
    install_into_hooks_json(path)
    pre = json.loads(open(path, encoding="utf-8").read())["hooks"]["PreToolUse"]
    assert sum(1 for h in _handlers(pre) if h["command"] == HOOK_COMMAND) == 1


def test_install_preserves_existing_events(tmp_path):
    path = str(tmp_path / ".codex" / "hooks.json")
    os.makedirs(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"hooks": {"PostToolUse": [{"command": "./audit.sh"}]}}, f)
    install_into_hooks_json(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert "PostToolUse" in data["hooks"]
    assert "PreToolUse" in data["hooks"]

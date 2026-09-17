r"""The tool told people to raise a number nothing could raise.

Both snapshot-cap refusals ended with "Raise DEMO_CLI_MAX_SNAPSHOT_FILES and
the hook timeout together". DEMO_CLI_MAX_SNAPSHOT_FILES existed. The hook
timeout was a module constant - no env var, no config key, no CLI flag, and
until 2026-09-17 no installer path that would rewrite an existing entry. The
only route was hand-editing the host's JSON, which is how a BOM gets in and
how the whole H1 data-loss finding started.

    ADVICE YOU CANNOT FOLLOW IS THE SAME DEFECT AS A REFUSAL THAT NAMES NO
    KNOB AT ALL, AND IT WAS SHIPPED IN THE COMMIT THAT FIXED THE SECOND ONE.

That commit (C1, "a cap refusal reached one door of three") replaced "Could not
snapshot the file" with a message naming the cause and the knob - and the knob
it named for the timeout half did not exist. Found by the subagent audit, not
by the suite.

TWO LITERALS, ONE NUMBER. Claude Code had `_HOOK_TIMEOUT = 120`; Codex had an
inline `"timeout": 120` tied to nothing. The snapshot cap is sized against this
budget in test_snapshot_file_cap, which read CODEX's copy - so editing one
host's literal silently re-sized the safety margin for the other. There is now
one hooks.hook_timeout().

AND IT ONLY REACHES THE HOST ON RE-INSTALL, because the value lives in the
host's config file rather than in our process. The message has to say so or it
is unfollowable again in a subtler way.
"""
import json
import os

import pytest

from demo_cli import checkpoint, recovery
from demo_cli.config import Config
from demo_cli.hooks import _DEFAULT_HOOK_TIMEOUT, hook_timeout
from demo_cli.hooks import claude_code, codex
from demo_cli.hooks.claude_code import install_into_settings


def _snippet_timeouts(mod, event):
    snip = mod.settings_snippet()["hooks"][event]
    return [h["timeout"] for g in snip for h in g["hooks"]]


# ------------------------------------------------------------ the knob

def test_the_default_is_the_measured_budget(monkeypatch):
    monkeypatch.delenv("DEMO_CLI_HOOK_TIMEOUT", raising=False)
    assert hook_timeout() == _DEFAULT_HOOK_TIMEOUT == 120


def test_the_knob_is_honoured(monkeypatch):
    monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", "300")
    assert hook_timeout() == 300


@pytest.mark.parametrize("raw", ["", "nonsense", "nan", "inf", "-5", "0",
                                 "0.5", None])
def test_nonsense_falls_back_to_the_default(monkeypatch, raw):
    """Parsed as defensively as the snapshot caps, and for the same reason: a
    typo must not shrink the budget a SILENT failure is measured against.
    Zero is refused here where the byte cap allows it - "no timeout" is the
    host's own ambiguous default, which is the thing this declaration exists
    to replace."""
    if raw is None:
        monkeypatch.delenv("DEMO_CLI_HOOK_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", raw)
    assert hook_timeout() == _DEFAULT_HOOK_TIMEOUT


# ------------------------------------------------------- one number, two hosts

def test_both_hosts_read_the_same_knob(monkeypatch):
    """THE DRIFT. Two independent literals, and the cap test read one of them."""
    monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", "247")
    assert _snippet_timeouts(claude_code, "PreToolUse") == [247, 247, 247]
    assert _snippet_timeouts(codex, "PreToolUse") == [247]


def test_no_host_carries_its_own_timeout_literal():
    """Grepped, because a constant that is 'shared' by being copied is the
    thing this commit removes. _DEFAULT_HOOK_TIMEOUT may appear once, in the
    package that owns it."""
    import pathlib
    root = pathlib.Path(recovery.__file__).parent / "hooks"
    for name in ("claude_code.py", "codex.py"):
        text = (root / name).read_text(encoding="utf-8")
        body = "\n".join(l for l in text.splitlines()
                         if not l.strip().startswith("#"))
        assert '"timeout": 120' not in body, f"{name} still hardcodes a budget"
        assert "_HOOK_TIMEOUT" not in body, f"{name} kept its own constant"


# ------------------------------------------------------- it reaches the host

def test_the_knob_reaches_an_installed_config(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", "400")
    p = str(tmp_path / ".claude" / "settings.json")
    install_into_settings(p)
    blocks = json.loads(open(p, encoding="utf-8").read())["hooks"]["PreToolUse"]
    assert {h["timeout"] for b in blocks for h in b["hooks"]} == {400}


def test_raising_the_knob_makes_an_existing_install_stale(tmp_path, monkeypatch):
    """The knob, the reconcile and the audit have to agree or the advice is
    still unfollowable: doctor must SEE the gap the user just created."""
    from demo_cli.cli import _hook_check_rows
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("os.path.expanduser", lambda s: s.replace("~", str(home), 1))
    proj = tmp_path / "P"
    proj.mkdir()
    install_into_settings(str(proj / ".claude" / "settings.json"))

    def row():
        return [r for r in _hook_check_rows(Config(project_root=str(proj)))
                if r[1] == "hook: claude code"][0]

    assert row()[0] == "ok"
    monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", "600")
    assert row()[0] == "warn", "doctor did not notice the raised knob"
    assert "current 600" in row()[2]

    install_into_settings(str(proj / ".claude" / "settings.json"))
    assert row()[0] == "ok", "the reconcile did not apply the new knob"


# ------------------------------------------------------- the advice is followable

def test_the_file_cap_refusal_names_a_knob_that_exists(tmp_path, monkeypatch):
    """The whole point. The sentence used to name 'the hook timeout'."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "1")
    d = tmp_path / "tree"
    d.mkdir()
    for i in range(3):
        (d / f"f{i}.txt").write_text("x")
    notes = {}
    recovery.snapshot(recovery.Target(kind="dir", ref=str(d), label="t"),
                      str(tmp_path / "rec"), "snapshot", notes=notes)
    msg = notes["refused"]
    assert "DEMO_CLI_HOOK_TIMEOUT" in msg, msg
    assert "the hook timeout together" not in msg, "the old dead phrasing survived"
    assert "install-hook" in msg, (
        "raising the env var alone changes nothing - the value lives in the "
        "host's config, so the message must say to re-install")


def test_the_checkpoint_refusal_names_it_too(monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "1")
    msg = checkpoint.reason_text(checkpoint.TOO_MANY_FILES, Config())
    assert "DEMO_CLI_HOOK_TIMEOUT" in msg
    assert "install-hook" in msg


def test_every_env_knob_the_refusals_name_is_real(tmp_path, monkeypatch):
    """A refusal may only name variables the code actually reads. This is the
    check that would have caught the dead name the day it shipped."""
    import re
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "1")
    d = tmp_path / "tree"
    d.mkdir()
    (d / "a.txt").write_text("x")
    (d / "b.txt").write_text("x")
    notes = {}
    recovery.snapshot(recovery.Target(kind="dir", ref=str(d), label="t"),
                      str(tmp_path / "rec"), "snapshot", notes=notes)

    texts = [notes["refused"],
             checkpoint.reason_text(checkpoint.TOO_MANY_FILES, Config()),
             checkpoint.reason_text(checkpoint.TOO_LARGE, Config())]
    named = {n for t in texts for n in re.findall(r"DEMO_CLI_[A-Z_]+", t)}
    assert named, "no knob was named at all"

    import pathlib
    src = pathlib.Path(recovery.__file__).parent
    read = set()
    for f in src.rglob("*.py"):
        read |= set(re.findall(r'environ\.get\(\s*"(DEMO_CLI_[A-Z_]+)"',
                               f.read_text(encoding="utf-8")))
    assert named <= read, f"refusals name knobs nothing reads: {named - read}"

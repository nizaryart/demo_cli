r"""The install path rewrote the whole file, and treated a file it could not
read as an empty one.

    # claude_code.py, codex.py, cursor.py - all three, identically
    try:
        settings = json.load(f)
    except Exception:
        settings = {}          # <- then json.dump over the original

So an unparseable host config was REPLACED by one containing only our hooks.
On a real machine that file holds permissions, model, plugins, marketplaces
and additionalDirectories - around a hundred entries on the Windows box this
was found on. Gone, silently, exit 0, with "Installed..." printed.

THE MOST LIKELY CAUSE WAS THE ONE WE ALREADY KNEW ABOUT. The installers read
`encoding="utf-8"`, while doctor (_hook_installed) and teardown (_remove_hooks)
both read `utf-8-sig`. A settings.json written by PowerShell's `Out-File` has
a BOM, so it was readable by the two paths that only LOOK at it and unparseable
by the one that REWRITES it. This project's fourth BOM incident, after the
config parser, the Codex payload and the timeout lab.

AND THE RULE WAS ALREADY WRITTEN DOWN, TWELVE HUNDRED LINES AWAY:

    cli.py, _remove_hooks:
        except Exception:
            continue        # a config we cannot parse is one we must not rewrite

Teardown obeyed it. Install - the destructive direction - did not.

Three more shapes crashed with a bare AttributeError out of the CLI, because
`setdefault`/`append` were called on whatever the JSON happened to contain:
`{"hooks": []}`, `{"hooks": {"PreToolUse": {}}}`, and a non-dict inside a
handler list (Claude Code's _present omitted the isinstance guard that Codex's
_declares_our_hook has).

An empty file is deliberately NOT a refusal: it holds nothing to lose, and
erroring on `touch settings.json` would be a message with no cause.
"""
import json
import os
import types

import pytest

from demo_cli.hooks import HostConfigUnreadable
from demo_cli.hooks.claude_code import install_into_settings
from demo_cli.hooks.codex import install_into_hooks_json as codex_install
from demo_cli.hooks.cursor import install_into_hooks_json as cursor_install

# A stand-in for the real thing: the keys that were actually lost.
USER_SETTINGS = {
    "permissions": {"allow": ["Read", "Bash(git *)"], "deny": ["Bash(sudo *)"]},
    "model": "sonnet",
    "enabledPlugins": {"obsidian@obsidian-skills": True},
    "effortLevel": "medium",
}


@pytest.fixture
def claude(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    return str(d / "settings.json")


def _write(path, text, bom=False):
    with open(path, "wb") as f:
        if bom:
            f.write(b"\xef\xbb\xbf")
        f.write(text.encode("utf-8"))


def _read(path):
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------- the data loss, both ways

def test_a_bom_no_longer_destroys_the_users_settings(claude):
    """THE DEFECT. A BOM'd but perfectly VALID file was the realistic case:
    it parsed for doctor, failed for install, and was overwritten."""
    _write(claude, json.dumps(USER_SETTINGS), bom=True)
    install_into_settings(claude)

    after = json.loads(open(claude, encoding="utf-8-sig").read())
    assert after["model"] == "sonnet", "the user's settings were replaced"
    assert after["permissions"] == USER_SETTINGS["permissions"]
    assert after["enabledPlugins"] == USER_SETTINGS["enabledPlugins"]
    assert [b["matcher"] for b in after["hooks"]["PreToolUse"]] == [
        "Bash", "PowerShell", "Edit|Write|MultiEdit|NotebookEdit"]


def test_an_unparseable_config_is_refused_and_left_alone(claude):
    """And when it genuinely cannot be read, nothing is written at all."""
    _write(claude, '{"model": "sonnet", }')      # trailing comma
    before = _read(claude)
    with pytest.raises(HostConfigUnreadable):
        install_into_settings(claude)
    assert _read(claude) == before, "the file was rewritten anyway"


def test_the_refusal_says_what_to_do_about_it(claude):
    _write(claude, "{not json at all")
    with pytest.raises(HostConfigUnreadable) as exc:
        install_into_settings(claude)
    msg = str(exc.value)
    assert "will NOT rewrite it" in msg
    assert "BOM" in msg, "the usual cause went unnamed"
    assert claude in msg, "the message did not name the file"


def test_a_json_array_is_refused(claude):
    _write(claude, '["not", "an", "object"]')
    with pytest.raises(HostConfigUnreadable):
        install_into_settings(claude)


# ------------------------------------------------- the three crash shapes

@pytest.mark.parametrize("shape", [
    '{"hooks": []}',
    '{"hooks": {"PreToolUse": {}}}',
    '{"hooks": {"PreToolUse": "nonsense"}}',
])
def test_a_container_of_the_wrong_shape_is_refused_not_crashed(claude, shape):
    """These three raised AttributeError straight out of the CLI."""
    _write(claude, shape)
    before = _read(claude)
    with pytest.raises(HostConfigUnreadable):
        install_into_settings(claude)
    assert _read(claude) == before


def test_a_non_dict_handler_is_skipped_not_crashed(claude):
    """A stray non-dict beside our handler must not stop the install - it is
    something we only READ, unlike the containers above."""
    _write(claude, json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": ["a bare string", None]}]}}))
    install_into_settings(claude)
    blocks = json.loads(open(claude, encoding="utf-8").read())["hooks"]["PreToolUse"]
    assert sum(1 for b in blocks if b.get("matcher") == "Bash") == 2, (
        "the existing block held no handler of ours, so ours had to be added")


# ------------------------------------------------- the deliberate non-refusal

@pytest.mark.parametrize("text", ["", "   \n  "])
def test_an_empty_file_is_treated_as_absent(claude, text):
    _write(claude, text)
    install_into_settings(claude)
    after = json.loads(open(claude, encoding="utf-8").read())
    assert len(after["hooks"]["PreToolUse"]) == 3


def test_a_missing_file_is_still_created(claude):
    assert not os.path.exists(claude)
    install_into_settings(claude)
    assert os.path.exists(claude)


def test_an_ordinary_valid_config_still_merges(claude):
    _write(claude, json.dumps(USER_SETTINGS))
    install_into_settings(claude)
    after = json.loads(open(claude, encoding="utf-8").read())
    assert after["model"] == "sonnet"
    assert "hooks" in after


# ------------------------------------------------- the other two hosts

def test_codex_is_refused_too(tmp_path):
    p = tmp_path / ".codex" / "hooks.json"
    p.parent.mkdir()
    _write(str(p), '{"hooks": {"PreToolUse": [}}')
    before = _read(str(p))
    with pytest.raises(HostConfigUnreadable):
        codex_install(str(p))
    assert _read(str(p)) == before


def test_codex_keeps_a_bom_users_other_events(tmp_path):
    p = tmp_path / ".codex" / "hooks.json"
    p.parent.mkdir()
    _write(str(p), json.dumps({"hooks": {"PostToolUse": [{"hooks": [
        {"type": "command", "command": "their-own-tool"}]}]}}), bom=True)
    codex_install(str(p))
    after = json.loads(open(str(p), encoding="utf-8-sig").read())
    assert "PostToolUse" in after["hooks"], "another event was dropped"
    assert "PreToolUse" in after["hooks"]


def test_cursor_is_refused_too(tmp_path):
    p = tmp_path / ".cursor" / "hooks.json"
    p.parent.mkdir()
    _write(str(p), "nonsense")
    with pytest.raises(HostConfigUnreadable):
        cursor_install(str(p))


def test_cursor_still_writes_its_schema_version(tmp_path):
    p = tmp_path / ".cursor" / "hooks.json"
    cursor_install(str(p))
    assert json.loads(open(str(p), encoding="utf-8").read())["version"] == 1


# ------------------------------------------------- the CLI must not traceback

def test_the_cli_reports_the_refusal_instead_of_a_traceback(tmp_path, monkeypatch,
                                                            capsys):
    from demo_cli.cli import cmd_install_hook
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude").mkdir()
    _write(str(tmp_path / ".claude" / "settings.json"), "{broken")

    rc = cmd_install_hook(types.SimpleNamespace(
        codex=False, cursor=False, print=False, scope="project"))
    assert rc == 1, "a refused install reported success"
    out = capsys.readouterr().out
    assert "demo_cli:" in out and "will NOT rewrite it" in out
    assert "Installed" not in out, "it claimed to have installed something"

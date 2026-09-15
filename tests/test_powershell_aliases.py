"""PowerShell's aliases are real commands, and four of them were invisible.

`del`, `erase`, `rd` and `rmdir` are all Remove-Item in PowerShell and need no
flag. The only rules covering those words were written for cmd.exe:

    del_force   \\bdel\\b.*\\/[fFsS]      cmd.exe DEL requires /f or /s
    rmdir_s     \\brmdir\\b.*\\/[sS]      cmd.exe RMDIR requires /s

so `del app.db` on Windows matched nothing at all and was ALLOWed. The most
common destructive verb an agent writes, with nothing captured and nothing
claimed.

The alias set comes from `Get-Alias` on Windows PowerShell 5.1 (2026-09-15),
not from memory - the handoff's list included `ci`, which is not an alias at
all (`cli` is Clear-Item, `cpi` is Copy-Item).
"""
import pytest

from demo_cli import recovery
from demo_cli.classify import POSIX, POWERSHELL, classify_pipeline
from demo_cli.config import Config
from demo_cli.decide import ALLOW, REVERSIBLE
from demo_cli.guard import Guard

DELETE_ALIASES = ["del app.db", "erase app.db", "rd dist", "rmdir dist",
                  "ri app.db"]
FORCE_ALIASES = [("cpi -Force a b", "ps_copy_force"),
                 ("copy -Force a b", "ps_copy_force"),
                 ("cp -Force a b", "ps_copy_force"),
                 ("mi -Force a b", "ps_move_force"),
                 ("move -Force a b", "ps_move_force"),
                 ("ren -Force a b", "ps_rename_force"),
                 ("rni -Force a b", "ps_rename_force"),
                 ("ni -Force f.txt", "ps_new_item_force"),
                 ("clc log.txt", "ps_clear_content")]


@pytest.mark.parametrize("cmd", DELETE_ALIASES)
def test_delete_aliases_are_remove_item_in_powershell(cmd):
    c = classify_pipeline(cmd, POWERSHELL)
    assert c.is_destructive is True
    assert c.matched_rule == "ps_remove_item", c.matched_rule


@pytest.mark.parametrize("cmd", DELETE_ALIASES)
def test_delete_aliases_are_inert_on_posix(cmd):
    assert classify_pipeline(cmd, POSIX).is_destructive is False


@pytest.mark.parametrize("cmd,rule", FORCE_ALIASES)
def test_force_aliases_in_powershell(cmd, rule):
    c = classify_pipeline(cmd, POWERSHELL)
    assert c.is_destructive is True, cmd
    assert c.matched_rule == rule, (cmd, c.matched_rule)


@pytest.mark.parametrize("cmd,_rule", FORCE_ALIASES)
def test_force_aliases_are_inert_on_posix(cmd, _rule):
    assert classify_pipeline(cmd, POSIX).is_destructive is False, cmd


def test_cmd_exe_hard_stops_keep_precedence():
    # rmdir_s and del_force carry recursive_force_delete, a hard stop in every
    # environment. The new alias rules sit AFTER them in the table so a
    # cmd.exe-shaped command cannot be downgraded to a recoverable delete.
    for cmd in ["rmdir /s /q build", "del /s /q build"]:
        for d in (POSIX, POWERSHELL):
            c = classify_pipeline(cmd, d)
            assert c.nonrecoverable_surface == "recursive_force_delete", (cmd, d)


def test_recurse_force_alias_keeps_the_higher_signal_id():
    c = classify_pipeline("del -Recurse -Force dist", POWERSHELL)
    assert c.matched_rule == "ps_remove_item_rf"


def test_sc_is_still_left_alone():
    # Set-Content on 5.1, sc.exe on PowerShell 7, and `sc.exe /?` does not list
    # all its own verbs (`delete` is missing), so no verb list separates them.
    for d in (POSIX, POWERSHELL):
        assert classify_pipeline('sc f.txt "x"', d).is_destructive is False
        assert classify_pipeline("sc query", d).is_destructive is False
    # sc.exe's own resume-index option carries the letters "ri" - the anchor is
    # what keeps the Remove-Item alias off it.
    assert classify_pipeline("sc query ri= 14", POWERSHELL).is_destructive is False


def test_recovery_resolves_the_alias_target(tmp_path):
    f = tmp_path / "app.db"
    f.write_text("x")
    assert recovery.extract_path_operand(f"del {f}", POWERSHELL) == str(f)
    assert recovery.extract_path_operand(f"rd {f}", POWERSHELL) == str(f)
    assert recovery.extract_path_operand(f"del {f}", POSIX) is None
    assert recovery.is_fs_delete(f"del {f}", POWERSHELL) is True
    assert recovery.is_fs_delete(f"del {f}", POSIX) is False


def test_posix_copy_does_not_count_as_a_destructive_step(tmp_path):
    # _PS_DEST_ALIAS_RE feeds the multiplicity counter. Ungated, `cp a b` would
    # count as a second acting segment on POSIX and escalate an ordinary
    # `rm x; cp a b` that snapshots perfectly well today.
    f = tmp_path / "old.txt"
    f.write_text("x")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"rm {f} && cp a.txt b.txt", dialect=POSIX)
    assert r.recovery_entry is not None
    assert r.decision.decision == REVERSIBLE


def test_powershell_delete_alias_is_snapshotted_end_to_end(tmp_path):
    # The prize: `del app.db` used to be ALLOW with nothing captured.
    f = tmp_path / "app.db"
    f.write_text("keep me")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"del {f}", dialect=POWERSHELL)
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_posix_delete_alias_stays_allowed_end_to_end(tmp_path):
    (tmp_path / "app.db").write_text("x")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    assert g.evaluate("del app.db", dialect=POSIX).decision.decision == ALLOW

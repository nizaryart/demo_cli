"""PowerShell's short aliases are only aliases in PowerShell.

`ri` is Remove-Item in PowerShell and Ruby's documentation viewer on POSIX, and
the rule table matched both. `classify_pipeline` computed each segment's
dialect and then discarded it, so the rules were judged blind.

The dialect the segments carry is not always the outer one:
`powershell.exe -Command "ri x"` run from Claude Code's Bash tool arrives as
POSIX, and effective_segments re-dialects the payload correctly. Measured on
Windows 2026-09-15 - Claude Code's Bash tool there is Git Bash, so POSIX is the
truthful answer for the outer shell and the nested payload still has to be
judged as PowerShell.

recovery.py is gated identically. If the two disagree, one module calls a
command a deletion while the other looks for its target in text that does not
describe one.
"""
from demo_cli import recovery
from demo_cli.classify import POSIX, POWERSHELL, classify_pipeline
from demo_cli.config import Config
from demo_cli.decide import ALLOW
from demo_cli.guard import Guard

ALIASES = ["ri app.db", "ri -Recurse -Force dist", "clc log.txt"]
CMDLETS = ["Remove-Item app.db", "Remove-Item -Recurse -Force dist",
           "Clear-Content log.txt"]


def test_aliases_are_inert_on_posix():
    for cmd in ALIASES:
        c = classify_pipeline(cmd, POSIX)
        assert c.is_destructive is False, cmd
        assert c.matched_rule is None, cmd


def test_aliases_fire_on_powershell():
    for cmd in ALIASES:
        assert classify_pipeline(cmd, POWERSHELL).is_destructive is True, cmd


def test_full_cmdlet_names_are_not_gated():
    # Unambiguous in any shell, so gating them would buy nothing and cost a
    # miss whenever an adapter's dialect guess is wrong.
    for cmd in CMDLETS:
        for d in (POSIX, POWERSHELL):
            assert classify_pipeline(cmd, d).is_destructive is True, (cmd, d)


def test_ri_doc_viewer_is_released():
    # The command that started this: Ruby's doc viewer, escalating on POSIX.
    c = classify_pipeline("ri Array#each", POSIX)
    assert c.is_destructive is False
    assert c.is_mutating is False


def test_nested_powershell_from_bash_is_still_caught():
    # The outer shell is POSIX and the payload is not. This is what Claude Code
    # on Windows actually produces.
    for cmd in ['powershell.exe -Command "ri app.db"',
                'powershell -Command "ri app.db"',
                'pwsh -c "ri app.db"',
                'powershell.exe -NoProfile -Command "ri app.db"']:
        c = classify_pipeline(cmd, POSIX)
        assert c.is_destructive is True, cmd
        assert c.matched_rule == "ps_remove_item", (cmd, c.matched_rule)


def test_segments_carry_their_own_dialect_in_recovery_too(tmp_path):
    # recovery must agree with classify about what the command IS.
    f = tmp_path / "app.db"
    f.write_text("x")
    nested = f'powershell.exe -Command "ri {f}"'
    assert recovery.extract_path_operand(nested, POSIX) == str(f)
    assert recovery.is_fs_delete(f"ri {f}", POWERSHELL) is True
    assert recovery.is_fs_delete(f"ri {f}", POSIX) is False


def test_posix_ri_is_allowed_end_to_end(tmp_path):
    (tmp_path / "app.db").write_text("x")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate("ri Array#each", dialect=POSIX)
    assert r.decision.decision == ALLOW
    assert r.recovery_entry is None


def test_powershell_ri_is_snapshotted_end_to_end(tmp_path):
    f = tmp_path / "app.db"
    f.write_text("x")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"ri {f}", dialect=POWERSHELL)
    assert r.recovery_entry is not None
    assert r.decision.decision != ALLOW

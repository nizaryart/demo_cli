"""PowerShell destructive cmdlets - the Windows half of the perimeter.

Before this, Windows had exactly ONE destructive rule (Remove-Item) while POSIX
had a dozen, so an agent could empty or overwrite any file unseen.

Every destructive case below is paired with its SAFE counterpart. That pairing
is the point: the perimeter has to be narrow, because a false positive gets the
guard uninstalled and an uninstalled guard has 0% coverage.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import POWERSHELL, classify_pipeline
from demo_cli.config import load_config
from demo_cli.decide import ESCALATE, REVERSIBLE
from demo_cli.guard import Guard


def _lab(tmp_path, mode="enforce"):
    (tmp_path / ".demo_cli.toml").write_text(f'mode = "{mode}"\n')
    return Guard(config=load_config(start=str(tmp_path)))


# --------------------------------------------------------------------------
# Classification: destructive forms and their safe twins
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,rule", [
    (r"Clear-Content C:\logs\app.log",              "ps_clear_content"),
    (r'Set-Content -Path C:\a.txt -Value "x"',      "ps_set_content"),
    (r"Get-Process | Out-File C:\out.txt",          "ps_set_content"),
    (r"Move-Item -Force a.txt b.txt",               "ps_move_force"),
    (r"Copy-Item -Force a.txt b.txt",               "ps_copy_force"),
    (r"Rename-Item -Force a.txt b.txt",             "ps_rename_force"),
    (r"New-Item -Force -ItemType File C:\x.txt",    "ps_new_item_force"),
    (r"Format-Volume -DriveLetter D",               "ps_format_volume"),
])
def test_destructive_powershell_is_caught(cmd, rule):
    assert classify_pipeline(cmd, POWERSHELL).matched_rule == rule


@pytest.mark.parametrize("cmd", [
    r'Add-Content C:\a.txt "more"',        # append destroys nothing
    r"Get-Content C:\a.txt",               # a read
    r"Out-File -Append C:\log.txt",        # append, not overwrite
    r"Out-File -NoClobber C:\new.txt",     # refuses to overwrite
    r"Move-Item a.txt b.txt",              # without -Force it will not clobber
    r"Copy-Item a.txt b.txt",
    r"Rename-Item a.txt b.txt",
    r"New-Item -ItemType Directory C:\d",  # makes a directory
    r"Get-Volume",                         # a read, near Format-Volume
])
def test_safe_powershell_is_not_flagged(cmd):
    c = classify_pipeline(cmd, POWERSHELL)
    assert c.matched_rule is None, f"false positive: {c.matched_rule}"
    assert not c.is_destructive


def test_short_aliases_are_deliberately_not_matched():
    """`sc` is Set-Content's alias AND the Windows Service Control tool.
    `sc query` is an ordinary read, so matching it would flag safe commands.
    Documented miss, chosen over a false positive."""
    assert classify_pipeline("sc query wuauserv", POWERSHELL).matched_rule is None


# --------------------------------------------------------------------------
# Target resolution
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,target", [
    (r"Clear-Content C:\logs\app.log",                              r"C:\logs\app.log"),
    (r'Set-Content -Path C:\a.txt -Value "hello world"',            r"C:\a.txt"),
    (r"Out-File C:\out.txt",                                        r"C:\out.txt"),
    (r'Set-Content -LiteralPath "C:\Program Files\x.txt" -Value y', r"C:\Program Files\x.txt"),
    (r"New-Item -Force -ItemType File -Path C:\x.txt",              r"C:\x.txt"),
])
def test_content_cmdlet_target_is_resolved(cmd, target):
    """-Value and friends must be skipped WITH their argument, or the value
    looks like a second target and an ordinary overwrite escalates."""
    assert recovery._ps_write_target(cmd) == target


@pytest.mark.parametrize("cmd,dest", [
    (r"Move-Item -Force a.txt b.txt",                                  "b.txt"),
    (r"Copy-Item -Force -Path a.txt -Destination C:\keep\b.txt",       r"C:\keep\b.txt"),
    (r"Rename-Item -Force old.txt new.txt",                            "new.txt"),
])
def test_move_family_protects_the_destination(cmd, dest):
    """The DESTINATION is what gets clobbered, not the source - same reasoning
    as the mv branch."""
    assert recovery._ps_dest_target(cmd) == dest


def test_wildcard_target_is_refused():
    """A target that cannot be pinned down exactly must not be snapshotted."""
    assert recovery._ps_write_target(r"Clear-Content C:\logs\*.log") is None


# --------------------------------------------------------------------------
# End to end at the guard
# --------------------------------------------------------------------------

def test_overwriting_an_existing_file_is_snapshotted(tmp_path):
    victim = tmp_path / "existing.txt"
    victim.write_text("PRECIOUS")
    g = _lab(tmp_path)
    r = g.evaluate(f'Set-Content -Path {victim} -Value "x"', dialect=POWERSHELL)
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_clear_content_is_snapshotted(tmp_path):
    victim = tmp_path / "app.log"
    victim.write_text("log lines")
    g = _lab(tmp_path)
    r = g.evaluate(f"Clear-Content {victim}", dialect=POWERSHELL)
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_writing_a_new_file_is_not_destruction(tmp_path):
    """Creation destroys nothing. Flagging it would be a false positive on one
    of the most ordinary things an agent does."""
    g = _lab(tmp_path)
    r = g.evaluate(f'Set-Content -Path {tmp_path / "brand-new.txt"} -Value "x"',
                   dialect=POWERSHELL)
    assert r.classification.matched_rule is None
    assert r.recovery_entry is None


def test_move_force_onto_a_free_name_is_not_destruction(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("data")
    g = _lab(tmp_path)
    r = g.evaluate(f"Move-Item -Force {src} {tmp_path / 'free.txt'}", dialect=POWERSHELL)
    assert r.classification.matched_rule is None


def test_move_force_onto_an_existing_file_snapshots_the_destination(tmp_path):
    src = tmp_path / "a.txt"; src.write_text("new")
    dst = tmp_path / "b.txt"; dst.write_text("WILL BE OVERWRITTEN")
    g = _lab(tmp_path)
    r = g.evaluate(f"Move-Item -Force {src} {dst}", dialect=POWERSHELL)
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_format_volume_hard_stops(tmp_path):
    """A whole volume cannot be snapshotted, so it escalates in every
    environment rather than claiming a recovery - the Windows mkfs."""
    g = _lab(tmp_path)
    r = g.evaluate("Format-Volume -DriveLetter D", dialect=POWERSHELL)
    assert r.decision.decision == ESCALATE
    assert r.classification.nonrecoverable_surface == "disk_format"
    assert r.recovery_entry is None


def test_undo_restores_an_overwritten_file(tmp_path):
    """The whole promise, on the new rules: destroy, then get it back."""
    victim = tmp_path / "notes.txt"
    victim.write_text("ORIGINAL CONTENT")
    g = _lab(tmp_path)
    r = g.evaluate(f'Set-Content -Path {victim} -Value "wiped"', dialect=POWERSHELL)
    assert r.recovery_entry is not None
    victim.write_text("wiped")                      # simulate the command running
    assert recovery.restore_entry(r.recovery_entry)
    assert victim.read_text() == "ORIGINAL CONTENT"

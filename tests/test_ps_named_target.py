r"""PowerShell destination resolution, and the last place the resolver
contract was missing. Review findings F4 and F10 of 2026-09-08, plus a third
defect found while reading them.

    Copy-Item -Force -Destination keep\b.txt -Path a.txt   -> a.txt  (the SOURCE)
    Rename-Item -Force -Path C:\proj\a.txt -NewName b.txt  -> ALLOW
    Rename-Item -Force C:\proj\old.txt new.txt             -> ALLOW
    Set-Content -Path $env:APPDATA\notes.txt -Value x      -> ALLOW
    Set-Content -Path $(Get-Date).txt -Value x             -> ALLOW

F10: _ps_dest_target took ops[-1], assuming -Path was written before
-Destination. PowerShell named parameters are order-free. The loop already
distinguished the flags and threw the distinction away one line later.

THE THIRD ONE: -NewName is a NAME, not a path. It names a file beside the
SOURCE, so `-Path C:\proj\a.txt -NewName b.txt` clobbers C:\proj\b.txt. Taken
literally it resolved against the working directory, found nothing there, and
the guard read that as "creates" and cleared the destructive flag.

F4: ps_named_target returned a bare string, so the guard could not tell
resolved-and-absent (creates, clear it) from unresolvable (ambiguous,
escalate) - though its own docstring already stated the rule. Third
comment/code contradiction of the review.

EVERY RULE THAT REACHES THIS CODE REQUIRES -Force (ps_move_force,
ps_copy_force, ps_rename_force, ps_new_item_force), so the non-clobbering
forms never arrive here. Load-bearing and invisible, hence stated.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import POWERSHELL
from demo_cli.guard import Guard


# --------------------------------------------------------------------------
# F10: named parameters are order-free.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    r"Copy-Item -Force -Path a.txt -Destination keep\b.txt",
    r"Copy-Item -Force -Destination keep\b.txt -Path a.txt",
    r"Move-Item -Force -Destination keep\b.txt -Path a.txt",
])
def test_the_destination_is_found_whatever_the_flag_order(cmd):
    assert recovery._ps_dest_target(cmd) == r"keep\b.txt"


def test_the_flag_is_kept_alongside_the_value():
    """The loop already told -path from -destination and discarded it. This is
    the information that was being thrown away."""
    pairs = recovery._ps_flagged_operands(
        r"Copy-Item -Force -Destination keep\b.txt -Path a.txt")
    assert pairs == [("-destination", r"keep\b.txt"), ("-path", "a.txt")]


def test_the_values_only_view_is_unchanged():
    """_ps_named_operands keeps its exact old output, so its other caller -
    _ps_write_target - is genuinely untouched."""
    cmd = r"Copy-Item -Force -Path a.txt -Destination C:\keep\b.txt"
    assert recovery._ps_named_operands(cmd) == ["a.txt", r"C:\keep\b.txt"]


# --------------------------------------------------------------------------
# -NewName names a file beside the source.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,expected", [
    (r"Rename-Item -Force -Path C:\proj\a.txt -NewName b.txt", r"C:\proj\b.txt"),
    (r"Rename-Item -Force -NewName b.txt -Path C:\proj\a.txt", r"C:\proj\b.txt"),
    (r"Rename-Item -Force C:\proj\old.txt new.txt",            r"C:\proj\new.txt"),
])
def test_newname_is_relative_to_the_source_directory(cmd, expected):
    assert recovery._ps_dest_target(cmd) == expected


def test_a_bare_filename_source_is_the_degenerate_case(request):
    r"""`Rename-Item -Force old.txt new.txt` was the ONLY case pinned before,
    and it passed for the wrong reason: dirname("old.txt") is "", so the join
    is a no-op and the assertion held whether or not the join worked. It could
    not fail against the broken code. Kept as the degenerate case; the pins
    that matter are the ones above, with a non-empty dirname."""
    assert recovery._ps_dest_target(r"Rename-Item -Force old.txt new.txt") == "new.txt"


def test_a_newname_with_a_separator_is_refused():
    """Whether PowerShell errors on this could not be confirmed without a
    Windows box. Refusing is correct under both readings - unreachable if it
    errors, the honest answer if it does not - so the uncertainty stops
    mattering."""
    assert recovery._ps_dest_target(
        r"Rename-Item -Force -Path a.txt -NewName sub\b.txt") is None


def test_destination_is_never_joined_to_the_source():
    """-Destination IS a path. Only -NewName is a name. Joining both would
    turn an ordinary move into a wrong target."""
    assert recovery._ps_dest_target(
        r"Move-Item -Force -Path C:\proj\a.txt -Destination C:\keep\b.txt"
    ) == r"C:\keep\b.txt"


def test_a_windows_path_joins_with_a_backslash_on_any_host():
    r"""os.path.dirname(r"proj\old.txt") is "" on POSIX, so a join against it
    silently does nothing and this whole fix would look correct while
    achieving nothing. The suite runs on both platforms with literal C:\
    fixtures, so the flavour cannot be left to os.path."""
    got = recovery._ps_dest_target(r"Rename-Item -Force C:\proj\old.txt new.txt")
    assert "\\" in got and "/" not in got, got


# --------------------------------------------------------------------------
# F4: (path, resolved), the same contract as resolve_redirect_target.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    r"Set-Content -Path $env:APPDATA\notes.txt -Value x",
    r"Set-Content -Path $(Get-Date).txt -Value x",
    r"Set-Content -Path ${TGT} -Value x",
    r"Out-File $env:TEMP\log.txt",
])
def test_an_unexpanded_name_is_unresolved_not_absent(cmd):
    assert recovery.ps_named_target(cmd) == (None, False), cmd


def test_a_tilde_is_expanded_rather_than_refused():
    r"""`~\notes.txt` is resolvable. os.path.expanduser leaves it alone on
    POSIX because a backslash is not a separator there, so it needs handling
    of its own rather than a refusal."""
    named, resolved = recovery.ps_named_target(
        r"Set-Content -Path ~\notes.txt -Value x")
    assert resolved is True
    assert "~" not in named
    assert named.startswith(os.path.expanduser("~"))


def test_the_path_comes_back_absolute():
    """resolve_redirect_target returns an absolute path. Two functions with the
    same signature and different conventions would be worse than either."""
    named, resolved = recovery.ps_named_target(
        r"Set-Content -Path notes.txt -Value x")
    assert resolved and os.path.isabs(named)


def test_a_command_this_does_not_handle_is_unresolved():
    assert recovery.ps_named_target("Get-Content a.txt") == (None, False)


# --------------------------------------------------------------------------
# End to end: the guard clears only on resolved-and-absent.
# --------------------------------------------------------------------------

@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    (tmp_path / "existing.txt").write_text("IMPORTANT")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize("cmd", [
    r"Set-Content -Path $env:APPDATA\notes.txt -Value x",
    r"Set-Content -Path $(Get-Date).txt -Value x",
])
def test_an_unresolvable_target_escalates(lab, cmd):
    assert Guard(mode="enforce").evaluate(
        cmd, dialect=POWERSHELL).decision.decision == "ESCALATE"


def test_a_resolvable_new_file_is_still_allowed(lab):
    """The capability this must not cost: writing a file that does not exist
    creates it, and creation is not destruction."""
    assert Guard(mode="enforce").evaluate(
        r"Set-Content -Path brand_new.txt -Value x",
        dialect=POWERSHELL).decision.decision == "ALLOW"


def test_overwriting_an_existing_file_is_still_captured(lab):
    r = Guard(mode="enforce").evaluate(
        r"Set-Content -Path existing.txt -Value x", dialect=POWERSHELL)
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry

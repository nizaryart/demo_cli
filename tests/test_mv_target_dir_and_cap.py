"""Two small findings from the review of 2026-09-08.

F11  `mv -t bk s1` snapshotted the SOURCE. The flag form inverts the operand
     order - every source lands in DIR, so the file at risk is DIR/basename -
     but _mv took ops[-1] as the destination, and _path_operands drops `-t` as
     a flag while keeping its value. So ops was [bk, s1] and ops[-1] was s1,
     the file merely being moved away. bk/s1 was overwritten with nothing
     captured, reported REVERSIBLE.

F14  DEMO_CLI_MAX_SNAPSHOT_MB=nan crashed the guard. float() was guarded and
     int() was not: float("nan") succeeds and int(nan * 1024 * 1024) raises
     ValueError; "inf" raises OverflowError. Neither is an OSError, and the
     call runs BEFORE the try/except around the copy, so both escaped
     Guard.evaluate into a hook that fails open on its own errors. A typo in
     one environment variable turned every directory capture into an
     unguarded delete.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    (tmp_path / "bk").mkdir()
    (tmp_path / "s1").write_text("NEW")
    (tmp_path / "s2").write_text("NEW2")
    (tmp_path / "bk" / "s1").write_text("IMPORTANT")
    (tmp_path / "bk" / "s2").write_text("IMPORTANT2")
    (tmp_path / "fresh.txt").write_text("no collision")
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------
# F11
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'mv -t bk s1',
    'mv -tbk s1',
    'mv --target-directory=bk s1',
    'mv --target-directory bk s1',
])
def test_the_overwritten_file_is_captured_not_the_source(lab, cmd):
    got = recovery.extract_path_operand(cmd)
    assert got and os.path.samefile(got, lab / "bk" / "s1"), f"{cmd} -> {got}"
    assert not os.path.samefile(got, lab / "s1"), "captured the source"


def test_the_guard_snapshots_the_file_that_is_overwritten(lab):
    r = Guard(mode="enforce").evaluate('mv -t bk s1')
    assert r.decision.decision == "REVERSIBLE"
    assert os.path.samefile(r.recovery_entry["target"], lab / "bk" / "s1")


def test_several_collisions_collapse_to_the_target_directory(lab):
    got = recovery.extract_path_operand('mv -t bk s1 s2')
    assert got and os.path.samefile(got, lab / "bk")


def test_with_nothing_to_overwrite_the_source_is_captured(lab):
    """The move itself is what would be undone, so the source is the honest
    target - same as the plain two-operand form."""
    got = recovery.extract_path_operand('mv -t bk fresh.txt')
    assert got and os.path.samefile(got, lab / "fresh.txt")


def test_an_unsplittable_flag_cluster_escalates(lab):
    """`mv -ft bk s1` bundles -f with -t. Rather than guess which token is the
    directory, refuse - the same contract the rest of the module follows."""
    assert recovery.extract_path_operand('mv -ft bk s1') is None


def test_the_plain_form_is_unchanged(lab):
    got = recovery.extract_path_operand('mv s1 bk/s1')
    assert got and os.path.samefile(got, lab / "bk" / "s1")


# --------------------------------------------------------------------------
# F14
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "1e400", "abc", "", "-5"])
def test_a_nonsense_cap_falls_back_instead_of_raising(monkeypatch, value):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", value)
    got = recovery._max_snapshot_bytes()                 # must not raise
    assert got == int(recovery._DEFAULT_MAX_SNAPSHOT_MB * 1024 * 1024), value


def test_a_negative_cap_does_not_silently_disable_recovery(monkeypatch, lab):
    """Worse than a crash: every tree exceeds a cap of -5 MB, so directory
    capture is switched off with no message at all."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "-5")
    (lab / "d").mkdir()
    (lab / "d" / "a.txt").write_text("a")
    (lab / "d" / "b.txt").write_text("b")
    r = Guard(mode="enforce").evaluate('rm d/a.txt d/b.txt')
    assert r.recovery_entry, "a negative cap silently disabled directory capture"


@pytest.mark.parametrize("value,expected_mb", [("0", 0), ("0.5", 0.5), ("12", 12)])
def test_a_sensible_cap_is_still_honoured(monkeypatch, value, expected_mb):
    """0 is coherent - 'files only' - and must not be swept up with the
    nonsense values."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", value)
    assert recovery._max_snapshot_bytes() == int(expected_mb * 1024 * 1024)


def test_the_guard_survives_a_nan_cap_end_to_end(monkeypatch, lab):
    """The path that actually mattered: _max_snapshot_bytes runs before the
    try/except around the copy, so this used to escape into the hook."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "nan")
    (lab / "d").mkdir()
    (lab / "d" / "a.txt").write_text("a")
    (lab / "d" / "b.txt").write_text("b")
    r = Guard(mode="enforce").evaluate('rm d/a.txt d/b.txt')   # must not raise
    assert r.decision.decision == "REVERSIBLE"

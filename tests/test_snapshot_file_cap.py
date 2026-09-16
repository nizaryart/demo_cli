"""Capture cost is per-file, and the only cap we had counted bytes.

Measured 2026-09-16, Windows NTFS with Defender live, the platform this ships
to:

    2,000 files   131.1 MB   copytree 2.041s
    2,000 files     1.0 MB   copytree 1.878s     131x the data, 9% the time
   20,000 files    10.2 MB   copytree 21.794s

991 us per file, essentially independent of size. So the 256 MB byte cap
permits 262,144 one-kilobyte files and about 260 seconds of copying, while the
hook's budget was 30.

WHY THIS IS A REFUSAL AND NOT A WARNING. Measured the same day against Claude
Code on Windows: when a hook outlives its timeout the host kills it, runs the
command unguarded, and says NOTHING - a hook that CRASHES is announced, a hook
that times out is not. There is no process of ours left to warn from, so the
only moment we can speak is before the copy starts.

Bytes bound disk space, files bound time. Two instruments, two jobs, both kept.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.config import Config
from demo_cli.decide import ESCALATE, REVERSIBLE
from demo_cli.guard import Guard


def _tree(root, n, size=16):
    os.makedirs(root, exist_ok=True)
    for i in range(n):
        with open(os.path.join(root, f"f{i}"), "wb") as f:
            f.write(b"x" * size)


def test_default_cap_is_read_from_the_environment(monkeypatch):
    monkeypatch.delenv("DEMO_CLI_MAX_SNAPSHOT_FILES", raising=False)
    assert recovery._max_snapshot_files() == recovery._DEFAULT_MAX_SNAPSHOT_FILES
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "1234")
    assert recovery._max_snapshot_files() == 1234


@pytest.mark.parametrize("raw", ["abc", "nan", "inf", "-5", ""])
def test_nonsense_falls_back_to_the_default(monkeypatch, raw):
    # Same discipline as the byte cap: this runs BEFORE the try/except around
    # the copy, and the adapters fail open on our errors, so a typo in one
    # variable must not turn every directory capture into an unguarded delete.
    # A negative value is the dangerous one - every tree exceeds a cap of -5,
    # so recovery switches off silently.
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", raw)
    assert recovery._max_snapshot_files() == recovery._DEFAULT_MAX_SNAPSHOT_FILES


def test_zero_means_no_directory_capture(monkeypatch):
    # Coherent, like the byte cap's zero: "files only, never a tree".
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "0")
    assert recovery._max_snapshot_files() == 0


def test_walk_cost_counts_both_and_skips_what_the_copy_skips(tmp_path):
    _tree(str(tmp_path / "src"), 10, size=100)
    _tree(str(tmp_path / "node_modules"), 50, size=100)
    nbytes, nfiles = recovery._walk_cost(str(tmp_path), 10 ** 9, None)
    assert nfiles == 10, "node_modules is in IGNORED_DIRS and must not be counted"
    assert nbytes == 1000
    # The measurement and the copy must skip the SAME directories, or neither
    # cap bounds anything.
    nbytes2, nfiles2 = recovery._walk_cost(str(tmp_path), 10 ** 9, None,
                                           ignore_dirs=frozenset())
    assert nfiles2 == 60


def test_walk_cost_short_circuits_on_the_file_cap(tmp_path):
    _tree(str(tmp_path / "many"), 200)
    _, nfiles = recovery._walk_cost(str(tmp_path), 10 ** 9, 20)
    assert nfiles <= 21, "must stop counting shortly after the cap, not walk it all"


def test_dir_size_still_returns_bytes_only(tmp_path):
    # checkpoint.py and four existing tests call it; one walk, two entry points.
    _tree(str(tmp_path / "src"), 10, size=100)
    assert recovery._dir_size(str(tmp_path), 10 ** 9) == 1000


def test_over_the_file_cap_refuses_even_though_bytes_are_tiny(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "50")
    _tree(str(tmp_path / "assets"), 120)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"rm -rf {tmp_path / 'assets'}")
    assert r.decision.decision == ESCALATE
    assert r.recovery_entry is None


def test_under_the_cap_is_still_captured(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "50")
    _tree(str(tmp_path / "src"), 5)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"rm -rf {tmp_path / 'src'}")
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None


def test_the_refusal_says_which_cap_and_which_knob(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "50")
    _tree(str(tmp_path / "assets"), 120)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    reason = g.evaluate(f"rm -rf {tmp_path / 'assets'}").decision.reason
    assert "DEMO_CLI_MAX_SNAPSHOT_FILES" in reason
    assert "50" in reason
    # and it must not be confused with the byte cap's message
    assert "MAX_SNAPSHOT_MB" not in reason


def test_the_byte_cap_refusal_also_explains_itself(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0")
    _tree(str(tmp_path / "assets"), 3, size=4096)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    reason = g.evaluate(f"rm -rf {tmp_path / 'assets'}").decision.reason
    assert "DEMO_CLI_MAX_SNAPSHOT_MB" in reason


def test_the_explanation_reaches_the_decision_not_only_the_receipt(tmp_path, monkeypatch):
    # THE RECEIPT IS NOT THE PERSON. Every adapter renders
    # result.decision.reason; the augmented text used to live only on the
    # Receipt, so the checkpoint explanation - whose own comment says someone
    # blocked "has to be told why" - reached the ledger and nobody else.
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "50")
    _tree(str(tmp_path / "assets"), 120)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate(f"rm -rf {tmp_path / 'assets'}")
    assert r.receipt is not None
    assert r.decision.reason == r.receipt.reason


def test_a_captured_snapshot_carries_no_refusal_text(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "50")
    _tree(str(tmp_path / "src"), 5)
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    reason = g.evaluate(f"rm -rf {tmp_path / 'src'}").decision.reason
    assert "DEMO_CLI_MAX_SNAPSHOT" not in reason


def test_both_hosts_declare_a_budget_we_can_size_against():
    # An unknown budget for a silent failure is not a budget. Claude Code used
    # to declare none and take the host default.
    from demo_cli.hooks import claude_code, codex
    cc = claude_code.settings_snippet()["hooks"]["PreToolUse"]
    assert all(h["timeout"] > 0 for group in cc for h in group["hooks"])
    cx = codex.settings_snippet()["hooks"]["PreToolUse"]
    assert all(h["timeout"] > 0 for group in cx for h in group["hooks"])


def test_the_default_cap_fits_inside_the_declared_budget():
    # 991 us/file measured on Windows NTFS. The default must leave real room,
    # not sit exactly on the line.
    from demo_cli.hooks import codex
    budget = codex.settings_snippet()["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"]
    worst_case = recovery._DEFAULT_MAX_SNAPSHOT_FILES * 991e-6
    assert worst_case < budget / 2, (worst_case, budget)

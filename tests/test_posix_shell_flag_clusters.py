"""`bash -lc` is `bash -l -c`, and it was never unwrapped.

_POSIX_SH demanded a bare `-c`, so a clustered flag - `-lc`, `-ilc`,
`--login -c` - left the whole line as one segment beginning with "bash". Every
ANCHORED rule then failed to fire:

    bash -c  "rm app.db"   ->  rm_local
    bash -lc "rm app.db"   ->  nothing at all

Not the lost snapshot the 2026-09-14 handoff recorded - a lost command. The
unanchored rm_rf still matched by substring, which is what made it look like
an escalation problem.

This module has named the failure before, in _payload_tokens' own docstring:
"anchored rules did not fire at all, which is a SILENT PASS". Same class,
different cause - that one was quote stripping, this one is the flag regex.

`-lc` is the form agent shell tools actually emit.

WHICH CLUSTERS RUN THE SCRIPT WAS MEASURED, NOT REASONED. A first draft
required `c` to be LAST in the cluster and recorded `bash -cl` as an accepted
miss. Running it printed the script's output: -c, -lc, -ilc, -cl, -clx, -cil
and a repeated `-c -c` all run it, so `c` may sit anywhere. `-C` is noclobber
and does not.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import POSIX, classify_pipeline, effective_segments
from demo_cli.config import Config
from demo_cli.decide import ALLOW, REVERSIBLE
from demo_cli.guard import Guard

WRAPPERS = [
    'bash -c "rm app.db"',
    'bash -lc "rm app.db"',
    'bash -ilc "rm app.db"',
    # c need not be last in the cluster - measured against bash itself.
    'bash -cl "rm app.db"',
    'bash -clx "rm app.db"',
    'bash -cil "rm app.db"',
    # -C is noclobber, an uppercase flag that is NOT -c; it may precede one.
    'bash -C -c "rm app.db"',
    'bash -c -c "rm app.db"',
    'bash -l -c "rm app.db"',
    'bash --login -c "rm app.db"',
    'bash --noprofile --norc -c "rm app.db"',
    'sh -lc "rm app.db"',
    'zsh -ic "rm app.db"',
    'dash -c "rm app.db"',
    '/usr/bin/bash -lc "rm app.db"',
]

# A shell invocation that is NOT "-c <script>" must be left exactly as it is.
NOT_WRAPPERS = [
    "bash -x script.sh",
    # -C is noclobber and runs no script.
    'bash -C "rm app.db"',
    "bash --version",
    "bash script.sh",
    "sh -n script.sh",
    "bashful -c x",
    "echo bash -lc",
]


@pytest.mark.parametrize("cmd", WRAPPERS)
def test_payload_is_unwrapped(cmd):
    assert effective_segments(cmd, POSIX) == [("rm app.db", POSIX)], cmd


@pytest.mark.parametrize("cmd", WRAPPERS)
def test_anchored_rule_fires_on_the_payload(cmd):
    # rm_local is anchored ^\s*rm. It is the rule the cluster forms lost.
    c = classify_pipeline(cmd, POSIX)
    assert c.is_destructive is True, cmd
    assert c.matched_rule == "rm_local", (cmd, c.matched_rule)


@pytest.mark.parametrize("cmd", NOT_WRAPPERS)
def test_non_command_invocations_are_untouched(cmd):
    assert effective_segments(cmd, POSIX) == [(cmd, POSIX)], cmd


def test_powershell_payload_inside_a_cluster_wrapper():
    c = classify_pipeline('bash -lc "Remove-Item app.db"', POSIX)
    assert c.matched_rule == "ps_remove_item"


def test_operand_is_resolved_so_a_snapshot_can_happen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.db").write_text("x")
    for cmd in WRAPPERS:
        assert recovery.extract_path_operand(cmd, POSIX) == "app.db", cmd


def test_cluster_wrapper_is_snapshotted_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.db"
    f.write_text("keep me")
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate('bash -lc "rm app.db"', dialect=POSIX)
    assert r.decision.decision == REVERSIBLE
    assert r.recovery_entry is not None
    # and the captured bytes are the real file, not a same-named bystander
    with open(r.recovery_entry["recovery_point"], "rb") as fh:
        assert fh.read() == b"keep me"


def test_a_plain_script_run_is_still_allowed(tmp_path):
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    assert g.evaluate("bash script.sh", dialect=POSIX).decision.decision == ALLOW


def test_c_anywhere_in_the_cluster():
    # This is the assertion a first draft got backwards. `bash -cl "echo RAN"`
    # prints RAN, so requiring c last was a real miss, not an accepted one.
    for cmd in ['bash -cl "rm app.db"', 'bash -clx "rm app.db"',
                'bash -cil "rm app.db"']:
        assert classify_pipeline(cmd, POSIX).matched_rule == "rm_local", cmd


def test_uppercase_C_is_not_a_command_flag():
    # -C is noclobber. It must not be mistaken for -c, and it may legitimately
    # precede one.
    assert effective_segments('bash -C "rm app.db"', POSIX) == [
        ('bash -C "rm app.db"', POSIX)]
    assert classify_pipeline('bash -C -c "rm app.db"', POSIX).matched_rule == "rm_local"

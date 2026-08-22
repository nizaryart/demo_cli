"""An unreadable .demo_cli.toml must BLOCK, not be ignored.

Three times in this project the dangerous state has been the same: installed,
apparently fine, protecting nothing. The Windows case was the worst - a UTF-8
BOM made the config unparseable, the hook caught the error and failed OPEN, and
the guard stepped aside on every command while install-hook said "Installed".

The distinction this file locks in:

    config MISSING  -> "no opinion"                    -> defaults, allow
    config BROKEN   -> "you asked and we cannot read"  -> refuse

Fail-closed applies to the USER'S config only. Our own bugs still fail open;
that rule is unchanged.
"""
import json

from demo_cli.config import load_config
from demo_cli.decide import ESCALATE
from demo_cli.guard import Guard

BOM = b"\xef\xbb\xbf"
BROKEN = b'mode = = "enforce"\n'


def _guard(tmp_path):
    return Guard(config=load_config(start=str(tmp_path)))


# --------------------------------------------------------------------------
# Broken config blocks everything
# --------------------------------------------------------------------------

def test_broken_config_blocks_a_destructive_command(tmp_path):
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    (tmp_path / "hello.txt").write_text("data")
    r = _guard(tmp_path).evaluate("rm hello.txt")
    assert r.decision.decision == ESCALATE
    assert r.classification.matched_rule == "config_unreadable"


def test_broken_config_blocks_even_a_harmless_command(tmp_path):
    """The point of fail-closed: we cannot classify anything, so we cannot
    honestly say `ls` is safe either."""
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    assert _guard(tmp_path).evaluate("ls").decision.decision == ESCALATE


def test_broken_config_blocks_the_file_write_door_too(tmp_path):
    """Both doors, or the block is trivially bypassed by using the other one."""
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    victim = tmp_path / "hello.txt"
    victim.write_text("data")
    r = _guard(tmp_path).evaluate_file_edit(str(victim), tool_name="Write")
    assert r.decision.decision == ESCALATE


def test_broken_config_never_claims_a_recovery(tmp_path):
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    r = _guard(tmp_path).evaluate("rm hello.txt")
    assert r.recovery_entry is None
    assert r.decision.recoverable is False


# --------------------------------------------------------------------------
# The message has to be usable
# --------------------------------------------------------------------------

def test_the_block_message_is_actionable(tmp_path):
    """A block with no way forward is its own kind of failure: it must name the
    file, say why everything stopped, and give an escape hatch."""
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    reason = _guard(tmp_path).evaluate("ls").decision.reason
    assert ".demo_cli.toml" in reason
    assert "blocked" in reason.lower()
    assert "delete it" in reason            # the way out
    assert "BOM" in reason                  # the most likely cause on Windows


def test_the_refusal_is_recorded_in_the_ledger(tmp_path):
    """A block nobody can see afterwards is the problem we are fixing."""
    (tmp_path / ".demo_cli.toml").write_bytes(BROKEN)
    _guard(tmp_path).evaluate("rm hello.txt")
    receipts = (tmp_path / ".demo_cli" / "receipts.jsonl").read_text().splitlines()
    last = json.loads(receipts[-1])
    assert last["decision"] == ESCALATE
    assert last["matched_rule"] == "config_unreadable"


# --------------------------------------------------------------------------
# ... and the cases that must NOT block
# --------------------------------------------------------------------------

def test_a_missing_config_does_not_block(tmp_path):
    """No config means no opinion. Falling back to defaults is correct - this
    is the distinction the whole change rests on."""
    (tmp_path / "hello.txt").write_text("data")
    r = _guard(tmp_path).evaluate("ls")
    assert r.decision.decision != ESCALATE
    assert r.classification.matched_rule != "config_unreadable"


def test_a_valid_config_with_a_bom_does_not_block(tmp_path):
    """The BOM itself is tolerated. Only genuinely unparseable content blocks -
    otherwise this change would re-break what the BOM fix repaired."""
    (tmp_path / ".demo_cli.toml").write_bytes(BOM + b'mode = "enforce"\n')
    (tmp_path / "hello.txt").write_text("data")
    g = _guard(tmp_path)
    assert g.config.mode == "enforce"
    assert g.evaluate("ls").decision.decision != ESCALATE

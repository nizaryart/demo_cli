"""The receipt records which shell the guard judged the command as.

The adapters decide the dialect from signals nothing else writes down - Claude
Code from its tool name, Codex from the platform - so before this the trail
could not answer which rules were even eligible for a given command. That
question is about to matter: gating the short PowerShell aliases makes the
dialect change the verdict.
"""
import json

from demo_cli.classify import POSIX, POWERSHELL
from demo_cli.config import Config
from demo_cli.guard import Guard
from demo_cli.receipts import Receipt, append_receipt, verify_chain


def _cfg(tmp_path):
    return Config(mode="shadow", project_root=str(tmp_path))


def _last(tmp_path):
    with open(Config(project_root=str(tmp_path)).receipts_path) as f:
        return json.loads(f.read().strip().splitlines()[-1])


def test_receipt_records_the_dialect_it_was_judged_in(tmp_path):
    g = Guard(config=_cfg(tmp_path))
    g.evaluate("Remove-Item app.db", dialect=POWERSHELL)
    assert _last(tmp_path)["dialect"] == POWERSHELL


def test_posix_is_recorded_explicitly_not_left_blank(tmp_path):
    # An absent field would read as "we did not judge a shell", which is the
    # one thing it must not be confused with.
    g = Guard(config=_cfg(tmp_path))
    g.evaluate("rm app.db", dialect=POSIX)
    assert _last(tmp_path)["dialect"] == POSIX


def test_file_edit_receipt_has_no_dialect(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    g = Guard(config=_cfg(tmp_path))
    g.evaluate_file_edit(str(f), tool_name="Edit")
    assert _last(tmp_path)["dialect"] is None


def test_receipts_written_before_this_field_still_verify(tmp_path):
    # verify_chain recomputes over the keys the line actually carries, so a
    # ledger written by an older build must keep verifying untouched. Adding a
    # dataclass field is exactly the change that would break that if it did not.
    path = Config(project_root=str(tmp_path)).receipts_path
    r = Receipt(action_raw="rm old.txt", action_type="shell",
                target_environment="dev", decision="ESCALATE", reason="x",
                mode="shadow")
    append_receipt(path, r)

    lines = open(path).read().strip().splitlines()
    body = json.loads(lines[-1])
    del body["dialect"]
    body["receipt_hash"] = _rehash(body)
    lines[-1] = json.dumps(body, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")

    assert verify_chain(path).ok is True
    assert "dialect" not in json.loads(open(path).read().strip().splitlines()[-1])

    # and a new receipt still chains onto it
    append_receipt(path, Receipt(action_raw="rm new.txt", action_type="shell",
                                 target_environment="dev", decision="ESCALATE",
                                 reason="x", mode="shadow", dialect=POSIX))
    assert verify_chain(path).ok is True


def _rehash(body: dict) -> str:
    import hashlib
    from demo_cli.receipts import _canon
    inner = {k: v for k, v in body.items() if k != "receipt_hash"}
    return hashlib.sha256(
        (_canon(inner) + body.get("prev_receipt_hash", "")).encode()).hexdigest()

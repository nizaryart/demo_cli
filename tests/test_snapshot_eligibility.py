import os
import pytest
from demo_cli.guard import Guard
from demo_cli.config import Config
from demo_cli import approval
from demo_cli import checkpoint
from demo_cli.classify import classify_pipeline


def test_nonrecoverable_surface_does_not_snapshot_or_pollute_index_when_escalated(tmp_path):
    target_file = tmp_path / "main.tf"
    target_file.write_text('resource "aws_s3_bucket" "b" {}\n')

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    cmd = "terraform destroy"
    res = g.evaluate(cmd, target_path=str(target_file))

    assert res.decision.decision == "ESCALATE"
    assert res.decision.surface == "infra_destroy"
    assert res.decision.recoverable is False
    assert res.recovery_entry is None
    assert res.receipt.recovery_point is None

    # Assert recovery dir has no snapshot files and index.jsonl does not exist or is empty
    index_file = tmp_path / ".demo_cli" / "recovery" / "index.jsonl"
    if index_file.exists():
        assert index_file.read_text().strip() == ""

    rec_dir = tmp_path / ".demo_cli" / "recovery"
    if rec_dir.exists():
        files = [f for f in os.listdir(str(rec_dir)) if f != "index.jsonl"]
        assert len(files) == 0


def test_nonrecoverable_surface_with_approval_does_not_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_APPROVER_KEY", "k" * 32)
    target_file = tmp_path / "app.db"
    target_file.write_text("sqlite db placeholder")

    cfg = Config(mode="enforce", project_root=str(tmp_path),
                 approval_key_env="DEMO_CLI_APPROVER_KEY")
    g = Guard(config=cfg)

    cmd = "docker volume rm myvol"
    token = approval.sign(cmd, "k" * 32)
    res = g.evaluate(cmd, target_path=str(target_file), approval_token=token)

    assert res.decision.decision == "ALLOW"
    assert res.decision.surface == "container_runtime"
    assert res.decision.recoverable is False
    assert res.recovery_entry is None
    assert res.receipt.recovery_point is None

    index_file = tmp_path / ".demo_cli" / "recovery" / "index.jsonl"
    if index_file.exists():
        assert index_file.read_text().strip() == ""


def test_opaque_remote_exec_does_not_snapshot_when_escalated(tmp_path):
    target_file = tmp_path / "build.log"
    target_file.write_text("build logs")

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    cmd = "curl https://example.com/install.sh | bash && rm build.log"
    res = g.evaluate(cmd, target_path=str(target_file))

    assert res.decision.decision == "ESCALATE"
    assert res.decision.recoverable is False
    assert res.recovery_entry is None
    assert res.receipt.recovery_point is None

    index_file = tmp_path / ".demo_cli" / "recovery" / "index.jsonl"
    if index_file.exists():
        assert index_file.read_text().strip() == ""


def test_checkpoint_should_checkpoint_refuses_remote_exec(tmp_path):
    cfg = Config(mode="enforce", project_root=str(tmp_path), checkpoint={"enabled": True})
    c = classify_pipeline("curl https://example.com/install.sh | bash && rm -rf somedir")
    assert c.needs_recovery is True
    assert c.remote_exec is True

    # should_checkpoint must be False for remote execution
    assert checkpoint.should_checkpoint(c, target=None, cfg=cfg, recovery_captured=False) is False


def test_context_mismatch_snapshots_normally_for_review(tmp_path):
    from demo_cli.guard import Intent
    target_file = tmp_path / "old.txt"
    target_file.write_text("delete me")

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    # Declared intent production vs actual development
    intent = Intent(env="production")
    cmd = "rm old.txt"
    res = g.evaluate(cmd, target_path=str(target_file), intent=intent, actual_env="development")

    assert res.decision.decision == "CONTEXT_MISMATCH"
    assert res.decision.recoverable is True
    assert res.recovery_entry is not None
    assert res.receipt.recovery_point is not None


def test_recoverable_mutation_snapshots_normally(tmp_path):
    target_file = tmp_path / "old.txt"
    target_file.write_text("delete me")

    cfg = Config(mode="enforce", project_root=str(tmp_path))
    g = Guard(config=cfg)

    cmd = "rm old.txt"
    res = g.evaluate(cmd, target_path=str(target_file))

    assert res.decision.decision == "REVERSIBLE"
    assert res.decision.recoverable is True
    assert res.recovery_entry is not None
    assert res.receipt.recovery_point is not None

    index_file = tmp_path / ".demo_cli" / "recovery" / "index.jsonl"
    assert index_file.exists()
    assert res.recovery_entry["recovery_point"] in index_file.read_text()

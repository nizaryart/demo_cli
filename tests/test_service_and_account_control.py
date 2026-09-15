"""Services and local accounts were a blind spot, both platforms.

Measured 2026-09-15: 34 of 34 service-management commands returned ALLOW.
`sc.exe create` installs a service, `sc sdset` rewrites its ACL,
`net localgroup administrators <user> /add` makes someone an admin, and the
guard said nothing about any of them.

A service is SCM + registry state and an account is a SID, so neither can be
snapshotted. They are therefore non-recoverable SURFACES rather than plain
destructive rules, and that choice is deliberate: decide.py step 3 honours a
structural approval token, step 6 does not check one at all. Marking these as
surfaces is what leaves a human an override for a legitimate restart.

The sc.exe verb list came from `sc.exe /?` on Windows 10, corrected: that help
text does not list `delete`.
"""
import pytest

from demo_cli.classify import POSIX, POWERSHELL, classify_pipeline
from demo_cli.config import Config
from demo_cli.decide import ALLOW, ESCALATE, _RECOVERY_HINTS
from demo_cli.guard import Guard

SERVICE_WRITES = [
    "sc.exe delete svc", "sc delete svc", "sc.exe stop spooler",
    "sc config svc start= disabled", "sc.exe create evil binPath= C:\\x.exe",
    "sc sdset svc D:", "sc.exe failureflag svc 1", r"sc \\BOX delete svc",
    "sc boot bad",
    "Stop-Service -Name x", "Remove-Service x",
    "Set-Service x -StartupType Disabled",
    "New-Service -Name x -BinaryPathName y", "Restart-Service x",
    "Suspend-Service x",
    "net stop w32time", "systemctl stop nginx", "systemctl disable nginx",
    "systemctl mask nginx", "systemctl --now disable nginx",
    "service nginx stop",
]

ACCOUNT_WRITES = [
    "net user hacker /add", "net user victim /delete",
    "net localgroup administrators hacker /add",
    "net share c$ /delete", "userdel bob", "groupdel devs",
]

# Every one of these must stay silent, in BOTH dialects.
READS = [
    "sc query", "sc.exe query", "sc qc svc", "sc.exe queryex spooler",
    "sc showsid svc", "sc EnumDepend svc", "sc sdshow svc",
    "sc GetKeyName svc", "sc.exe qprotection svc",
    # sc.exe's resume-index option carries the letters "ri".
    "sc query ri= 14",
    "Get-Service", "gsv", "Start-Service -Name x", "net start w32time",
    "net user", "net share", "systemctl status nginx",
    "systemctl start nginx", "systemctl daemon-reload",
]


@pytest.mark.parametrize("cmd", SERVICE_WRITES)
def test_service_writes_are_a_nonrecoverable_surface(cmd):
    c = classify_pipeline(cmd, POWERSHELL)
    assert c.is_destructive is True
    assert c.matched_rule == "service_control", c.matched_rule
    assert c.nonrecoverable_surface == "service_control"


@pytest.mark.parametrize("cmd", ACCOUNT_WRITES)
def test_account_writes_are_a_nonrecoverable_surface(cmd):
    c = classify_pipeline(cmd, POWERSHELL)
    assert c.matched_rule == "account_control", c.matched_rule
    assert c.nonrecoverable_surface == "account_control"


@pytest.mark.parametrize("cmd", READS)
@pytest.mark.parametrize("dialect", [POSIX, POWERSHELL])
def test_reads_never_fire(cmd, dialect):
    c = classify_pipeline(cmd, dialect)
    assert c.is_destructive is False, (cmd, dialect, c.matched_rule)
    assert c.is_mutating is False, (cmd, dialect, c.matched_rule)


def test_sc_needs_no_dialect_gate():
    # Unlike the Set-Content alias, every reading of `sc delete svc` is
    # destructive: Set-Content writing a file called "delete" on 5.1, or the
    # service removed on 7 and cmd.exe. `cmd /c "sc delete x"` arrives POSIX.
    for d in (POSIX, POWERSHELL):
        assert classify_pipeline("sc delete svc", d).is_destructive is True, d
    assert classify_pipeline('cmd /c "sc delete svc"').is_destructive is True


def test_stop_service_alias_is_gated():
    # spsv is Stop-Service. gsv and sasv are reads and are not in the rule.
    assert classify_pipeline("spsv x", POWERSHELL).is_destructive is True
    assert classify_pipeline("spsv x", POSIX).is_destructive is False


def test_both_surfaces_have_recovery_hints():
    assert "service_control" in _RECOVERY_HINTS
    assert "account_control" in _RECOVERY_HINTS


def test_escalates_with_no_recovery_point(tmp_path):
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    for cmd in ["sc.exe delete svc", "net user victim /delete",
                "systemctl mask nginx"]:
        r = g.evaluate(cmd, dialect=POWERSHELL)
        assert r.decision.decision == ESCALATE, cmd
        assert r.recovery_entry is None, cmd
        assert r.decision.surface in ("service_control", "account_control"), cmd


def test_reads_are_allowed_end_to_end(tmp_path):
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    for cmd in ["sc query", "Get-Service", "systemctl status nginx"]:
        assert g.evaluate(cmd, dialect=POWERSHELL).decision.decision == ALLOW, cmd


def test_a_structural_approval_can_still_let_a_restart_through(tmp_path, monkeypatch):
    # The reason these are surfaces and not bare destructive rules: decide.py
    # step 3 honours an approval token, step 6 never checks one. Without the
    # surface a legitimate Restart-Service would have no override at all.
    from demo_cli import approval
    key = "k" * 32
    monkeypatch.setenv("DEMO_CLI_APPROVER_KEY", key)
    cfg = Config(mode="enforce", project_root=str(tmp_path),
                 approval_key_env="DEMO_CLI_APPROVER_KEY")
    assert cfg.approver_key == key
    cmd = "Restart-Service myapp"
    g = Guard(config=cfg)
    assert g.evaluate(cmd, dialect=POWERSHELL).decision.decision == ESCALATE
    token = approval.sign(cmd, key)
    ok = g.evaluate(cmd, dialect=POWERSHELL, approval_token=token)
    assert ok.decision.decision == ALLOW
    assert ok.decision.surface == "service_control"

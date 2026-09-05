"""The two install scripts, checked against the code they claim to install.

WHY THIS FILE EXISTS. On 2026-09-05 v1.0.5 was tagged and pushed, and the
doctor work landed one commit later. The installers still pinned v1.0.5, so
the published one-liner would have installed a version WITHOUT the thing it
was being released for - and nothing anywhere would have said so. The scripts
are not Python, so nothing in the suite was watching them.

These are greps. They are cheap and they are not clever, and each one pins a
decision that was argued for and can be silently undone by an edit that looks
harmless.
"""
import os
import re

import pytest

from demo_cli.version import release_tag

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SH = os.path.join(ROOT, "install.sh")
PS = os.path.join(ROOT, "install.ps1")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(SH) and os.path.exists(PS)),
    reason="installers only exist in a source checkout")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def sh():
    return _read(SH)


@pytest.fixture(scope="module")
def ps():
    return _read(PS)


# --------------------------------------------------------------------------
# The version the scripts install must be the version in this tree.
# --------------------------------------------------------------------------

def test_both_installers_pin_the_current_release_tag(sh, ps):
    """A pinned install command is a promise about WHICH code arrives. When
    the pin lags the version, the promise is broken silently - the install
    succeeds, and the user is simply running something else."""
    tag = release_tag()
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        found = set(re.findall(r"v\d+\.\d+\.\d+(?:-beta\.\d+)?", text))
        assert found, f"{name} pins no version at all"
        assert found == {tag}, (
            f"{name} pins {sorted(found)} but this tree is {tag}. "
            f"Bump the scripts with version.py, or tag what they point at.")


def test_neither_installer_points_at_a_moving_branch(sh, ps):
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        assert "@beta" not in text, f"{name} points at a moving branch"
        assert "@main" not in text and "@master" not in text, name


def test_both_installers_use_the_repository_the_code_lives_in(sh, ps):
    """Upstream's push is disabled by design, so a URL pointing there installs
    code that will never contain this work."""
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        assert "nizaryart/DEMO_LOADING" in text, name
        assert "WePwn/demo_cli" not in text, f"{name} still points upstream"


# --------------------------------------------------------------------------
# Scope: the machine, never a project.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["demo_cli init", "demo_cli install-hook",
                                 "demo_cli setup", "demo_cli protect",
                                 "demo_cli install-shell-guard"])
def test_the_installer_never_runs_a_project_command(sh, ps, cmd):
    """Installing the tool and wiring a project are separate acts, and the
    second one moves files. The scripts may PRINT these as the next step -
    which is why the check is for an executed line, not a mention.

    They also used to duplicate init + install-hook, which `setup` now does
    better and with more steps; two copies of that logic is how they drift.
    """
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            # A printed line is fine; an executed one is not.
            if re.match(r"^(say|Say|ok|OK|warn|Warn|step|Step|printf|echo|Write-Host)\b",
                        stripped):
                continue
            assert not stripped.startswith(cmd), \
                f"{name} executes `{cmd}` - that is the user's decision"


def test_doctor_is_the_only_demo_cli_command_the_installers_run(sh, ps):
    """Read-only, and the one thing that proves the install worked."""
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        assert "demo_cli doctor" in text, f"{name} never verifies the install"


# --------------------------------------------------------------------------
# Elevation: refused, on both platforms, for the same reason.
# --------------------------------------------------------------------------

def test_the_posix_installer_refuses_root(sh):
    assert 'id -u' in sh and 'exit 1' in sh
    assert "Running as root" in sh


def test_the_windows_installer_refuses_an_elevated_shell(ps):
    assert "WindowsBuiltInRole]::Administrator" in ps
    assert "This shell is elevated" in ps


def test_the_refusal_explains_the_pipx_consequence_not_just_a_rule(sh, ps):
    """A refusal nobody understands gets worked around. Both must say WHY:
    pipx is per-user, so an elevated install lands on another account's PATH."""
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        assert "pipx installs per user" in text, name


# --------------------------------------------------------------------------
# Windows ordering and the traps found while writing it.
# --------------------------------------------------------------------------

def test_winfsp_is_installed_before_demo_cli(ps):
    """The winfspy binding is built against the driver. Reverse the order and
    the binding fails for a reason that looks like a packaging problem."""
    assert ps.index("[3/6] WinFsp") < ps.index("[4/6] demo_cli")


def test_the_windows_installer_verifies_winfsp_by_probe_not_exit_code(ps):
    """This project's standing lesson: an installer reporting success is not
    evidence. The registry is."""
    assert ps.count("Find-WinFspDll") >= 2, \
        "WinFsp must be re-probed after the install attempt, not trusted"
    assert "Do NOT trust $LASTEXITCODE" in ps


def test_winget_asks_for_the_full_feature_set(ps):
    """`winget show --id WinFsp.WinFsp` reports Installer Type: wix, so winget
    runs msiexec and --custom reaches it. The DEFAULT feature set may omit the
    Developer feature the winfspy binding needs, and the user would only learn
    that one step later from an import error that looks like a packaging
    fault. Asking up front costs nothing and removes a round trip."""
    assert 'ADDLOCAL=ALL' in ps
    assert '--custom "ADDLOCAL=ALL"' in ps, "must reach the MSI, not just be printed"


def test_the_pinned_winget_id_is_the_stable_package(ps):
    """A `winget search winfsp` also lists WinFsp.WinFsp.Beta. Pinning the
    stable id is deliberate; a driver is not the place to track a beta."""
    assert "--id WinFsp.WinFsp " in ps or "--id WinFsp.WinFsp\n" in ps
    assert "WinFsp.WinFsp.Beta" not in ps


def test_the_windows_extra_is_only_requested_when_the_driver_is_there(ps):
    assert "demo_cli[windows] @" in ps
    assert "without the [windows] extra" in ps


def test_the_mitmproxy_command_exposes_the_binary(sh, ps):
    """cli.py finds the proxy with shutil.which. A plain inject installs the
    library and leaves mitmdump off PATH, so the command silently does not
    work - and the user has no way to tell."""
    for name, text in (("install.sh", sh), ("install.ps1", ps)):
        assert "pipx inject --include-apps demo-cli mitmproxy" in text, name


def test_both_check_that_the_install_survives_a_new_terminal(sh, ps):
    """The old scripts checked PATH after editing PATH themselves, so they
    could only answer yes. The shell that launches the agent is a different
    shell, and that is the one that has to find demo_cli."""
    assert "new terminals" in sh and "new terminals" in ps
    assert "GetEnvironmentVariable(\"Path\",\"User\")" in ps
    assert ".profile" in sh

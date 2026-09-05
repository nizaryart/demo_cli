"""The prerequisite report, and the four-way split it exists for.

BACKGROUND. On 2026-09-02 three separate failures in this project reported a
permissions cause for a problem that was not about permissions, and the
generalisation written up that day was:

    a diagnostic that can only name one cause will name it wrongly.

`cli.py` contained a fourth instance, in the first command a new user runs:
any failure of `import winfspy` printed "pipx inject demo-cli winfspy". That is
correct when the binding is missing and CONFIDENTLY WRONG when the binding is
fine and the WinFsp driver is absent - the user runs it, pip reports success,
nothing changes, and there is no next move.

These tests pin all four combinations. They run on Linux on purpose: the
verdicts are pure functions over what the probes found, so the half that
matters is testable where the work happens.
"""
import os

import pytest

from demo_cli import deps


MSI = "winfsp.dev"
INJECT = "winfspy"


def _by_name(items, name):
    for d in items:
        if d.name == name:
            return d
    raise AssertionError(f"no dep named {name!r} in {[d.name for d in items]}")


# --------------------------------------------------------------------------
# The matrix. One row per real machine state.
# --------------------------------------------------------------------------

def test_neither_installed_names_both_in_dependency_order():
    driver, binding = deps.judge_filesystem_guard(None, None, False, None)
    assert driver.present is False and MSI in driver.fix
    assert binding.present is False and INJECT in binding.fix
    # Order matters and the report must reflect it: the binding builds against
    # the driver, so a user working top-down succeeds. Reversed, the inject
    # fails and they conclude the tool is broken.
    assert [driver.name, binding.name] == ["winfsp driver", "winfspy binding"]


def test_driver_missing_but_binding_present_does_not_tell_you_to_reinstall_it():
    """THE regression this module was written for.

    The binding is installed and importable-in-principle; the driver is not
    there. The old code printed the inject command, which succeeds and fixes
    nothing.
    """
    driver, binding = deps.judge_filesystem_guard(
        None, None, True, "RuntimeError: cannot find winfsp-x64.dll")
    assert driver.present is False and MSI in driver.fix
    assert binding.present is False
    assert binding.fix == "", "must not send the user to re-inject the binding"
    assert "driver" in binding.detail.lower()


def test_binding_missing_but_driver_present_is_one_unelevated_command():
    dll = r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll"
    driver, binding = deps.judge_filesystem_guard(
        r"C:\Program Files (x86)\WinFsp", dll, False, None)
    assert driver.present is True and driver.detail == dll
    assert binding.present is False and INJECT in binding.fix
    assert MSI not in binding.fix, "no elevation is needed for this one"


def test_both_present_but_still_broken_shows_the_real_error_not_a_guess():
    """Out of hypotheses is a legitimate state. Inventing a third cause is not."""
    dll = r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll"
    _, binding = deps.judge_filesystem_guard(
        r"C:\Program Files (x86)\WinFsp", dll, True,
        "ImportError: DLL load failed while importing _bindings")
    assert binding.present is False
    assert "DLL load failed" in binding.detail
    assert binding.fix == "", "we do not know the fix, so we must not name one"


def test_both_present_and_working():
    dll = r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll"
    driver, binding = deps.judge_filesystem_guard(
        r"C:\Program Files (x86)\WinFsp", dll, True, None)
    assert driver.present is True and binding.present is True
    assert [d.status() for d in (driver, binding)] == ["ok", "ok"]


def test_a_partial_install_is_not_reported_as_no_install():
    """Install directory present, runtime DLL absent. `import winfspy` cannot
    tell this apart from "never installed", which is precisely why the driver
    is probed on disk rather than inferred from the import."""
    driver, _ = deps.judge_filesystem_guard(
        r"C:\Program Files (x86)\WinFsp", None, True, "RuntimeError: no dll")
    assert driver.present is False
    assert "partial" in driver.detail
    assert "not installed" not in driver.detail


# --------------------------------------------------------------------------
# winfsp_dll: the probe under the driver verdict.
# --------------------------------------------------------------------------

def test_winfsp_dll_finds_either_architecture(tmp_path):
    binp = tmp_path / "bin"
    binp.mkdir()
    (binp / "winfsp-x86.dll").write_bytes(b"\x00")
    assert deps.winfsp_dll(str(tmp_path)) == str(binp / "winfsp-x86.dll")


def test_winfsp_dll_on_a_directory_without_one(tmp_path):
    (tmp_path / "bin").mkdir()
    assert deps.winfsp_dll(str(tmp_path)) is None
    assert deps.winfsp_dll(None) is None


# --------------------------------------------------------------------------
# Elevation. A warning about what this shell implies, never a failure.
# --------------------------------------------------------------------------

def test_an_unelevated_shell_says_nothing():
    """Silence is the correct output for the normal case - a permanently
    yellow line trains people to ignore the report."""
    assert deps.judge_elevation(False, windows=True) is None
    assert deps.judge_elevation(False, windows=False) is None


def test_an_elevated_windows_shell_names_the_bypass_it_enables():
    d = deps.judge_elevation(True, windows=True)
    assert d is not None
    assert d.status() == "warn", "setup legitimately runs elevated; not a fail"
    assert "backing" in d.detail and "bypass" in d.detail
    assert "agent" in d.fix


def test_an_elevated_posix_shell_names_a_different_risk():
    """There is no ACL separation on Linux, so quoting one would be false.
    Root there threatens the ledger and the recovery points instead."""
    d = deps.judge_elevation(True, windows=False)
    assert "ledger" in d.detail
    assert "backing" not in d.detail


# --------------------------------------------------------------------------
# The backing ACL: protection the user believes in and may not have.
# --------------------------------------------------------------------------

def test_an_unprotected_project_has_nothing_to_check():
    assert deps.judge_backing_lock(False, None, r"C:\p.real") is None


def test_a_locked_backing_passes():
    d = deps.judge_backing_lock(True, True, r"C:\p.real")
    assert d.present is True and d.status() == "ok"


def test_cannot_tell_is_a_warning_and_never_reported_as_open():
    """protect.is_locked returns None for an unreadable icacls. Rendering that
    as "not locked" would be a false alarm; as "locked" would be a false
    all-clear. It is its own answer."""
    d = deps.judge_backing_lock(True, None, r"C:\p.real")
    assert d.status() == "warn"
    assert "cannot tell" in d.detail
    assert "NOT LOCKED" not in d.detail


def test_an_unlocked_backing_is_a_hard_failure():
    """Every other check can still be green here: the mount runs, the hook is
    registered, receipts are written - and anything can write the real files
    directly. That is the worst state this project recognises."""
    d = deps.judge_backing_lock(True, False, r"C:\p.real")
    assert d.status() == "fail"
    assert "bypass" in d.detail
    assert "protect" in d.fix


# --------------------------------------------------------------------------
# External tools, and the one that was missing entirely.
# --------------------------------------------------------------------------

def test_mitmdump_is_checked_at_all():
    """It was not. pg_dump and git were checked; the egress layer's only
    dependency was not, so egress could be wholly absent with a green report."""
    names = [d.name for d in deps.check_all(None)]
    assert "mitmdump" in names


def test_the_mitmproxy_fix_exposes_the_binary_not_just_the_library():
    """cli.py locates the proxy with shutil.which, so a plain `pipx inject`
    would install mitmproxy into the venv and leave mitmdump off PATH - the
    command has to carry --include-apps or it silently does not work."""
    d = deps.judge_external_tool("mitmdump", None, "egress off",
                                 "pipx inject --include-apps demo-cli mitmproxy")
    assert "--include-apps" in d.fix


def test_a_present_tool_carries_no_fix():
    d = deps.judge_external_tool("git", "/usr/bin/git", "x", "install git")
    assert d.present is True
    assert d.as_check() == ("ok", "git", "/usr/bin/git")


def test_as_check_appends_the_fix_only_when_something_is_wrong():
    missing = deps.judge_external_tool("git", None, "context off", "install git")
    status, name, detail = missing.as_check()
    assert status == "warn" and "->" in detail and "install git" in detail


# --------------------------------------------------------------------------
# check_all on this machine: must not raise, must not invent Windows lines.
# --------------------------------------------------------------------------

def test_check_all_is_quiet_about_winfsp_off_windows():
    names = [d.name for d in deps.check_all(None)]
    if os.name != "nt":
        assert not any("winfsp" in n for n in names)


def test_check_all_survives_a_project_that_does_not_exist():
    """doctor runs before setup, from anywhere. It must never be the thing
    that crashes - a diagnostic that cannot run diagnoses nothing."""
    out = deps.check_all("/nonexistent/project/path")
    assert out and all(isinstance(d, deps.Dep) for d in out)

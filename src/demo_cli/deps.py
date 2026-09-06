"""What this machine is missing, and the exact command that fixes it.

WHY THIS IS A MODULE AND NOT FOUR LINES IN cmd_doctor
-----------------------------------------------------
Three times in this project a diagnostic reported a *permissions* cause for a
problem that had nothing to do with permissions (2026-09-02: teardown's
ERROR_ACCESS_DENIED was WinFsp not yet released; doctor's "cannot tell" was a
directory that did not exist; undo's "needs Administrator" was a child that
already HAD Administrator). The generalisation written up that day:

    a diagnostic that can only name one cause will name it wrongly.

`cli.py:496` is the fourth instance, and it sits in the first command a new
user runs. It catches any ImportError from `import winfspy` and always says
"pipx inject demo-cli winfspy" - which is confidently wrong advice when the
binding is installed fine and the WinFsp DRIVER is what is absent. The user
runs the suggested command, it succeeds, nothing changes, and they have no
next move.

So the driver and the binding are probed SEPARATELY here, and the four
combinations get four different messages. That is the whole reason this file
exists; everything else in it is bookkeeping.

TESTABILITY
-----------
The probes touch the Windows registry and PATH. The VERDICTS are pure
functions over what the probes found, so the interesting half runs on Linux -
the same reason fsguard.py holds judgement and fsmount.py holds plumbing.
"""

import os
import shutil
from dataclasses import dataclass
from typing import List, Optional, Tuple

# The two things WinFsp puts on disk that we can look for without loading it.
_WINFSP_REG_KEYS = (
    r"SOFTWARE\WOW6432Node\WinFsp",   # what winfspy itself reads
    r"SOFTWARE\WinFsp",               # 32-bit registry view
)
_WINFSP_DEFAULT_DIR = r"C:\Program Files (x86)\WinFsp"
_WINFSP_DLLS = ("winfsp-x64.dll", "winfsp-x86.dll")


@dataclass
class Dep:
    """One prerequisite, and what to do about it.

    `present` is deliberately Optional[bool]. "missing" and "I could not tell"
    are different answers and must not share a line - the same discipline
    protect.is_locked already applies.
    """
    name: str
    present: Optional[bool]
    detail: str
    fix: str = ""
    # What breaks without it. A dep whose absence only disables an optional
    # layer is a warning; one that silently removes protection the user thinks
    # they have is a failure.
    severity: str = "warn"          # "ok" | "warn" | "fail"

    def status(self) -> str:
        return "ok" if self.present else self.severity

    def as_check(self) -> Tuple[str, str, str]:
        """The (status, label, detail) triple render_doctor consumes."""
        detail = self.detail
        if not self.present and self.fix:
            detail = f"{detail}  ->  {self.fix}"
        return (self.status(), self.name, detail)


# ---------------------------------------------------------------------------
# Probes. Thin, Windows-touching, deliberately dumb.
# ---------------------------------------------------------------------------

def winfsp_driver_dir() -> Optional[str]:
    """Where WinFsp is installed, or None.

    Registry first because that is what winfspy consults, so agreeing with it
    means we diagnose the binding's actual view rather than our own guess. The
    filesystem fallback covers a registry we cannot read (rare, but a denied
    read must not be reported as an absent driver).
    """
    if os.name != "nt":
        return None
    try:
        import winreg
        for key in _WINFSP_REG_KEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as h:
                    value, _ = winreg.QueryValueEx(h, "InstallDir")
                    if value and os.path.isdir(value):
                        return value
            except OSError:
                continue
    except Exception:
        pass
    if os.path.isdir(_WINFSP_DEFAULT_DIR):
        return _WINFSP_DEFAULT_DIR
    return None


def winfsp_dll(install_dir: Optional[str]) -> Optional[str]:
    """The runtime DLL under an install directory, or None.

    An install directory without the DLL is a broken or partial install -
    which reads identically to "not installed" from `import winfspy`, and is
    exactly the distinction this module exists to draw.
    """
    if not install_dir:
        return None
    for name in _WINFSP_DLLS:
        path = os.path.join(install_dir, "bin", name)
        if os.path.isfile(path):
            return path
    return None


def winfspy_state() -> Tuple[bool, Optional[str]]:
    """(package installed?, import error text or None).

    find_spec answers "is it on disk" without executing it; the import answers
    "does it actually load". Only asking the second question is what conflates
    a missing package with a package that cannot find its driver.
    """
    try:
        import importlib.util
        found = importlib.util.find_spec("winfspy") is not None
    except Exception:
        found = False
    if not found:
        return (False, None)
    try:
        import winfspy  # noqa: F401
        return (True, None)
    except Exception as exc:
        return (True, f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Verdicts. Pure functions over probe results - these run anywhere.
# ---------------------------------------------------------------------------

def judge_filesystem_guard(driver_dir: Optional[str], dll: Optional[str],
                           pkg_installed: bool,
                           import_error: Optional[str]) -> List[Dep]:
    """The four-way split that cli.py:496 collapsed into one message.

        driver   binding   what to actually do
        -------  --------  ------------------------------------------------
        absent   absent    install WinFsp, THEN inject winfspy (order matters:
                           the binding builds against the driver's headers)
        absent   present   install WinFsp. Injecting again changes nothing,
                           which is the wrong advice we used to give.
        present  absent    inject winfspy. One command, no elevation.
        present  present   if it still will not import, print the REAL error
                           rather than guessing a third time.
    """
    inject = "pipx inject demo-cli winfspy   (or: pip install winfspy)"
    msi = ("install WinFsp from https://winfsp.dev with the Developer "
           "feature enabled (needs Administrator, one time)")

    driver_ok = bool(dll)
    if driver_dir and not dll:
        driver = Dep("winfsp driver", False,
                     f"found {driver_dir} but no runtime DLL under bin\\ - "
                     f"a partial install", msi)
    elif driver_ok:
        driver = Dep("winfsp driver", True, dll or "")
    else:
        driver = Dep("winfsp driver", False, "not installed", msi)

    if not pkg_installed:
        binding = Dep("winfspy binding", False, "not installed", inject)
    elif import_error and not driver_ok:
        # The import failed AND the driver is missing. Do not blame the
        # binding for the driver's absence - say so, and point at the driver
        # line rather than repeating its fix here.
        binding = Dep("winfspy binding", False,
                      "installed, but cannot load without the driver above",
                      "", severity="warn")
    elif import_error:
        # Driver present, package present, still broken. We are out of
        # guesses, so show the exception instead of inventing a cause.
        binding = Dep("winfspy binding", False,
                      f"installed and the driver is present, but it will not "
                      f"import - {import_error}", "")
    else:
        binding = Dep("winfspy binding", True, "importable")

    return [driver, binding]


def judge_elevation(elevated: bool, windows: bool) -> Optional[Dep]:
    """Elevation is not an error - it is only wrong for the AGENT's shell.

    The guard's separation on Windows is a privilege difference: the backing
    directory is Administrators-only, so an unelevated agent physically cannot
    reach around the mount. Launch the agent from an elevated shell and that
    property is gone, silently, with every other check still green.

    doctor can only see the shell it was run from, so this is a warning about
    what that shell implies - never a failure. Setup legitimately runs
    elevated.
    """
    if not elevated:
        return None
    what = ("the backing directory is Administrators-only, so an agent "
            "launched from HERE could write it directly and bypass the guard"
            if windows else
            "an agent launched from HERE could rewrite the ledger and the "
            "recovery points it is supposed to be constrained by")
    return Dep("shell is elevated", False, what,
               "launch the agent from a normal shell; let setup/protect "
               "elevate themselves when they need to")


def judge_backing_lock(backing_exists: bool, locked: Optional[bool],
                       backing: str, project: str = "<project>") -> Optional[Dep]:
    """Is the ACL that makes protection real still in place?

    protect sets this lock once. Nothing has ever re-checked it, so a project
    whose ACL was reset - by an icacls /reset, a restore, a copy through a
    filesystem that drops ACLs - keeps reporting as protected while the
    backing is writable by anything. That is protection the user believes in
    and does not have, which this project has agreed is the worst state.
    """
    if not backing_exists:
        return None                      # not protected; nothing to check
    if locked is True:
        return Dep("backing locked", True, backing)
    if locked is None:
        return Dep("backing locked", None,
                   f"cannot tell for {backing} (icacls unavailable or "
                   f"unreadable)", "", severity="warn")
    # The real path, not a <placeholder>. A remediation the reader has to
    # edit before running is one they may edit wrongly, and doctor already
    # knows which project it is looking at.
    return Dep("backing locked", False,
               f"NOT LOCKED - {backing} is writable without elevation, so the "
               f"guard can be bypassed by writing the real files directly",
               f"demo_cli protect {project}   (re-applies the lock; moves nothing)",
               severity="fail")


def judge_external_tool(name: str, path: Optional[str], purpose: str,
                        fix: str) -> Dep:
    """pg_dump, git, mitmdump: shelled out to, never imported.

    mitmdump is the one that was missing entirely from doctor. It cannot be a
    packaging dependency either: cli.py locates it with shutil.which, so
    declaring `mitmproxy` as an extra would install the library into demo_cli's
    venv and still leave the BINARY off PATH - metadata that lies.
    """
    return Dep(name, bool(path), path or f"missing ({purpose})", "" if path else fix)


# ---------------------------------------------------------------------------
# The assembled report.
# ---------------------------------------------------------------------------

def check_all(project_root: Optional[str] = None) -> List[Dep]:
    """Every prerequisite, in the order a new user has to satisfy them."""
    from . import protect as protect_mod

    out: List[Dep] = []

    out.append(judge_external_tool(
        "git", shutil.which("git"), "branch/remote context off", "install git"))
    pg = shutil.which("pg_dump") and shutil.which("pg_restore")
    out.append(judge_external_tool(
        "postgres tools", pg and shutil.which("pg_dump"),
        "postgres snapshot disabled", "install the postgresql client tools"))
    out.append(judge_external_tool(
        "mitmdump", shutil.which("mitmdump"), "egress layer disabled",
        "pipx inject --include-apps demo-cli mitmproxy"))

    if os.name == "nt":
        d = winfsp_driver_dir()
        out.extend(judge_filesystem_guard(d, winfsp_dll(d), *winfspy_state()))

    elev = judge_elevation(protect_mod.is_elevated(), os.name == "nt")
    if elev:
        out.append(elev)

    if project_root:
        backing = protect_mod.backing_for(project_root)
        exists = os.path.isdir(backing)
        lock = judge_backing_lock(
            exists, protect_mod.is_locked(backing) if exists else None, backing,
            project_root)
        if lock:
            out.append(lock)

    return out

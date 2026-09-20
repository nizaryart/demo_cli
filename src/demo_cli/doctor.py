"""System diagnostics and health checks.

Provides environment validation, dependency status, host hook audit,
filesystem guard mount verification, and the `doctor` command.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import io
import json
import os
import shutil
import sys
import tempfile
from typing import List, Optional, Tuple

from . import config as config_mod
from .config import load_config
from . import deps as deps_mod
from . import fsmount, mountstate, render, protect as protect_mod
from .receipts import load_all_receipts, load_receipts, iter_all_receipts
from .version import __version__

# Every host demo_cli can hook, and where each keeps its registration.
# `nested` distinguishes the two config shapes: Claude Code and Codex wrap
# handlers in a group ({matcher, hooks:[{type, command}]}), Cursor lists them
# flat ({command, failClosed}).
# `module` is the hooks submodule that owns that host's settings_snippet(), so
# "what we would install today" is read from the installer itself rather than
# retyped here. A retyped duplicate is how _walk_cost once measured a
# different ignore set than the copy it was bounding.
#            label          directory   filename         event                   command                nested  module
_HOSTS = [
    ("claude code", ".claude", "settings.json", "PreToolUse",            "demo_cli hook",        True,  "claude_code"),
    ("cursor",      ".cursor", "hooks.json",    "beforeShellExecution",  "demo_cli hook-cursor", False, "cursor"),
    ("codex",       ".codex",  "hooks.json",    "PreToolUse",            "demo_cli hook-codex",  True,  "codex"),
]


def _our_entries(data, event: str, command: str, nested: bool):
    """[(matcher_or_None, handler)] for every entry of OURS in `data`.

    One traversal, used for the installed file and for settings_snippet()
    alike - the two have the same shape, which is what lets doctor compare
    them without a second description of either.
    """
    out = []
    for block in ((data.get("hooks") if isinstance(data, dict) else None) or {}).get(event, []) or []:
        if not isinstance(block, dict):
            continue
        handlers = (block.get("hooks") or []) if nested else [block]
        for h in handlers:
            if isinstance(h, dict) and h.get("command") == command:
                out.append((block.get("matcher") if nested else None, h))
    return out


def _read_host_config(path):
    """The parsed file, or None. utf-8-sig: a BOM must not read as absent."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def _hook_installed(path, event: str = "PreToolUse",
                    command: str = "demo_cli hook", nested: bool = True) -> bool:
    data = _read_host_config(path)
    return bool(data is not None and _our_entries(data, event, command, nested))


def _compare_entries(installed, expected, nested: bool):
    """(stale, inert) - short phrases naming what does not match.

    `stale` is a field we would write differently today; the fix is a re-run
    of install-hook. `inert` is stronger: the entry is registered and cannot
    fire, which is worse than not being installed at all because every other
    signal reports it as present. codex.py documents the one case - a handler
    without "type" is "accepted by the file parser and then SILENTLY IGNORED
    - no error, no warning, no hook, no protection". Both nested hosts use
    that handler shape; Cursor's flat entry has no "type" to miss.
    """
    stale, inert = [], []
    by_matcher = {}
    for matcher, handler in installed:
        by_matcher.setdefault(matcher, handler)
    for matcher, want in expected:
        if matcher not in by_matcher:
            stale.append(f"no entry for {matcher!r}" if matcher is not None
                         else "no entry")
            continue
        got = by_matcher[matcher]
        where = f" on {matcher!r}" if matcher is not None and len(expected) > 1 else ""
        if nested and "type" in want and "type" not in got:
            inert.append(f'handler{where} has no "type"')
        for key, value in want.items():
            if key in ("command", "type"):
                continue        # the match key, and the inert case above
            if key not in got:
                stale.append(f"{key} absent{where}, current {value!r}")
            elif got[key] != value:
                stale.append(f"{key} {got[key]!r}{where}, current {value!r}")
    return stale, inert


def _expected_entries(module: str, event: str, command: str, nested: bool):
    """What this version would install, read off the installer's own snippet."""
    import importlib
    mod = importlib.import_module(f".hooks.{module}", __package__)
    return _our_entries(mod.settings_snippet(), event, command, nested)


def _hook_check_rows(cfg):
    """[(status, label, detail)] - doctor's hook rows.

    Four states, where there used to be two. `inert` is a FAIL for the same
    reason the PATH check is: every other signal reports such an entry as
    present, so a soft row is how it stays broken.
    """
    rows = []
    for label, path, stale, inert in _host_hook_audit(cfg):
        flag = {"codex": " --codex", "cursor": " --cursor"}.get(label, "")
        name = f"hook: {label}"
        if path is None:
            rows.append(("warn", name,
                         f"not installed (demo_cli install-hook{flag})"))
        elif inert:
            rows.append(("fail", name,
                         f"{path}  ->  REGISTERED BUT INERT: {'; '.join(inert)}"))
        elif stale:
            rows.append(("warn", name,
                         f"{path}  ->  stale: {'; '.join(stale)}"
                         f"  ->  re-run: demo_cli install-hook{flag}"))
        else:
            rows.append(("ok", name, path))
    return rows


def _host_hook_audit(cfg):
    """[(label, path_or_None, stale, inert)] for every host.

    doctor answered "am I protected" with presence: one string compared, and
    `ok` printed. An entry written by an older version kept whatever it had -
    the raised hook timeout never reached anyone already installed, and there
    was no state between "not installed" and "ok" for doctor to say so in.
    """
    out = []
    for label, directory, filename, event, command, nested, module in _HOSTS:
        found, stale, inert = None, [], []
        for base in (cfg.project_root, os.path.expanduser("~")):
            path = os.path.join(base, directory, filename)
            data = _read_host_config(path)
            if data is None:
                continue
            installed = _our_entries(data, event, command, nested)
            if not installed:
                continue
            found = path
            stale, inert = _compare_entries(
                installed, _expected_entries(module, event, command, nested), nested)
            break
        out.append((label, found, stale, inert))
    return out


def _host_hook_status(cfg):
    """[(label, path_or_None)] - the view guarded.assess takes. One traversal
    behind it, in _host_hook_audit.

    doctor used to report a single 'claude code hook' row and look only in
    .claude, so a machine with Codex fully wired up was told 'not installed' by
    the one command whose job is answering 'am I protected'."""
    return [(label, path) for label, path, _stale, _inert in _host_hook_audit(cfg)]


def _hook_selftest(tool_name: str, command: str) -> bool:
    """Run a harmless destructive command through the real hook entrypoint,
    as the named tool (Bash or PowerShell), and confirm the ADAPTER turns it
    into a real decision.

    SCOPE, corrected 2026-09-17: this said it "proves the wiring end to end"
    and "catches a Windows install where only the Bash matcher got
    registered". It cannot. It builds its own payload and calls
    run_pretooluse IN-PROCESS - it never opens settings.json and never
    consults a matcher, so it passes identically whether PowerShell is
    registered or not. The missing matcher is caught by _host_hook_audit,
    which compares the file against settings_snippet(); this proves the
    adapter, and the receipts row below is what proves the wiring.
    """
    from .hooks.claude_code import run_pretooluse

    directory = tempfile.mkdtemp()
    previous_directory = os.getcwd()

    try:
        os.chdir(directory)

        with open(os.path.join(directory, "canary.txt"), "w", encoding="utf-8") as file:
            file.write("safe test file")

        # Force enforce mode inside the temporary test project.
        with open(os.path.join(directory, ".demo_cli.toml"), "w", encoding="utf-8") as file:
            file.write('mode = "enforce"\n')

        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {
                "command": command,
                "description": "demo_cli doctor self-test",
            },
            "cwd": directory,
        }

        output = io.StringIO()
        # Swallow the hook's stderr. It is a real run, so it emits the loud
        # "recovery point captured, undo with demo_cli undo <id>" banner - but
        # the canary lives in a temp directory that is deleted immediately, so
        # printing it would tell the user to undo something that no longer
        # exists, and would greet anyone running `doctor` for reassurance with
        # two alarming messages about deletions they never made.
        with contextlib.redirect_stderr(io.StringIO()):
            run_pretooluse(io.StringIO(json.dumps(payload)), output)

        raw = output.getvalue().strip()
        if not raw:
            return False

        response = json.loads(raw)
        hook_output = response.get("hookSpecificOutput", {})
        permission = hook_output.get("permissionDecision")

        return permission in {"allow", "deny", "ask"}

    finally:
        os.chdir(previous_directory)
        shutil.rmtree(directory, ignore_errors=True)


# (tool_name, synthetic destructive command) pairs the doctor self-test drives
# through the real hook entrypoint - one per shell Claude Code can launch.
_SELFTEST_PAYLOADS = [
    ("Bash", "rm -rf canary.txt"),
    ("PowerShell", "Remove-Item -Recurse -Force canary.txt"),
]


def _any_hook_installed(cfg) -> bool:
    project = os.path.join(cfg.project_root, ".claude", "settings.json")
    glob = os.path.expanduser("~/.claude/settings.json")
    return _hook_installed(project) or _hook_installed(glob)


def _mount_checks(cfg) -> List[tuple]:
    """Is the filesystem guard running RIGHT NOW, and can it be bypassed?

    Every other doctor check is paperwork - a config exists, a hook is
    registered, a binary is on PATH. A mount is different: it is a live
    process, and when it stops the directory it was serving simply is not
    there any more. Nothing else in this report would notice.

    That makes a STALE record a hard fail rather than a warning. "No record"
    means nobody started a guard, which is a choice. "Recorded but the process
    is gone" means somebody started one, believes it is running, and is not
    protected - the fourth appearance of installed-but-inert, and the only one
    where the user has positive reason to think otherwise.
    """
    st = mountstate.status(cfg)
    # Silent on platforms that cannot mount and where nobody has tried, so the
    # report does not grow a permanently-yellow line on Linux.
    if os.name != "nt" and not st.recorded:
        return []

    out: List[tuple] = []

    if not st.recorded:
        if not fsmount.available():
            # Deliberately does NOT name a cause. The driver/binding lines
            # above already did, separately and correctly; repeating a guess
            # here is how the wrong one got printed for three weeks.
            return [("warn", "filesystem guard",
                     "not running - see the winfsp lines above for why")]
        # Telling somebody to protect a project that is already protected
        # reads as the tool not knowing its own state. guarded.assess makes
        # the same distinction; this is the second copy of that message and
        # it had already drifted.
        protected = os.path.isdir(protect_mod.backing_for(cfg.project_root))
        return [("warn", "filesystem guard",
                 "protected but NOT RUNNING - demo_cli mount (elevated), or it "
                 "returns at your next logon" if protected else
                 "not running (demo_cli setup <project>)")]

    where = st.mountpoint or "?"
    age = f", up {st.age_minutes} min" if st.age_minutes is not None else ""

    if st.running is None:
        out.append(("warn", "filesystem guard",
                    f"recorded for {where} (pid {st.pid}) but its state cannot "
                    f"be checked from here"))
    elif st.stale:
        # TWO VERY DIFFERENT SITUATIONS WEAR THE SAME RECORD, and calling both
        # a failure cost a clean teardown a red FAIL on 2026-09-02.
        #
        #   backing still there -> the project IS protected and its guard died.
        #                          Real, dangerous, unguarded. fail.
        #   backing gone        -> the project was torn down and the record was
        #                          left behind. Nothing claims protection it
        #                          does not have; there is nothing to guard.
        #                          Untidy, not unsafe. warn.
        if os.path.isdir(protect_mod.backing_for(cfg.project_root)):
            out.append(("fail", "filesystem guard",
                        f"RECORDED BUT NOT RUNNING - pid {st.pid} is gone, so {where} "
                        f"is unguarded while the record says otherwise. "
                        f"Restart it, or clear with: demo_cli unmount"))
        else:
            out.append(("warn", "filesystem guard",
                        f"not running, and this project is not protected - the "
                        f"record for pid {st.pid} is left over from a teardown. "
                        f"Clear it with: demo_cli unmount --root {cfg.project_root}"))
    else:
        out.append(("ok", "filesystem guard", f"mounted at {where} (pid {st.pid}{age})"))

    # THE BACKING LOCK IS CHECKED IN deps.py, NOT HERE.
    #
    # It used to be in both, and the two copies had already drifted: this one
    # said "warn", deps says "fail", for the same fact. A doctor report that
    # prints one label twice with two severities is worse than either verdict
    # alone - the reader cannot tell which to believe. Observed on real
    # hardware 2026-09-05, both lines visible in one report.
    #
    # deps wins the merge on coverage: it keys on the backing directory
    # EXISTING, so it also catches a protected project whose guard has never
    # started, whereas st.backing is only populated once a mount is recorded.
    # It wins on severity too - the comment that used to sit here noted the
    # bypass was demonstrated live on 2026-08-25 by an ordinary Remove-Item
    # the guard never saw, and a demonstrated bypass is not a warning.
    if not st.backing and st.running:
        out.append(("warn", "filesystem guard storage",
                    "IN MEMORY - contents are lost on unmount. "
                    "For real work: demo_cli protect <project>"))

    if st.log and os.path.exists(st.log):
        out.append(("ok", "guard log", st.log))
    return out


def _egress_checks(cfg) -> List[tuple]:
    """Is the egress proxy running, is the CA bundle available, and is NO_PROXY sane?

    Provides visibility into the wire-level network guard:
      - Is mitmproxy listening on the egress port?
      - Is the root CA cert generated (and on Windows, trusted in the user store)?
      - If HTTPS_PROXY is active in the environment, does NO_PROXY correctly
        bypass localhost and model provider endpoints?
    """
    from . import guarded

    port = 8080
    if getattr(cfg, "egress", None) and isinstance(cfg.egress, dict):
        try:
            port = int(cfg.egress.get("port", 8080))
        except (ValueError, TypeError):
            port = 8080

    mitm_installed = bool(shutil.which("mitmdump"))
    up = guarded.port_open(port)

    # If mitmdump is missing and no proxy is listening, keep doctor focused
    # (deps.py already emits the single mitmdump install line).
    if not mitm_installed and not up:
        return []

    rows: List[tuple] = []

    # 1. Proxy listener
    if up:
        rows.append(("ok", "egress proxy", f"listening on :{port}"))
    else:
        rows.append(("warn", "egress proxy",
                     f"not running on :{port} (start: demo_cli egress --port {port}, "
                     f"or demo_cli guarded <agent>)"))

    # 2. CA Certificate & Trust Store
    ca = guarded.ca_bundle()
    if ca and os.path.isfile(ca):
        if os.name == "nt":
            cer = os.path.normpath(
                os.path.join(os.path.expanduser("~/.mitmproxy"), "mitmproxy-ca-cert.cer"))
            trusted = False
            if os.path.isfile(cer):
                try:
                    import subprocess
                    r = subprocess.run(["certutil", "-user", "-viewstore", "Root", "mitmproxy"],
                                       capture_output=True, text=True, timeout=2)
                    trusted = (r.returncode == 0 and "mitmproxy" in (r.stdout or "").lower())
                except Exception:
                    pass
            if trusted:
                rows.append(("ok", "egress CA", f"trusted in Windows user store ({cer})"))
            else:
                rows.append(("warn", "egress CA",
                             f"present ({ca}) but not trusted in Windows store (demo_cli egress --trust-ca)"))
        else:
            rows.append(("ok", "egress CA", f"generated ({ca})"))
    else:
        rows.append(("warn", "egress CA",
                     "not generated yet (run demo_cli egress once to generate)"))

    # 3. Shell NO_PROXY environment
    hp = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    np = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    if hp:
        missing = [h for h in ("api.anthropic.com", "api.openai.com") if h not in np]
        missing_lh = [h for h in ("localhost", "127.0.0.1") if h not in np]
        all_missing = missing + missing_lh
        if all_missing:
            rows.append(("warn", "egress NO_PROXY",
                         f"HTTPS_PROXY active but NO_PROXY missing {', '.join(all_missing)} "
                         "(model streams may be intercepted)"))
        else:
            rows.append(("ok", "egress NO_PROXY",
                         "configured in shell, localhost and model endpoints bypassed"))
    else:
        rows.append(("ok", "egress NO_PROXY",
                     "defaults protect localhost and model endpoints (anthropic, openai, gemini)"))

    # 4. Configured Policy Reflection (if [egress] is defined in .demo_cli.toml)
    if getattr(cfg, "egress", None) and isinstance(cfg.egress, dict) and cfg.egress:
        emode = cfg.egress.get("mode", cfg.mode)
        strict = cfg.egress.get("strict_unknown_hosts", False)
        saas = cfg.egress.get("saas_hosts") or []
        detail = f"mode={emode}"
        if strict:
            detail += ", strict_unknown=true"
        if saas:
            detail += f", {len(saas)} SaaS host(s)"
        rows.append(("ok", "egress policy", detail))

    return rows


def cmd_doctor(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    checks = []

    pyok = sys.version_info >= (3, 9)
    checks.append(("ok" if pyok else "fail", "python >= 3.9",
                   f"{sys.version_info.major}.{sys.version_info.minor}"))
    checks.append(("ok", "mode", cfg.mode))
    # "found" is not "usable". A .demo_cli.toml written by PowerShell carries a
    # UTF-8 BOM, fails to parse, and used to disable the guard silently while
    # this line still reported ok because source_path was set.
    if cfg.config_error:
        checks.append(("fail", "config parses", f"NO - {cfg.config_error}"))
    elif cfg.source_path:
        checks.append(("ok", "config parses", cfg.source_path))
    else:
        checks.append(("warn", "config", "using defaults (run: demo_cli init)"))

    ws = cfg.workspace
    # This check used to CREATE the workspace, parents and all. On a protected
    # Windows project the parent is the mount point, so running doctor while
    # the guard was down left a real directory there and the guard could never
    # remount - the diagnostic bricking the thing it diagnosed (2026-08-29).
    refused = config_mod.ensure_workspace(cfg)
    if refused:
        checks.append(("warn", "workspace", refused))
    else:
        writable = True
        try:
            probe = os.path.join(ws, ".write_probe")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
        except Exception:
            writable = False
        checks.append(("ok" if writable else "fail", "workspace writable", ws))

    # Prerequisites, each with the command that fixes it. Moved out to deps.py
    # so the verdicts are pure functions testable off Windows - and so the
    # WinFsp driver stops being conflated with the winfspy binding, which is
    # the fourth time a diagnostic in this project has been able to name only
    # one cause and named it wrongly.
    checks.extend(d.as_check() for d in deps_mod.check_all(cfg.project_root))

    checks.extend(_hook_check_rows(cfg))
    hook = _any_hook_installed(cfg)   # Claude Code specifically - gates the self-test below

    checks.extend(_mount_checks(cfg))
    checks.extend(_egress_checks(cfg))

    # THE check that actually predicts protection: is `demo_cli` resolvable on
    # PATH? Claude Code launches the hook as a bare `demo_cli hook` command in a
    # fresh shell; if it is not on PATH there, the hook silently never runs and
    # the user THINKS they are protected. A registered-but-unreachable hook is
    # worse than no hook, so this is a hard fail, not a warning.
    on_path = shutil.which("demo_cli")
    checks.append(("ok" if on_path else "fail", "demo_cli on PATH",
                   on_path if on_path else
                   "NOT FOUND - Claude Code will silently skip the hook. "
                   "Install with pipx or keep your venv active."))

    # End-to-end self-test: feed a known destructive command through the SAME
    # hook entrypoint Claude Code uses, once per shell tool (Bash, PowerShell),
    # and confirm each comes back as a real decision. This proves the wiring
    # end to end, not just that files exist.
    if hook and on_path:
        for tool_name, command in _SELFTEST_PAYLOADS:
            try:
                selftest_ok = _hook_selftest(tool_name, command)
                checks.append(("ok" if selftest_ok else "fail", f"hook self-test ({tool_name})",
                               "a test delete was intercepted and snapshotted"
                               if selftest_ok else
                               "hook did NOT intercept a test command - see logs"))
            except Exception as exc:
                checks.append(("warn", f"hook self-test ({tool_name})", f"could not run ({exc})"))

    # THE question every other check only approximates: has this guard actually
    # run? Config, registration and PATH are all paperwork - a receipt written
    # by an AGENT is evidence. Three separate times the failure mode has been
    # "installed, looks fine, protecting nothing" (Codex config shape, Codex
    # stale session, Windows BOM), and each time a receipt would have said so.
    has_receipts = False
    by_agent = {}
    for r in iter_all_receipts(cfg.receipts_path):
        has_receipts = True
        aid = r.get("agent_id", "unknown")
        by_agent[aid] = max(by_agent.get(aid, ""), r.get("timestamp", ""))
    agents = [a for a in by_agent if a not in ("cli", "unknown")]
    if agents:
        newest = max(by_agent[a] for a in agents)
        try:
            age = _dt.datetime.now(_dt.timezone.utc) - _dt.datetime.fromisoformat(newest)
            when = f"{int(age.total_seconds() // 60)} min ago" if age.total_seconds() < 86400 \
                   else f"{age.days}d ago"
        except Exception:
            when = newest[:19]
        checks.append(("ok", "ACTIVE (agent receipts)",
                       f"{', '.join(sorted(agents))} - last {when}"))
    elif has_receipts:
        checks.append(("warn", "ACTIVE (agent receipts)",
                       "receipts exist but only from the CLI - no agent has been "
                       "gated yet. Run one command through the agent to confirm."))
    else:
        checks.append(("warn", "ACTIVE (agent receipts)",
                       "NONE - nothing has ever been gated here. Installed is not "
                       "the same as protecting; run one command through the agent."))

    render.render_doctor(checks, __version__)
    return 0 if all(s != "fail" for s, _, _ in checks) else 1


__all__ = [
    "_HOSTS",
    "_our_entries",
    "_read_host_config",
    "_hook_installed",
    "_compare_entries",
    "_expected_entries",
    "_hook_check_rows",
    "_host_hook_audit",
    "_host_hook_status",
    "_hook_selftest",
    "_SELFTEST_PAYLOADS",
    "_any_hook_installed",
    "_mount_checks",
    "_egress_checks",
    "cmd_doctor",
]


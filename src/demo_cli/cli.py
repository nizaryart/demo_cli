"""Command-line interface.

Thin by design: parse arguments, call into the library, render the result.
No safety logic lives here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import recovery, render
from .config import CONFIG_NAME, load_config
from .context import Intent, normalize_env
from .decide import CONTEXT_MISMATCH, ESCALATE
from .diff import diff_entry
from .guard import Guard
from .receipts import verify_chain, find_receipt, share_card, load_receipts
from .version import __version__

_EXIT = {ESCALATE: 2, CONTEXT_MISMATCH: 1}

_CONFIG_TEMPLATE = """\
# demo_cli configuration. All fields are optional; defaults are safe.
# Docs: https://github.com/WePwn/demo_cli

mode = "shadow"            # "shadow" observes only; "enforce" gates actions

[workspace]
dir = ".demo_cli"          # receipts + recovery points live here (per project)

# [approval]
# key_env = "DEMO_CLI_APPROVER_KEY"   # env var holding the structural-approval key

# Declare your real targets so environment is known, not guessed.
# [[target]]
# match = "production"     # substring matched against the resolved target ref
# env = "production"
# recovery = "snapshot"    # snapshot | none   (attest is reserved)
"""


def _build_intent(a) -> Intent:
    return Intent(
        env=normalize_env(getattr(a, "intent_env", None)),
        branch=getattr(a, "intent_branch", None),
        cwd=getattr(a, "intent_cwd", None),
        remote=getattr(a, "intent_remote", None),
        scope=getattr(a, "intent_scope", None),
        reasoning=getattr(a, "reason", None),
    )


def cmd_check(a) -> int:
    if getattr(a, "no_color", False):
        render.set_color(False)
    guard = Guard(mode=a.mode)
    result = guard.evaluate(
        a.command,
        target_path=a.target, explicit_db=a.db, db_url=a.db_url,
        intent=_build_intent(a), actual_env=a.actual_env,
        approval_token=a.approval_token,
        agent_id="cli", session_id="cli",
    )
    if getattr(a, "json", False):
        print(json.dumps(render.result_json(result, __version__), indent=2))
    elif getattr(a, "quiet", False):
        print(render.quiet_line(result))
    else:
        render.render_result(result, __version__)
    return _EXIT.get(result.decision.decision, 0)


def _resolve_entry(cfg, a):
    """Pick a recovery entry: by id if given, else scoped by --target, else latest."""
    rid = getattr(a, "id", None)
    if rid:
        return recovery.find(cfg.recovery_dir, rid)
    ref = os.path.abspath(a.target) if getattr(a, "target", None) else None
    return recovery.latest(cfg.recovery_dir, ref)


def cmd_undo(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    entry = _resolve_entry(cfg, a)
    ok = recovery.restore_entry(entry) if entry else False
    # Pass the ledger we searched: "not found" is unactionable without it, and
    # the recovery dir follows the project root, which follows the directory a
    # guard was started from.
    render.render_restore(entry, ok, __version__,
                          recovery_dir=cfg.recovery_dir,
                          requested_id=getattr(a, "id", None))
    return 0 if ok else 1


def cmd_diff(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    entry = _resolve_entry(cfg, a)
    if not entry:
        print(render.c("No recovery point matched. Try `demo_cli log`.", "red"))
        return 1
    render.render_diff(entry, diff_entry(entry), __version__)
    return 0


def cmd_log(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    render.render_log(recovery.load_entries(cfg.recovery_dir), __version__)
    return 0


def cmd_verify(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    v = verify_chain(cfg.receipts_path)
    render.render_verify(v, __version__)
    return 0 if v.ok else 1


def cmd_report(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    v = verify_chain(cfg.receipts_path)
    if not os.path.exists(cfg.receipts_path):
        print("No receipts yet. Run some commands through `demo_cli check` first.")
        return 0
    total = 0
    by_decision = {}
    recovered = 0
    with open(cfg.receipts_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            total += 1
            by_decision[r.get("decision", "?")] = by_decision.get(r.get("decision", "?"), 0) + 1
            if r.get("recovery_point"):
                recovered += 1
    print(render.c(f"\ndemo_cli {__version__}  shadow report\n", "dim"))
    print(render.kv("receipts", total))
    print(render.kv("chain", "intact" if v.ok else f"TAMPERED at line {v.broken_at}"))
    print(render.kv("recovery points", recovered))
    for k, n in sorted(by_decision.items()):
        print(render.kv("  " + k, n))
    print()
    return 0


def cmd_receipt(a) -> int:
    """`demo_cli receipt --share [id]` — print a copy-pasteable proof card for a
    single receipt (the latest, or one by id). `--list` shows recent receipt ids.
    """
    cfg = load_config(getattr(a, "root", None))

    if getattr(a, "list", False):
        rows = load_receipts(cfg.receipts_path)
        if not rows:
            print("No receipts yet. Run some commands through the hook or `demo_cli check` first.")
            return 0
        print(render.c(f"\ndemo_cli {__version__}  receipts\n", "dim"))
        print("  " + render.c(f"{'id':<10}{'when':<27}{'decision':<16}action", "dim"))
        for r in rows[-20:]:
            rid = str(r.get("receipt_id", "?"))[:8]
            ts = str(r.get("timestamp", "?"))[:25]
            dec = str(r.get("decision", "?"))[:15]
            act = str(r.get("action_raw", ""))
            if len(act) > 40:
                act = act[:37] + "..."
            print(f"  {rid:<10}{ts:<27}{dec:<16}{act}")
        print()
        return 0

    receipt = find_receipt(cfg.receipts_path, getattr(a, "id", None))
    if not receipt:
        if getattr(a, "id", None):
            print(f"No receipt matched id '{a.id}'. Try `demo_cli receipt --list`.")
        else:
            print("No receipts yet. Run some commands through the hook or `demo_cli check` first.")
        return 1

    # --share is the default (and only) rendering today; the card is plain text
    # so it can be pasted straight into a forum, PR, or issue.
    print(share_card(receipt))
    return 0


# Every host demo_cli can hook, and where each keeps its registration.
# `nested` distinguishes the two config shapes: Claude Code and Codex wrap
# handlers in a group ({matcher, hooks:[{type, command}]}), Cursor lists them
# flat ({command, failClosed}).
#            label          directory   filename         event                   command                nested
_HOSTS = [
    ("claude code", ".claude", "settings.json", "PreToolUse",            "demo_cli hook",        True),
    ("cursor",      ".cursor", "hooks.json",    "beforeShellExecution",  "demo_cli hook-cursor", False),
    ("codex",       ".codex",  "hooks.json",    "PreToolUse",            "demo_cli hook-codex",  True),
]


def _hook_installed(path, event: str = "PreToolUse",
                    command: str = "demo_cli hook", nested: bool = True) -> bool:
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception:
        return False
    for block in (data.get("hooks", {}) or {}).get(event, []) or []:
        if not isinstance(block, dict):
            continue
        handlers = (block.get("hooks") or []) if nested else [block]
        for h in handlers:
            if isinstance(h, dict) and h.get("command") == command:
                return True
    return False


def _host_hook_status(cfg):
    """[(label, path_or_None)] - where each host's hook is registered, if it is.

    doctor used to report a single 'claude code hook' row and look only in
    .claude, so a machine with Codex fully wired up was told 'not installed' by
    the one command whose job is answering 'am I protected'."""
    out = []
    for label, directory, filename, event, command, nested in _HOSTS:
        found = None
        for base in (cfg.project_root, os.path.expanduser("~")):
            path = os.path.join(base, directory, filename)
            if _hook_installed(path, event, command, nested):
                found = path
                break
        out.append((label, found))
    return out


def _hook_selftest(tool_name: str, command: str) -> bool:
    """Run a harmless destructive command through the real hook entrypoint,
    as the named tool (Bash or PowerShell), and confirm it comes back as a
    real decision. This proves the wiring end to end, not just that files
    exist - and running it once per shell tool is what catches a Windows
    install where only the Bash matcher got registered (PowerShell commands
    would otherwise silently skip the hook)."""
    import contextlib
    import io
    import json
    import os
    import shutil
    import tempfile

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
    from . import fsmount, mountstate, protect as protect_mod

    st = mountstate.status(cfg)
    # Silent on platforms that cannot mount and where nobody has tried, so the
    # report does not grow a permanently-yellow line on Linux.
    if os.name != "nt" and not st.recorded:
        return []

    out: List[tuple] = []

    if not st.recorded:
        detail = ("not running (demo_cli protect <project>, then demo_cli mount)"
                  if fsmount.available() else
                  "not running; winfspy not importable "
                  "(pipx inject demo-cli winfspy)")
        return [("warn", "filesystem guard", detail)]

    where = st.mountpoint or "?"
    age = f", up {st.age_minutes} min" if st.age_minutes is not None else ""

    if st.running is None:
        out.append(("warn", "filesystem guard",
                    f"recorded for {where} (pid {st.pid}) but its state cannot "
                    f"be checked from here"))
    elif st.stale:
        out.append(("fail", "filesystem guard",
                    f"RECORDED BUT NOT RUNNING - pid {st.pid} is gone, so {where} "
                    f"is unguarded while the record says otherwise. "
                    f"Restart it, or clear with: demo_cli unmount"))
    else:
        out.append(("ok", "filesystem guard", f"mounted at {where} (pid {st.pid}{age})"))

    # A mount over a writable backing directory is bypassable by anything that
    # writes to the backing path instead - demonstrated live on 2026-08-25 by
    # an ordinary Remove-Item that the guard never saw.
    if st.backing:
        locked = protect_mod.is_locked(st.backing)
        if locked is True:
            out.append(("ok", "backing locked", st.backing))
        elif locked is False:
            out.append(("warn", "backing locked",
                        f"NO - {st.backing} is writable directly, which bypasses "
                        f"the guard entirely. Re-run `demo_cli protect` from an "
                        f"Administrator shell"))
        else:
            out.append(("warn", "backing locked",
                        f"cannot tell for {st.backing}"))
    elif st.running:
        out.append(("warn", "filesystem guard storage",
                    "IN MEMORY - contents are lost on unmount. "
                    "For real work: demo_cli protect <project>"))

    if st.log and os.path.exists(st.log):
        out.append(("ok", "guard log", st.log))
    return out


def cmd_doctor(a) -> int:
    import shutil
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
    writable = True
    try:
        os.makedirs(ws, exist_ok=True)
        probe = os.path.join(ws, ".write_probe")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
    except Exception:
        writable = False
    checks.append(("ok" if writable else "fail", "workspace writable", ws))

    pg = bool(shutil.which("pg_dump") and shutil.which("pg_restore"))
    checks.append(("ok" if pg else "warn", "postgres tools",
                   "pg_dump/pg_restore found" if pg else "missing (postgres snapshot disabled)"))
    git = bool(shutil.which("git"))
    checks.append(("ok" if git else "warn", "git", "found" if git else "missing (branch/remote context off)"))

    hosts = _host_hook_status(cfg)
    for label, path in hosts:
        flag = {"codex": " --codex", "cursor": " --cursor"}.get(label, "")
        checks.append(("ok" if path else "warn", f"hook: {label}",
                       path or f"not installed (demo_cli install-hook{flag})"))
    hook = _any_hook_installed(cfg)   # Claude Code specifically - gates the self-test below

    checks.extend(_mount_checks(cfg))

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
    import datetime as _dt
    from .receipts import load_receipts
    rows = load_receipts(cfg.receipts_path)
    by_agent = {}
    for r in rows:
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
    elif rows:
        checks.append(("warn", "ACTIVE (agent receipts)",
                       "receipts exist but only from the CLI - no agent has been "
                       "gated yet. Run one command through the agent to confirm."))
    else:
        checks.append(("warn", "ACTIVE (agent receipts)",
                       "NONE - nothing has ever been gated here. Installed is not "
                       "the same as protecting; run one command through the agent."))

    render.render_doctor(checks, __version__)
    return 0 if all(s != "fail" for s, _, _ in checks) else 1


def cmd_prune(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    if a.keep is None and a.older_than is None:
        print("Specify --keep N or --older-than DAYS. Receipts are never pruned (audit trail).")
        return 1
    removed = recovery.prune(cfg.recovery_dir, keep=a.keep, older_than_days=a.older_than)
    freed = sum(e.get("_freed_bytes", 0) for e in removed)
    print(render.c(f"\ndemo_cli {__version__}  prune\n", "dim"))
    print(render.kv("removed", f"{len(removed)} recovery point(s)"))
    print(render.kv("freed", render._size(freed)))
    print(render.kv("note", "receipts untouched (tamper-evident audit trail)"))
    print()
    return 0


def cmd_status(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    v = verify_chain(cfg.receipts_path)
    total = v.entries if v.ok else 0
    if not v.ok and os.path.exists(cfg.receipts_path):
        with open(cfg.receipts_path, encoding="utf-8") as f:
            total = sum(1 for line in f if line.strip())
    info = {
        "mode": cfg.mode,
        "hook": _any_hook_installed(cfg),
        "config": cfg.source_path,
        "receipts": total,
        "chain": "intact" if v.ok else (f"TAMPERED at line {v.broken_at}"
                                        if os.path.exists(cfg.receipts_path) else "none yet"),
        "recovery_points": len(recovery.load_entries(cfg.recovery_dir)),
        "workspace": cfg.workspace,
    }
    render.render_status(info, __version__)
    return 0


def cmd_init(a) -> int:
    path = os.path.join(os.getcwd(), CONFIG_NAME)
    if os.path.exists(path) and not a.force:
        print(f"{CONFIG_NAME} already exists. Use --force to overwrite.")
        return 1
    template = _CONFIG_TEMPLATE
    mode = getattr(a, "mode", None)
    if mode:
        template = template.replace('mode = "shadow"', f'mode = "{mode}"', 1)
    # encoding="utf-8" writes NO byte-order mark. That matters: PowerShell's
    # Out-File -Encoding utf8 adds one, TOML parsers reject it, and the guard
    # used to fail open on every command as a result. `init` exists partly so a
    # user never has to hand-write this file.
    with open(path, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"Wrote {path}" + (f" (mode = {mode})" if mode else ""))
    return 0


def cmd_install_hook(a) -> int:
    if getattr(a, "codex", False):
        from .hooks.codex import settings_snippet, install_into_hooks_json
        snippet = settings_snippet()
        if a.print:
            print(json.dumps(snippet, indent=2))
            return 0
        target = (os.path.expanduser("~/.codex/hooks.json") if a.scope == "global"
                  else os.path.join(os.getcwd(), ".codex", "hooks.json"))
        install_into_hooks_json(target)
        print(f"Installed PreToolUse hook into {target}")
        print("Gates Codex shell commands (Bash) AND file edits (apply_patch).")
        print()
        print("  ACTION REQUIRED - the hook is INERT until both of these are done:")
        print("   1. RESTART Codex. Hook config is read once, at session start; a")
        print("      session already running keeps whatever it loaded and this")
        print("      install has no effect on it (silently - no warning either side).")
        print("   2. Run  /hooks  in Codex and approve this entry. Trust is tracked")
        print("      by hash, so re-approve after any upgrade.")
        print()
        print("  Until then: no gating, no receipts, no protection.")
        if a.scope != "global":
            print()
            print("  TIP: --scope global installs to ~/.codex/hooks.json so every Codex")
            print("       session is covered. A per-project guard is missing precisely")
            print("       in the projects you did not think to protect. Outside a")
            print("       configured project it runs in shadow (observe + snapshot,")
            print("       never block), so it is safe to enable everywhere.")
        return 0
    if getattr(a, "cursor", False):
        from .hooks.cursor import settings_snippet, install_into_hooks_json
        snippet = settings_snippet()
        if a.print:
            print(json.dumps(snippet, indent=2))
            return 0
        target = (os.path.expanduser("~/.cursor/hooks.json") if a.scope == "global"
                  else os.path.join(os.getcwd(), ".cursor", "hooks.json"))
        install_into_hooks_json(target)
        print(f"Installed beforeShellExecution hook into {target}")
        print("demo_cli will now fire before each Cursor shell command (failClosed: true).")
        return 0
    from .hooks.claude_code import settings_snippet, install_into_settings
    snippet = settings_snippet()
    if a.print:
        print(json.dumps(snippet, indent=2))
        return 0
    target = (os.path.expanduser("~/.claude/settings.json") if a.scope == "global"
              else os.path.join(os.getcwd(), ".claude", "settings.json"))
    install_into_settings(target)
    print(f"Installed PreToolUse hook into {target}")
    print("demo_cli will now fire automatically before each Bash command.")
    return 0


def cmd_hook(a) -> int:
    from .hooks.claude_code import run_pretooluse
    return run_pretooluse(sys.stdin, sys.stdout)


def cmd_hook_cursor(a) -> int:
    from .hooks.cursor import run_before_shell
    return run_before_shell(sys.stdin, sys.stdout)


def cmd_hook_codex(a) -> int:
    from .hooks.codex import run_pretooluse
    return run_pretooluse(sys.stdin, sys.stdout)


_SHELL_GUARD_SNIPPET = r'''# >>> demo_cli shell guard >>>
# Gate commands that bypass the PreToolUse hook: Claude Code `!` mode, or any
# command typed directly into the shell. Bash only. The DEBUG trap fires BEFORE
# each command; on a blocking decision it stops the command from running.
#   * non-interactive shell (Claude Code `!` mode is `bash -c`): `extdebug`
#     cannot be enabled from a startup file, so we TERMINATE the shell before the
#     command runs.
#   * interactive shell: skip the command via `extdebug` so the terminal survives.
# A cheap pre-filter avoids spawning demo_cli for obviously-safe commands (it
# shares the string classifier's frontier by design - obfuscation is the syscall
# guard's job, not this).
#
# TWO ESCAPE HATCHES, and they exist because of a real lockout on 2026-08-25.
# A syntax error committed to cli.py made `demo_cli` unimportable. This trap
# runs on EVERY command in EVERY bash, it read the resulting non-zero exit as
# "the guard refused", and every command in every shell started failing -
# including the ones needed to fix the file. The recovery path was the one
# thing that could not be done from a shell.
#
#   DEMO_CLI_DISABLE=1   turns the guard off entirely. `export` is a builtin
#                        and matches no pattern below, so it still works from
#                        a shell that is otherwise stuck.
#   the sanity probe     below distinguishes "the guard said no" from "the
#                        guard is broken". Our own failures must fail OPEN -
#                        that is already the rule inside guard-shell, and a
#                        package that will not even import is the same class
#                        of failure, just earlier.
if [ -n "$BASH_VERSION" ] && [ -z "$DEMO_CLI_DISABLE" ] && command -v demo_cli >/dev/null 2>&1; then
  case $- in *i*) shopt -s extdebug 2>/dev/null ;; esac
  __demo_cli_shell_guard() {
    case "$BASH_COMMAND" in
      # Skip the `eval '<cmd>' < /dev/null` wrapper Claude Code !-mode uses:
      # eval re-fires the DEBUG trap on its EXPANSION (the real command), which
      # is handled there exactly once. Processing the wrapper too = double
      # snapshot. (guard-shell keeps an eval-unwrap for direct/test calls.)
      demo_cli*|__demo_cli_shell_guard*|eval\ *) return 0 ;;
      *rm\ *|*rmdir*|*mkfs*|*shred*|*truncate*|*\ dd\ *|*git\ *|*Remove-Item*|*\>\ *|*DROP\ *|*TRUNCATE\ *|*DELETE\ FROM*|*shutil.rmtree*)
        if ! demo_cli guard-shell "$BASH_COMMAND"; then
          # Did the guard REFUSE, or is it broken? A package that cannot
          # import exits non-zero too, and reading that as a refusal locks the
          # user out of their own shell. One cheap probe tells them apart, and
          # it only ever runs on the failure path.
          if ! demo_cli --version >/dev/null 2>&1; then
            echo "demo_cli: guard is not working (demo_cli itself will not run) - allowing." >&2
            echo "demo_cli: silence it with  export DEMO_CLI_DISABLE=1" >&2
            return 0
          fi
          echo "demo_cli: blocked \"$BASH_COMMAND\" before it ran." >&2
          case $- in
            *i*) return 1 ;;                           # interactive: skip, keep the shell
            *)   kill -TERM $$ 2>/dev/null; exit 1 ;;  # non-interactive (!-mode): terminate
          esac
        fi ;;
      *) return 0 ;;
    esac
  }
  trap '__demo_cli_shell_guard' DEBUG
fi
# <<< demo_cli shell guard <<<
'''


def cmd_guard_shell(a) -> int:
    """(internal) Evaluate a raw shell command (e.g. from a bash DEBUG trap) so
    commands that bypass the PreToolUse hook - Claude Code `!` mode, or direct
    shell use - still get classified, snapshotted, and gated. In enforce mode a
    blocking decision returns exit 1, which under `shopt -s extdebug` aborts the
    command. Fail-open on our own errors: never brick the user's shell."""
    import re
    from .guard import Guard
    from .context import Intent
    command = " ".join(getattr(a, "argv", None) or []).strip()
    # Claude Code `!`-mode delivers the command wrapped as `eval '<cmd>' < /dev/null`.
    # classify would flag the `eval` as opaque execution and block everything;
    # unwrap it so we judge the real command. (The DEBUG trap also re-fires on
    # eval's expansion, so a destructive inner command is caught either way.)
    m = re.match(r"""^\s*eval\s+(['"])(.*)\1\s*(?:<\s*\S+\s*)*$""", command, re.S)
    if m:
        command = m.group(2).strip()
    if not command or command.startswith("demo_cli") or "guard-shell" in command:
        return 0
    try:
        guard = Guard(config=load_config())
        result = guard.evaluate(command, intent=Intent(reasoning="shell/!-mode"),
                                agent_id="shell", session_id="bang-mode")
    except Exception as exc:
        sys.stderr.write(f"demo_cli: shell-guard internal error, stepping aside ({exc})\n")
        return 0
    if guard.mode != "enforce":
        if result.decision.is_blocking:
            sys.stderr.write(f"demo_cli [shadow/shell] {result.decision.decision}: {result.decision.reason}\n")
        elif result.recovery_entry:
            rid = result.recovery_entry.get("id", "")
            sys.stderr.write(f"demo_cli [shadow/shell] snapshot {rid}; undo: demo_cli undo {rid}\n")
        return 0
    if result.decision.is_blocking:
        sys.stderr.write(f"demo_cli ⛔ shell-guard blocked: {result.decision.reason}\n")
        return 1
    if result.recovery_entry:
        rid = result.recovery_entry.get("id", "")
        sys.stderr.write(f"demo_cli ✅ shell-guard snapshot {rid}; undo: demo_cli undo {rid}\n")
    return 0


def cmd_install_shell_guard(a) -> int:
    if getattr(a, "print", False):
        print(_SHELL_GUARD_SNIPPET)
        return 0
    script = os.path.expanduser("~/.demo_cli_shellguard.sh")
    with open(script, "w", encoding="utf-8") as f:
        f.write(_SHELL_GUARD_SNIPPET)
    rc = os.path.expanduser("~/.bashrc")
    marker = "demo_cli_shellguard.sh"
    already = os.path.exists(rc) and marker in open(rc, encoding="utf-8").read()
    if not already:
        with open(rc, "a", encoding="utf-8") as f:
            # BASH_ENV makes a NON-interactive `bash -c` (Claude Code !-mode,
            # which does not read ~/.bashrc) source the guard. We deliberately do
            # NOT `source` it into the interactive shell: guarding the human's own
            # prompt is out of scope (demo_cli gates the agent, not the user) and
            # would fire the trap on ordinary interactive commands.
            f.write(
                f"\n# demo_cli shell guard (gates non-interactive bash -c, e.g. Claude Code !-mode)\n"
                f"export BASH_ENV={script}\n")
    print(f"Wrote {script}")
    print(f"{'Already configured' if already else 'Set BASH_ENV'} in {rc} "
          "(gates non-interactive `bash -c` / !-mode; the interactive shell is left alone).")
    print("Relaunch Claude Code from a NEW terminal so !-mode inherits BASH_ENV.")
    print()
    print("If demo_cli ever stops working, the guard steps aside rather than")
    print("blocking your shell. To turn it off outright:  export DEMO_CLI_DISABLE=1")
    return 0


def cmd_mount(a) -> int:
    """Mount the Windows filesystem guard - the behavioural layer for Windows,
    where ptrace does not exist. Everything written through the mount is
    intercepted below the syscall boundary, so obfuscation in the command text
    cannot route around it."""
    from .fsmount import available, mount
    if not available():
        if os.name != "nt":
            print("The filesystem guard is Windows-only (WinFsp).")
            print("On Linux the equivalent layer is:  demo_cli run <cmd>")
        else:
            print("winfspy is not importable. Install WinFsp from winfsp.dev")
            print("with the Developer feature enabled, then:")
            print("  pipx inject demo-cli winfspy      (if demo_cli came from pipx)")
            print("  pip install winfspy               (otherwise)")
        return 1
    if os.path.exists(a.mountpoint):
        print(f"{a.mountpoint} already exists.")
        print("WinFsp CREATES the mount point itself, so it must not exist yet.")
        print("Pick a new path, e.g. a 'myproject-guarded' beside your project.")
        return 1
    backing = getattr(a, "backing", None)
    if backing and not os.path.isdir(backing):
        print(f"The backing directory {backing} does not exist.")
        print("It is where your files actually live. To convert an existing")
        print("project, run:  demo_cli protect <your project>")
        return 1
    if not backing:
        # Said before the mount starts, not buried in the banner afterwards.
        print("NOTE: no --backing given, so this mount is IN MEMORY.")
        print("      Everything written inside it is LOST when you unmount.")
        print("      For real work:  demo_cli protect <your project>")

    if getattr(a, "foreground", False):
        return _mount_foreground(a, backing)
    return _mount_detached(a, backing)


def _mount_foreground(a, backing) -> int:
    """Run the mount in this process, printing to this terminal.

    Now the opt-in rather than the default. Useful for debugging, and for
    watching the [fs] lines live.
    """
    from . import fsmount, mountstate
    from .fsmount import mount

    cfg = load_config(fsmount.config_anchor(os.path.abspath(a.mountpoint), backing))
    mountstate.write(cfg, os.getpid(), os.path.abspath(a.mountpoint), backing)
    try:
        mount(a.mountpoint, debug=a.debug, backing=backing)
    finally:
        mountstate.clear(cfg)
    return 0


def _mount_detached(a, backing) -> int:
    """Start the guard as a background process that outlives this terminal.

    THE DEFAULT, deliberately. The mount used to block, so closing the window
    silently stopped all protection - and a guard that stops protecting you
    without saying so is worse than one you never installed, because you go on
    believing you are covered. That is the fourth costume of "installed but
    inert" in this project; the other three each cost hours.

    Detached, the [fs] lines have no terminal to reach, and those lines are
    the only channel carrying recovery-point ids. They go to mount.log, and
    doctor points at it.
    """
    import subprocess
    import time

    from . import fsmount, mountstate

    cfg = load_config(fsmount.config_anchor(os.path.abspath(a.mountpoint), backing))

    existing = mountstate.status(cfg)
    if existing.running:
        print(f"A filesystem guard is already running for {existing.mountpoint}")
        print(f"  pid {existing.pid}.  Stop it with:  demo_cli unmount")
        return 1

    os.makedirs(cfg.workspace, exist_ok=True)
    log = mountstate.log_path(cfg)

    argv = [sys.executable, "-m", "demo_cli", "mount", a.mountpoint, "--foreground"]
    if backing:
        argv += ["--backing", backing]
    if a.debug:
        argv += ["--debug"]

    # Detach properly on both platforms: no console, no process group tie, so
    # closing the terminal or pressing Ctrl+C here does not take the guard down
    # with it.
    kwargs = {}
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        # CREATE_NO_WINDOW as well: DETACHED_PROCESS alone still let Windows
        # pop an empty console for python.exe, which looks like something went
        # wrong and shows nothing, because the child's output is redirected to
        # mount.log.
        CREATE_NO_WINDOW = 0x08000000
        kwargs["creationflags"] = (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
                                   | CREATE_NO_WINDOW)
    else:
        kwargs["start_new_session"] = True

    with open(log, "a", encoding="utf-8") as fh:
        proc = subprocess.Popen(argv, stdout=fh, stderr=fh,
                                stdin=subprocess.DEVNULL, **kwargs)

    # Give it long enough to fail loudly. A mount that dies immediately - a
    # mount point that already exists, WinFsp not installed - must not be
    # reported as started.
    time.sleep(2.0)
    if proc.poll() is not None:
        print(render.c("The filesystem guard exited immediately.", "red"))
        print(f"  see {log}")
        try:
            tail = open(log, encoding="utf-8", errors="replace").read().splitlines()[-8:]
            for line in tail:
                print("  " + line)
        except OSError:
            pass
        return 1

    mountstate.write(cfg, proc.pid, os.path.abspath(a.mountpoint), backing)
    print(render.c(f"\ndemo_cli {__version__}  filesystem guard running\n", "dim"))
    print(render.kv("mounted at", os.path.abspath(a.mountpoint)))
    if backing:
        print(render.kv("backing", backing))
    print(render.kv("pid", proc.pid))
    print(render.kv("log", log))
    print("\n  " + render.c("It keeps running after you close this window.", "dim"))
    print("  " + render.c("Stop it with:  demo_cli unmount", "dim") + "\n")
    return 0


def cmd_unmount(a) -> int:
    """Stop a detached filesystem guard."""
    import signal

    from . import mountstate

    cfg = load_config(getattr(a, "root", None))
    st = mountstate.status(cfg)
    if not st.recorded:
        print("No filesystem guard is recorded for this project.")
        print(f"  looked in {mountstate.state_path(cfg)}")
        return 1
    if st.stale:
        print(f"The recorded guard (pid {st.pid}) is no longer running.")
        print("  Clearing the stale record.")
        mountstate.clear(cfg)
        return 0
    try:
        os.kill(st.pid, signal.SIGTERM)
    except PermissionError:
        # Expected, and a GOOD sign: the guard runs elevated so the backing
        # directory is out of reach, which also means a non-elevated process
        # cannot kill it. An agent cannot stop the thing watching it. Say what
        # to do rather than reporting a bare access error.
        print(f"Could not stop pid {st.pid}: access denied.")
        print("  The guard runs elevated, which is why an ordinary process")
        print("  cannot kill it. Stop it from an Administrator shell.")
        return 1
    except Exception as exc:
        print(f"Could not stop pid {st.pid}: {exc}")
        print("  The record is left in place; the guard may still be running.")
        return 1
    mountstate.clear(cfg)
    print(f"Stopped the filesystem guard at {st.mountpoint} (pid {st.pid}).")
    return 0


def _show_plan(plan, title: str, next_steps: List[str]) -> int:
    """Print what is about to happen, then require the word 'yes'.

    This command MOVES SOMEBODY'S PROJECT. It prints the exact before and after
    paths and waits, every time, unless --yes is passed deliberately. A y/N
    prompt is too easy to hit by reflex for an operation this size.
    """
    from . import protect as protect_mod

    print(render.c(f"\ndemo_cli {__version__}  {title}\n", "dim"))
    print(render.kv("project", plan.source))
    print(render.kv("files move to", plan.backing))
    print(render.kv("mount point", plan.mountpoint))
    print(render.kv("lock backing", "yes (Administrators + SYSTEM only)"
                    if plan.will_lock and protect_mod.is_elevated() else "no"))
    for w in plan.warnings:
        print("\n  " + render.c("! " + w, "yellow"))
    for pr in plan.problems:
        print("\n  " + render.c("x " + pr, "red"))
    if not plan.ok:
        print()
        return 1
    print()
    for line in next_steps:
        print("  " + render.c(line, "dim"))
    print()
    return 0


def cmd_protect(a) -> int:
    """Relocate a project so its own path can become the guarded mount point."""
    from . import protect as protect_mod

    plan = protect_mod.plan_protect(a.project, getattr(a, "backing", None),
                                    lock=not getattr(a, "no_lock", False))
    mount_cmd = f"demo_cli mount {plan.mountpoint} --backing {plan.backing}"
    rc = _show_plan(plan, "protect", ["After this, start the guard with:",
                                      f"  {mount_cmd}",
                                      "Undo at any time with:",
                                      f"  demo_cli unprotect {plan.source}"])
    if rc:
        return rc
    if not getattr(a, "yes", False):
        if input("  Type 'yes' to move your project: ").strip().lower() != "yes":
            print("  Nothing was changed.\n")
            return 1
    for step in protect_mod.protect(plan):
        print("  " + render.c(step, "green"))
    print("\n  " + render.c(f"Now run:  {mount_cmd}", "dim") + "\n")
    return 0


def cmd_unprotect(a) -> int:
    """Move a protected project back and remove the lock."""
    from . import protect as protect_mod

    plan = protect_mod.plan_unprotect(a.project, getattr(a, "backing", None))
    print(render.c(f"\ndemo_cli {__version__}  unprotect\n", "dim"))
    print(render.kv("files move back to", plan.source))
    print(render.kv("from", plan.backing))
    for w in plan.warnings:
        print("\n  " + render.c("! " + w, "yellow"))
    for pr in plan.problems:
        print("\n  " + render.c("x " + pr, "red"))
    print()
    if not plan.ok:
        return 1
    if not getattr(a, "yes", False):
        if input("  Type 'yes' to restore: ").strip().lower() != "yes":
            print("  Nothing was changed.\n")
            return 1
    for step in protect_mod.unprotect(plan):
        print("  " + render.c(step, "green"))
    print()
    return 0


def cmd_egress(a) -> int:
    """Start the egress guard: an mitmproxy addon that gates destructive external
    / SaaS API calls on the network wire. Shells out to the installed `mitmdump`
    (demo_cli never imports mitmproxy), mirroring how recovery.py uses pg_dump."""
    import shutil
    mitm = shutil.which("mitmdump")
    if not mitm:
        print("mitmdump not found. Install it (external tool, not bundled):")
        print("  pipx install mitmproxy      # then re-run demo_cli egress")
        return 1
    here = os.path.dirname(os.path.abspath(__file__))       # .../<pkgparent>/demo_cli
    loader = os.path.join(here, "egress_addon.py")          # thin package-aware entry
    pkg_parent = os.path.dirname(here)                       # so `import demo_cli` works
    port = getattr(a, "port", 8080)
    mode = "enforce" if getattr(a, "enforce", False) else load_config().mode
    ca = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    print(render.c(f"\ndemo_cli egress guard  (mode={mode}, port={port})\n", "dim"))
    print("1) point the agent's traffic at the proxy:")
    print(f"     export HTTPS_PROXY=http://localhost:{port}  HTTP_PROXY=http://localhost:{port}")
    print("2) let it read TLS by trusting mitmproxy's CA (first run generates it):")
    print(f"     export REQUESTS_CA_BUNDLE={ca}   NODE_EXTRA_CA_CERTS={ca}")
    print("3) relaunch the agent from that shell. Ctrl-C here stops the guard.\n")
    # mitmdump runs its OWN Python; add demo_cli's location so the addon imports.
    env = dict(os.environ, DEMO_CLI_EGRESS_MODE=mode,
               PYTHONPATH=pkg_parent + os.pathsep + os.environ.get("PYTHONPATH", ""))
    os.execve(mitm, [mitm, "-s", loader, "--listen-port", str(port), "-q"], env)


def cmd_run(a) -> int:
    """Run a command under the behavioral (syscall) guard [Linux only].

    Complements the pre-execution string guard: it does not read the command
    text, it watches the syscalls, so obfuscated / indirected destruction that
    the classifier misses is still snapshotted before it happens.
    """
    argv = [t for t in (getattr(a, "argv", None) or []) if t != "--"]
    if not argv:
        print("usage: demo_cli run [--deny] <command> [args...]")
        return 1
    try:
        from .syscall_guard import run_supervised
        return run_supervised(argv, config=load_config(), deny=getattr(a, "deny", False))
    except RuntimeError as exc:  # e.g. non-Linux
        print(f"demo_cli run: {exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="demo_cli",
        description="A pre-execution safety layer for AI coding agents: "
                    "preview, snapshot, undo, and a tamper-evident receipt of every decision.",
    )
    p.add_argument("--version", action="version", version=f"demo_cli {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="disable coloured output")
    common.add_argument("--root", metavar="DIR",
                        help="project whose ledger to use, instead of resolving one "
                             "from the current directory. A filesystem guard mounted "
                             "elsewhere writes elsewhere; this is how you reach it")
    sub = p.add_subparsers(dest="cmd")

    ch = sub.add_parser("check", parents=[common], help="evaluate one command before it runs")
    ch.add_argument("command")
    ch.add_argument("--target", default=None, help="file or directory to snapshot")
    ch.add_argument("--db", default=None, help="sqlite database path")
    ch.add_argument("--db-url", default=None, help="postgres connection url")
    ch.add_argument("--mode", choices=("shadow", "enforce"), default=None)
    ch.add_argument("--actual-env", default=None, help="assert the real environment")
    ch.add_argument("--intent-env", default=None, help="environment the agent believes it is in")
    ch.add_argument("--intent-branch", default=None)
    ch.add_argument("--intent-cwd", default=None)
    ch.add_argument("--intent-remote", default=None)
    ch.add_argument("--intent-scope", default=None)
    ch.add_argument("--reason", default=None, help="the agent's stated reasoning (why-ledger)")
    ch.add_argument("--approval-token", default=None, help="structural-approval token")
    ch.add_argument("--json", action="store_true", help="machine-readable output")
    ch.add_argument("--quiet", action="store_true", help="one-line summary")
    ch.set_defaults(func=cmd_check)

    un = sub.add_parser("undo", parents=[common], help="restore a recovery point (latest, or by id)")
    un.add_argument("id", nargs="?", default=None, help="recovery point id (see `demo_cli log`)")
    un.add_argument("--target", default=None)
    un.set_defaults(func=cmd_undo)

    df = sub.add_parser("diff", parents=[common], help="show what changed since a recovery point")
    df.add_argument("id", nargs="?", default=None, help="recovery point id (see `demo_cli log`)")
    df.add_argument("--target", default=None)
    df.set_defaults(func=cmd_diff)

    lg = sub.add_parser("log", parents=[common], help="list captured recovery points")
    lg.set_defaults(func=cmd_log)

    vf = sub.add_parser("verify", parents=[common], help="verify the receipt hash-chain")
    vf.set_defaults(func=cmd_verify)

    rp = sub.add_parser("report", parents=[common], help="summarise recorded decisions (shadow report)")
    rp.set_defaults(func=cmd_report)

    rc = sub.add_parser("receipt", parents=[common],
                        help="show a copy-pasteable proof card for a receipt")
    rc.add_argument("id", nargs="?", default=None,
                    help="receipt id (see `demo_cli receipt --list`); default: latest")
    rc.add_argument("--share", action="store_true",
                    help="print the shareable proof card (default action)")
    rc.add_argument("--list", action="store_true",
                    help="list recent receipt ids instead of printing a card")
    rc.set_defaults(func=cmd_receipt)

    st = sub.add_parser("status", parents=[common], help="show mode, hook, receipts, recovery points")
    st.set_defaults(func=cmd_status)

    dc = sub.add_parser("doctor", parents=[common], help="check the install across this environment")
    dc.set_defaults(func=cmd_doctor)

    pr = sub.add_parser("prune", parents=[common], help="delete old recovery points (receipts kept)")
    pr.add_argument("--keep", type=int, default=None, help="retain the N most recent points")
    pr.add_argument("--older-than", type=int, default=None, metavar="DAYS",
                    help="delete points older than DAYS")
    pr.set_defaults(func=cmd_prune)

    it = sub.add_parser("init", parents=[common], help=f"write a starter {CONFIG_NAME}")
    it.add_argument("--force", action="store_true")
    it.add_argument("--mode", choices=("shadow", "enforce"), default=None,
                    help="write the config in this mode (default: shadow). Saves "
                         "hand-editing the file, which on Windows is how a BOM "
                         "gets in and silently disables the guard.")
    it.set_defaults(func=cmd_init)

    ih = sub.add_parser("install-hook", parents=[common],
                        help="wire the safety hook into Claude Code, Cursor, or Codex")
    ih.add_argument("--cursor", action="store_true",
                    help="install the Cursor beforeShellExecution hook (into .cursor/hooks.json) "
                         "instead of the Claude Code PreToolUse hook")
    ih.add_argument("--codex", action="store_true",
                    help="install the Codex PreToolUse hook (into .codex/hooks.json) "
                         "instead of the Claude Code PreToolUse hook")
    ih.add_argument("--scope", choices=("project", "global"), default="project")
    ih.add_argument("--print", action="store_true", help="print the settings snippet instead of writing")
    ih.set_defaults(func=cmd_install_hook)

    hk = sub.add_parser("hook", parents=[common], help="(internal) Claude Code PreToolUse entrypoint; reads JSON on stdin")
    hk.set_defaults(func=cmd_hook)

    hc = sub.add_parser("hook-cursor", parents=[common],
                        help="(internal) Cursor beforeShellExecution entrypoint; reads JSON on stdin")
    hc.set_defaults(func=cmd_hook_cursor)

    hx = sub.add_parser("hook-codex", parents=[common],
                        help="(internal) Codex PreToolUse entrypoint; reads JSON on stdin")
    hx.set_defaults(func=cmd_hook_codex)

    rn = sub.add_parser("run", parents=[common],
                        help="run a command under the behavioral (syscall) guard [Linux]")
    rn.add_argument("--deny", action="store_true",
                    help="block destructive syscalls instead of snapshot-then-allow")
    rn.add_argument("argv", nargs=argparse.REMAINDER,
                    help="the command to run under the guard (e.g. demo_cli run rm -rf ./x)")
    rn.set_defaults(func=cmd_run)

    isg = sub.add_parser("install-shell-guard", parents=[common],
                         help="gate `!`-mode / direct shell commands via a bash DEBUG-trap [bash]")
    isg.add_argument("--print", action="store_true", help="print the snippet instead of installing")
    isg.set_defaults(func=cmd_install_shell_guard)

    gs = sub.add_parser("guard-shell", parents=[common],
                        help="(internal) evaluate a raw shell command; used by the shell-guard DEBUG trap")
    gs.add_argument("argv", nargs=argparse.REMAINDER)
    gs.set_defaults(func=cmd_guard_shell)

    mt = sub.add_parser("mount", parents=[common],
                        help="mount the filesystem guard [Windows]")
    mt.add_argument("mountpoint",
                    help="a path that does NOT yet exist (WinFsp creates it), "
                         "or a drive letter like X: (a directory is preferred - "
                         "Claude Code will not use a bare drive root as its cwd)")
    mt.add_argument("--backing", metavar="DIR",
                    help="directory holding the real files (STAGE 2). Without "
                         "it the mount is in memory and its contents are LOST "
                         "on unmount - fine for a demo, not for real work")
    mt.add_argument("--foreground", action="store_true",
                    help="run in this terminal instead of detaching. The guard "
                         "then stops when the window closes - which is why it is "
                         "no longer the default")
    mt.add_argument("--debug", action="store_true", help="verbose WinFsp logging")
    mt.set_defaults(func=cmd_mount)

    um = sub.add_parser("unmount", parents=[common],
                        help="stop a detached filesystem guard [Windows]")
    um.set_defaults(func=cmd_unmount)

    pr = sub.add_parser("protect", parents=[common],
                        help="relocate a project so its path becomes the guarded mount [Windows]")
    pr.add_argument("project", help="the project directory to protect")
    pr.add_argument("--backing", metavar="DIR",
                    help="where the real files go (default: <project>.real)")
    pr.add_argument("--no-lock", action="store_true",
                    help="skip the ACL lock on the backing directory. Without "
                         "the lock anything can write to it directly and "
                         "bypass the guard entirely")
    pr.add_argument("--yes", action="store_true",
                    help="skip the confirmation prompt (this command MOVES your project)")
    pr.set_defaults(func=cmd_protect)

    up = sub.add_parser("unprotect", parents=[common],
                        help="move a protected project back and remove the lock")
    up.add_argument("project", help="the project directory to restore")
    up.add_argument("--backing", metavar="DIR",
                    help="where the real files are (default: <project>.real)")
    up.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    up.set_defaults(func=cmd_unprotect)

    eg = sub.add_parser("egress", parents=[common],
                        help="gate destructive external/SaaS API calls via an HTTP proxy (needs mitmdump)")
    eg.add_argument("--port", type=int, default=8080, help="proxy listen port (default 8080)")
    eg.add_argument("--enforce", action="store_true", help="block/review destructive calls (else shadow)")
    eg.set_defaults(func=cmd_egress)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_color", False):
        render.set_color(False)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Command-line interface.

Thin by design: parse arguments, call into the library, render the result.
No safety logic lives here.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import sys
from typing import List, Optional

from . import recovery, render
from . import config as config_mod
from .config import CONFIG_NAME, load_config
from .context import Intent, normalize_env
from .decide import CONTEXT_MISMATCH, ESCALATE
from .diff import diff_entry
from .guard import Guard
from .hooks import HostConfigUnreadable
from .receipts import (
    CHAIN_FS, chain_path, verify_chain, find_receipt, share_card,
    load_all_receipts, load_receipts, iter_all_receipts, tail_all_receipts,
)
from .version import __version__

_EXIT = {ESCALATE: 2, CONTEXT_MISMATCH: 1}

# Windows process-creation flags for long-lived background workers (filesystem
# guard and egress proxy). CREATE_NO_WINDOW suppresses console window without
# DETACHED_PROCESS (which Windows treats as overriding CREATE_NO_WINDOW).
_DETACHED_PROCESS = 0x00000008          # kept for reference; deliberately unused
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000

# Re-exported from .lifecycle for backward compatibility and clean modularity.
from .lifecycle import (
    CONFIG_TEMPLATE,
    _CONFIG_TEMPLATE,
    WAIT_MOUNT,
    WAIT_UNMOUNT,
    _wait_until,
    _show_plan,
    _step,
    _show_step,
    _protected_children,
    _install_hook_for,
    _remove_hooks,
    _strip_hook_entries,
    _teardown_admin_steps,
    _teardown_needs_admin,
    cmd_setup,
    cmd_teardown,
    cmd_teardown_admin,
    cmd_register_task,
)


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


def _undo_argv(a, root: Optional[str] = None) -> List[str]:
    """This same undo, as a command line, for the elevated re-run."""
    argv = ["undo"]
    if getattr(a, "id", None):
        argv.append(a.id)
    if getattr(a, "target", None):
        argv += ["--target", os.path.abspath(a.target)]
    # Pass explicit project root since ShellExecute child starts in C:\Windows\system32.
    argv += ["--root", os.path.abspath(
        getattr(a, "root", None) or root or os.getcwd())]
    # Target already pre-snapshotted unelevated; skip duplicate in child.
    argv.append("--no-presnapshot")
    return argv


def _undo_elevated(a, root: Optional[str] = None) -> Optional[int]:
    """Retry an undo that was refused for lack of privilege via UAC prompt.

    Returns None when elevation is unavailable, refused, or already elevated.
    """
    from . import protect as protect_mod
    if os.name != "nt" or protect_mod.is_elevated():
        return None                     # already admin: elevating again changes nothing
    print(render.c("[demo_cli] this recovery point lives in the protected backing; "
                   "asking for Administrator.", "yellow"))
    return protect_mod.rerun_elevated(_undo_argv(a, root))


def cmd_undo(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    entry = _resolve_entry(cfg, a)

    # Snapshot BEFORE restoring, and before any elevation attempt. The target
    # sits in the mount and is readable unelevated even when the recovery
    # point is not, so this succeeds here and the resulting id reaches the
    # shell the person is actually looking at - an elevated child's output
    # goes to a console that closes with it.
    preserved = None
    if not getattr(a, "no_presnapshot", False):
        try:
            preserved = recovery.snapshot_before_restore(entry, cfg.recovery_dir)
        except OSError:
            preserved = None            # never let bookkeeping block a recovery

    result = recovery.restore(entry)
    denied = result.denied              # may be cleared below; see the retry branch

    if not result.ok and result.denied:
        rc = _undo_elevated(a, cfg.project_root)
        if rc == 0:
            # Render restore output in parent console since child console closes on exit.
            render.render_restore(entry, True, __version__,
                                  recovery_dir=cfg.recovery_dir,
                                  requested_id=getattr(a, "id", None))
            _say_preserved(preserved)
            return 0
        if rc is not None:
            # Elevated retry ran with admin; do not blame permissions for non-zero exit.
            denied = False
            print(render.c("The elevated attempt did not restore it either "
                           f"(exit {rc}).", "red"))
            # Display child output captured from elevated execution.
            from . import protect as protect_mod
            out = protect_mod.elevated_output()
            for line in (out.splitlines() or ["(it printed nothing)"]):
                print("  " + render.c(line, "dim"))

    # Render restore result with searched recovery directory.
    render.render_restore(entry, result.ok, __version__,
                          recovery_dir=cfg.recovery_dir,
                          requested_id=getattr(a, "id", None),
                          denied=denied, problem=result.problem)
    if result.ok:
        _say_preserved(preserved)
    return 0 if result.ok else 1


def _say_preserved(entry) -> None:
    """Name the recovery point undo just took, so the undo is itself undoable.

    Silent when there was nothing to keep - an identical file, or no file.
    """
    if entry:
        print(render.c(f"  the previous content was kept as {entry['id']}"
                       f" - put it back with:  demo_cli undo {entry['id']}", "dim"))
        print()


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
    entries = recovery.load_entries(cfg.recovery_dir)
    last = getattr(a, "last", None)
    if last and last > 0:
        entries = entries[-last:]
    render.render_log(entries, __version__)
    return 0


def cmd_verify(a) -> int:
    from .receipts import CHAIN_FS, chain_path, anchor_chains

    cfg = load_config(getattr(a, "root", None))
    main_path = cfg.receipts_path
    fs_path = chain_path(main_path, CHAIN_FS)

    if getattr(a, "anchor", False):
        anchor_chains(main_path)

    v = verify_chain(main_path)
    # Filesystem chain is optional; only verify if it exists.
    fs = verify_chain(fs_path) if os.path.exists(fs_path) else None

    from .receipts import verify_cross_links
    links = verify_cross_links(main_path, fs_path) if fs is not None else None

    # Audit on-disk recovery artifacts
    artifacts = recovery.audit_recovery_artifacts(cfg.recovery_dir)

    # Only anchor non-empty chains (skip empty genesis).
    heads = {}
    if v.ok and not v.absent:
        heads["main"] = v.head
    if fs is not None and fs.ok and not fs.absent:
        heads["fs"] = fs.head
    render.render_verify(v, __version__, fs=fs, heads=heads or None, links=links, artifacts=artifacts)

    # Torn lines report warning without failing; unresolved cross-links fail command.
    # Absence of an unmounted filesystem chain is treated as valid.
    cross_ok = links.ok if (links and links.checked) else True
    artifacts_ok = artifacts.ok
    ok = v.ok and (fs.ok if fs else True) and cross_ok and artifacts_ok
    return 0 if ok else 1


def cmd_report(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    main_path = cfg.receipts_path
    fs_path = chain_path(main_path, CHAIN_FS)
    v = verify_chain(main_path)
    fs = verify_chain(fs_path) if os.path.exists(fs_path) else None

    total = 0
    by_decision = {}
    recovered = 0
    for r in iter_all_receipts(main_path):
        total += 1
        dec = r.get("decision", "?")
        by_decision[dec] = by_decision.get(dec, 0) + 1
        if r.get("recovery_point"):
            recovered += 1

    if total == 0 and not os.path.exists(main_path) and not os.path.exists(fs_path):
        print("No receipts yet. Run some commands through `demo_cli check` first.")
        return 0

    if not v.ok:
        chain_desc = f"TAMPERED (main) at line {v.broken_at}"
    elif fs and not fs.ok:
        chain_desc = f"TAMPERED (fs) at line {fs.broken_at}"
    else:
        chain_desc = "intact"

    print(render.c(f"\ndemo_cli {__version__}  shadow report\n", "dim"))
    print(render.kv("receipts", total))
    print(render.kv("chain", chain_desc))
    print(render.kv("recovery points", recovered))
    for k, n in sorted(by_decision.items()):
        print(render.kv("  " + k, n))
    print()
    return 0


def cmd_receipt(a) -> int:
    """`demo_cli receipt --share [id]` — print a copy-pasteable proof card for a
    single receipt (the latest, or one by id). `--list` (or running `demo_cli receipts`)
    shows recent receipt ids.
    """
    cfg = load_config(getattr(a, "root", None))

    is_list = getattr(a, "list", False)
    # If invoked as `demo_cli receipts` without a specific receipt id or --share, default to listing receipts
    if getattr(a, "cmd", None) == "receipts" and not getattr(a, "id", None) and not getattr(a, "share", False):
        is_list = True

    if is_list:
        rows = tail_all_receipts(cfg.receipts_path, n=20)
        if not rows:
            print("No receipts yet. Run some commands through the hook or `demo_cli check` first.")
            return 0
        print(render.c(f"\ndemo_cli {__version__}  receipts\n", "dim"))
        print("  " + render.c(f"{'id':<10}{'when':<27}{'decision':<16}action", "dim"))
        for r in rows:
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
            print(f"No receipt matched id '{a.id}'. Try `demo_cli receipts`.")
        else:
            print("No receipts yet. Run some commands through the hook or `demo_cli check` first.")
        return 1

    # --share is the default (and only) rendering today; the card is plain text
    # so it can be pasted straight into a forum, PR, or issue.
    print(share_card(receipt))
    return 0


# Re-exported from .doctor for backward compatibility and clean modularity.
from .doctor import (
    _HOSTS,
    _our_entries,
    _read_host_config,
    _hook_installed,
    _compare_entries,
    _expected_entries,
    _hook_check_rows,
    _host_hook_audit,
    _host_hook_status,
    _hook_selftest,
    _SELFTEST_PAYLOADS,
    _any_hook_installed,
    _mount_checks,
    _egress_checks,
    cmd_doctor,
)


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
    print(render.kv("note", "receipts untouched (hash-chained audit trail)"))
    print()
    return 0


def cmd_status(a) -> int:
    cfg = load_config(getattr(a, "root", None))
    main_path = cfg.receipts_path
    fs_path = chain_path(main_path, CHAIN_FS)

    v = verify_chain(main_path)
    fs = verify_chain(fs_path) if os.path.exists(fs_path) else None

    total = 0
    for p, ver in ((main_path, v), (fs_path, fs)):
        if ver is None:
            continue
        if ver.ok:
            total += ver.entries
        elif os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                total += sum(1 for line in f if line.strip())

    if not v.ok:
        chain_desc = f"TAMPERED (main) at line {v.broken_at}"
    elif fs and not fs.ok:
        chain_desc = f"TAMPERED (fs) at line {fs.broken_at}"
    elif not os.path.exists(main_path) and not (fs and os.path.exists(fs_path)):
        chain_desc = "none yet"
    else:
        chain_desc = "intact"

    info = {
        "mode": cfg.mode,
        "hook": _any_hook_installed(cfg),
        "config": cfg.source_path,
        "receipts": total,
        "chain": chain_desc,
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
    # Write UTF-8 without BOM for TOML parser compatibility.
    with open(path, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"Wrote {path}" + (f" (mode = {mode})" if mode else ""))
    return 0


def _report_reconcile(changed) -> None:
    """Report reconciled items from hook installation."""
    if not changed:
        print("  already current - nothing changed.")
        return
    for item in changed:
        print(f"  reconciled: {item}")


def cmd_install_hook(a) -> int:
    try:
        return _install_hook(a)
    except HostConfigUnreadable as exc:
        print(f"demo_cli: {exc}")
        return 1


def _install_hook(a) -> int:
    if getattr(a, "codex", False):
        from .hooks.codex import settings_snippet, install_into_hooks_json
        snippet = settings_snippet()
        if a.print:
            print(json.dumps(snippet, indent=2))
            return 0
        target = (os.path.expanduser("~/.codex/hooks.json") if a.scope == "global"
                  else os.path.join(os.getcwd(), ".codex", "hooks.json"))
        changed = install_into_hooks_json(target)
        print(f"Installed PreToolUse hook into {target}")
        _report_reconcile(changed)
        print("Gates Codex shell commands (Bash) AND file edits (apply_patch).")
        print()
        # Codex hook reload and approval instructions.
        print("  RESTART CODEX. Hook config is read once, at session start; a")
        print("  session already running keeps whatever it loaded and this")
        print("  install has no effect on it (silently - no warning either side).")
        print()
        print("  Until you restart: no gating, no receipts, no protection.")
        print()
        print("  Some Codex builds also gate hooks behind approval. If nothing is")
        print("  captured after a restart, run  /hooks  and approve this entry -")
        print("  trust is tracked by hash, so re-approve after any upgrade.")
        print("  Verified NOT required on 0.154.0 (Windows).")
        print()
        print("  Either way, confirm with evidence, not with this message:")
        print("  run one command through Codex, then  demo_cli receipt --list")
        print("  An installed hook is not an active hook.")
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
        changed = install_into_hooks_json(target)
        print(f"Installed beforeShellExecution hook into {target}")
        _report_reconcile(changed)
        print("demo_cli will now fire before each Cursor shell command (failClosed: true).")
        return 0
    from .hooks.claude_code import settings_snippet, install_into_settings
    snippet = settings_snippet()
    if a.print:
        print(json.dumps(snippet, indent=2))
        return 0
    target = (os.path.expanduser("~/.claude/settings.json") if a.scope == "global"
              else os.path.join(os.getcwd(), ".claude", "settings.json"))
    changed = install_into_settings(target)
    print(f"Installed PreToolUse hook into {target}")
    _report_reconcile(changed)
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
# Escape hatches (fail-open if guard is broken):
#   DEMO_CLI_DISABLE=1   turns the guard off entirely.
#   the sanity probe     distinguishes guard block from an unrunnable guard.
if [ -n "$BASH_VERSION" ] && [ -z "$DEMO_CLI_DISABLE" ] && command -v demo_cli >/dev/null 2>&1; then
  # Fail-safe egress probe: if proxy is configured for localhost but nothing is listening,
  # unset the proxy so child network commands do not fail with Connection Refused.
  case "${HTTPS_PROXY:-$https_proxy}" in
    *localhost:*|*127.0.0.1:*)
      __demo_cli_p="${HTTPS_PROXY:-$https_proxy}"
      __demo_cli_port="${__demo_cli_p##*:}"
      __demo_cli_port="${__demo_cli_port%%/*}"
      case "$__demo_cli_port" in
        ''|*[!0-9]*) ;;
        *)
          if ! (echo > /dev/tcp/127.0.0.1/"$__demo_cli_port") >/dev/null 2>&1; then
            unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy
          fi
          ;;
      esac
      unset __demo_cli_p __demo_cli_port
      ;;
  esac

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
    # Unwrap Claude Code !-mode wrapper (`eval '<cmd>' < /dev/null`) to inspect inner command.
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
            # BASH_ENV configures non-interactive bash -c (e.g. Claude Code !-mode).
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
    from .fsmount import (available, clear_mountpoint, mount,
                          mountpoint_obstruction)
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
    # A leftover mount point must not be permanent. After a reboot the path
    # can be a dangling reparse point, or an empty directory another demo_cli
    # command conjured while the guard was down - neither holds any of the
    # user's bytes, and refusing on both meant the logon task failed every
    # boot with no route back but rmdir by hand. fsmount decides; this only
    # reports and acts.
    obstruction = mountpoint_obstruction(a.mountpoint)
    if obstruction:
        print(obstruction)
        print("WinFsp CREATES the mount point itself, so it must not exist yet.")
        print("Move or empty that path, or pick a new one.")
        return 1
    try:
        if clear_mountpoint(a.mountpoint):
            # Report cleared leftover mount point.
            print(f"[fs] cleared a leftover mount point at {a.mountpoint}")
    except OSError as e:
        print(f"{a.mountpoint} could not be cleared: {e.strerror}")
        print("Something is holding it open, or it is not empty after all.")
        return 1
    backing = getattr(a, "backing", None)
    if backing and not os.path.isdir(backing):
        print(f"The backing directory {backing} does not exist.")
        print("It is where your files actually live. To convert an existing")
        print("project, run:  demo_cli protect <your project>")
        return 1
    if not backing:
        # Warn if mount is in-memory without persistent backing.
        print("NOTE: no --backing given, so this mount is IN MEMORY.")
        print("      Everything written inside it is LOST when you unmount.")
        print("      For real work:  demo_cli protect <your project>")

    if getattr(a, "foreground", False):
        return _mount_foreground(a, backing)
    return _mount_detached(a, backing)


def _mount_foreground(a, backing) -> int:
    """Run the mount in this process, printing logs directly to terminal."""
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
    Logs are written to mount.log.
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

    refused = config_mod.ensure_workspace(cfg)
    if refused:
        print(f"Cannot prepare the guard's workspace: {refused}")
        return 1
    log = mountstate.log_path(cfg)

    argv = [sys.executable, "-m", "demo_cli", "mount", a.mountpoint, "--foreground"]
    if backing:
        argv += ["--backing", backing]
    if a.debug:
        argv += ["--debug"]

    # Detach background process from console and process group.
    kwargs = {}
    if os.name == "nt":
        # Windows process creation flags (CREATE_NO_WINDOW and new process group).
        kwargs["creationflags"] = _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    with open(log, "a", encoding="utf-8") as fh:
        proc = subprocess.Popen(argv, stdout=fh, stderr=fh,
                                stdin=subprocess.DEVNULL, **kwargs)

    # Wait for mount point to appear (or return immediately if --no-wait specified).
    if getattr(a, "no_wait", False):
        mounted = proc.poll() is None
    else:
        mounted = _wait_until(
            lambda: proc.poll() is not None or os.path.lexists(a.mountpoint),
            timeout=WAIT_MOUNT, label="waiting for the guard to come up")
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

    if not mounted:
        print(render.c(f"The guard is still starting after {int(WAIT_MOUNT)}s "
                       f"(pid {proc.pid}); it is not reported as running yet.",
                       "yellow"))
        print(f"  watch {log}")
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


def _watch_layers(cfg, port, baseline, proc, seconds: int = 60) -> None:
    """Watchdog thread: re-check coverage and report layer status transitions to stderr."""
    import threading
    import time

    from . import guarded as g

    if seconds <= 0:
        return

    def loop():
        previous = baseline
        while proc.poll() is None:
            time.sleep(seconds)
            if proc.poll() is not None:
                return
            try:
                current = g.assess(cfg, port, _host_hook_status(cfg))
            except Exception:
                continue                      # never let the watchdog kill the run
            for layer in g.dropped(previous, current):
                sys.stderr.write(
                    f"\ndemo_cli [!] {layer.name} STOPPED PROTECTING YOU: "
                    f"{layer.detail}\n")
                if layer.fixable:
                    sys.stderr.write(f"demo_cli     fix: {layer.fixable}\n")
                sys.stderr.flush()
            for layer in g.recovered(previous, current):
                sys.stderr.write(f"\ndemo_cli [+] {layer.name} is back: "
                                 f"{layer.detail}\n")
                sys.stderr.flush()
            previous = current

    threading.Thread(target=loop, daemon=True).start()


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
        # Guard runs elevated; non-elevated process cannot terminate it.
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




def _relock_target(project: str, backing: Optional[str]) -> Optional[str]:
    """Return verified backing path to re-lock if project is already protected.
    Requires an existing mount record matching this backing directory.
    """
    if os.name != "nt":
        return None
    from . import mountstate as _ms, protect as protect_mod
    target = os.path.abspath(backing) if backing else protect_mod.backing_for(project)
    if not os.path.isdir(target):
        return None
    try:
        st = _ms.status(load_config(project))
    except Exception:
        return None
    if not (st.recorded and st.backing):
        return None
    same = os.path.normcase(os.path.abspath(st.backing)) == os.path.normcase(target)
    return target if same else None


def cmd_protect(a) -> int:
    """Relocate a project so its own path can become the guarded mount point."""
    from . import protect as protect_mod

    project = os.path.abspath(a.project)
    relock = _relock_target(project, getattr(a, "backing", None))
    if relock:
        print(render.c(f"\ndemo_cli {__version__}  protect  ->  re-apply the lock\n", "dim"))
        print(f"  {project} is already protected.")
        print(f"  Nothing to move. Re-applying the lock on {relock}.\n")
        if not protect_mod.is_elevated():
            rc = protect_mod.rerun_elevated(["protect", project])
            if rc is None:
                print("  " + render.c("could not elevate.", "red"))
                print(protect_mod.elevated_output())
                return 1
            # Query filesystem ACL directly to verify lock status.
            state = protect_mod.is_locked(relock)
            if state is True:
                print("  " + render.c(f"locked {relock} to Administrators and SYSTEM", "green"))
                print("  " + render.c("no files were moved.", "dim") + "\n")
                return 0
            # Distinguish unlocked (False) from unreadable ACL state (None).
            if state is False:
                print("  " + render.c(f"the elevated step exited {rc}, but {relock} is "
                                      f"still not locked", "red") + "\n")
            else:
                print("  " + render.c(f"the elevated step exited {rc}, and the ACL on "
                                      f"{relock} could not be read - whether it is "
                                      f"locked is unknown", "yellow") + "\n")
            return 1
        protect_mod.lock_directory(relock)
        # Verify ACL state with is_locked rather than relying solely on icacls return code.
        state = protect_mod.is_locked(relock)
        if state is True:
            print("  " + render.c(f"locked {relock} to Administrators and SYSTEM", "green"))
            print("  " + render.c("no files were moved.", "dim") + "\n")
            return 0
        if state is False:
            print("  " + render.c(f"COULD NOT LOCK {relock} - it is still writable, "
                                  f"so the guard can be bypassed", "red") + "\n")
        else:
            print("  " + render.c(f"COULD NOT VERIFY THE LOCK on {relock} - its ACL "
                                  f"could not be read", "yellow") + "\n")
        return 1

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
    try:
        for step in protect_mod.protect(plan):
            print("  " + render.c(step, "green"))
    except (PermissionError, OSError) as exc:
        print("  " + render.c(str(exc), "red"))
        print()
        return 1
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
    try:
        for step in protect_mod.unprotect(plan):
            print("  " + render.c(step, "green"))
    except PermissionError as exc:
        # Catch permission errors gracefully during unprotect.
        print("  " + render.c(str(exc), "red"))
        print()
        return 1
    print()
    return 0


# Re-exported from .egress for backward compatibility and clean modularity.
from .egress import (
    _MITM_DIR,
    _CA_PEM_NAME,
    _CA_CER_NAME,
    _ca_path,
    egress_setup_lines,
    _trust_ca,
    cmd_egress,
)


def cmd_guarded(a) -> int:
    """Launch an agent with all configured security layers and print a coverage report."""
    import subprocess
    import time

    from . import guarded as g

    argv = [t for t in (getattr(a, "argv", None) or []) if t != "--"]
    if not argv:
        print("usage: demo_cli guarded <command> [args...]     e.g. demo_cli guarded claude")
        return 1

    cfg = load_config(getattr(a, "root", None))
    port, err = cfg.resolve_egress_port(getattr(a, "port", None))
    if err:
        print(render.c(f"demo_cli guarded: {err}", "red"))
        return 1
    started_egress = None

    # Auto-start proxy if configured and not already running.
    if not getattr(a, "no_egress", False) and not g.port_open(port):
        mitm = __import__("shutil").which("mitmdump")
        if mitm:
            log = os.path.join(cfg.workspace, "egress.log")
            config_mod.ensure_workspace(cfg)
            here = os.path.dirname(os.path.abspath(__file__))
            egress_mode = cfg.resolve_egress_mode()
            env = dict(os.environ, DEMO_CLI_EGRESS_MODE=egress_mode,
                       PYTHONPATH=os.path.dirname(here) + os.pathsep
                       + os.environ.get("PYTHONPATH", ""))
            # Detached process creation flags (CREATE_NO_WINDOW without DETACHED_PROCESS).
            kwargs = {"creationflags": _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP} \
                if os.name == "nt" else {"start_new_session": True}
            with open(log, "a", encoding="utf-8") as fh:
                started_egress = subprocess.Popen(
                    [mitm, "-s", os.path.join(here, "egress_addon.py"),
                     "--listen-port", str(port), "-q"],
                    stdout=fh, stderr=fh, stdin=subprocess.DEVNULL, env=env, **kwargs)
            for _ in range(40):                 # up to ~8s for the port to open
                if g.port_open(port):
                    break
                if started_egress.poll() is not None:
                    # Early failure: mitmdump exited or crashed
                    break
                time.sleep(0.2)
            if started_egress and not g.port_open(port) and started_egress.poll() is not None:
                err_tail = ""
                try:
                    if os.path.exists(log):
                        with open(log, "r", encoding="utf-8", errors="replace") as ef:
                            lines = ef.read().strip().splitlines()
                            if lines:
                                err_tail = "\n".join(lines[-3:])
                except Exception:
                    pass
                print(render.c(f"demo_cli: egress proxy failed to start (exit code {started_egress.returncode}).", "yellow"))
                if err_tail:
                    print(render.c(f"         {err_tail}", "dim"))

    layers = g.assess(cfg, port, _host_hook_status(cfg))
    print(render.c(f"\ndemo_cli {__version__}  guarded  ->  {' '.join(argv)}\n", "dim"))
    for layer in layers:
        mark = render.c("[+]", "green") if layer.ok else render.c("[!]", "yellow")
        print(f"  {mark} {layer.name:<16} {layer.detail}")
        if layer.fixable:
            print(f"      {render.c('turn it on: ' + layer.fixable, 'dim')}")
    print(f"\n  {g.summary(layers)}\n")
    # Flush coverage report to terminal before spawning child agent.
    sys.stdout.flush()

    extra_np = None
    if getattr(cfg, "egress", None) and isinstance(cfg.egress, dict):
        extra_np = cfg.egress.get("no_proxy")
    env = g.child_env(dict(os.environ), port, g.port_open(port), extra_no_proxy=extra_np, config=cfg)

    # Resolve executable via shutil.which to honor Windows PATHEXT.
    exe = __import__("shutil").which(argv[0])
    if not exe:
        print(f"{argv[0]}: not found on PATH.")
        return 127
    try:
        proc = subprocess.Popen([exe] + argv[1:], env=env)
        _watch_layers(cfg, port, layers, proc,
                      seconds=getattr(a, "heartbeat", 60))
        return proc.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        # Terminate proxy only if started by this process.
        if started_egress and started_egress.poll() is None:
            started_egress.terminate()
            print("\ndemo_cli: stopped the egress guard it started.")


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


def cmd_target(a) -> int:
    target_action = getattr(a, "target_action", None)
    if target_action == "add":
        pattern = getattr(a, "pattern", None)
        env = getattr(a, "env", "production")
        recovery = getattr(a, "recovery", "snapshot")
        root = getattr(a, "root", None)
        try:
            cfg_path, summary = config_mod.append_target_rule(
                root=root,
                match=pattern,
                env=env,
                recovery=recovery,
            )
            print(f"demo_cli: added {summary} to {cfg_path}")
            return 0
        except ValueError as exc:
            sys.stderr.write(f"demo_cli: error: {exc}\n")
            return 1
        except Exception as exc:
            sys.stderr.write(f"demo_cli: error: could not add target rule: {exc}\n")
            return 1

    # Default or "list"
    cfg = load_config(getattr(a, "root", None))
    if cfg.target_errors:
        print("Warning: errors in configured target rules:")
        for err in cfg.target_errors:
            print(f"  - {err}")
        print()

    if not cfg.targets:
        print("No target rules declared in .demo_cli.toml.")
        print("To declare a target, run:")
        print('  demo_cli target add "<pattern>" --env production')
        return 0

    cfg_name = cfg.source_path or CONFIG_NAME
    print(f"Declared target rules ({cfg_name}):")
    for t in cfg.targets:
        print(f"  - match: {t.match!r:<25} env: {t.env:<12} recovery: {t.recovery}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="demo_cli",
        description="A pre-execution safety layer for AI coding agents: "
                    "preview, snapshot, undo, and a hash-chained receipt of every decision.",
    )
    p.add_argument("--version", action="version", version=f"demo_cli {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="disable coloured output")
    # Captured output log for elevated child process.
    common.add_argument("--elevated-log", metavar="PATH", help=argparse.SUPPRESS)
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
    un.add_argument("--no-presnapshot", action="store_true", help=argparse.SUPPRESS)
    un.set_defaults(func=cmd_undo)

    df = sub.add_parser("diff", parents=[common], help="show what changed since a recovery point")
    df.add_argument("id", nargs="?", default=None, help="recovery point id (see `demo_cli log`)")
    df.add_argument("--target", default=None)
    df.set_defaults(func=cmd_diff)

    lg = sub.add_parser("log", parents=[common],
                        help="list captured recovery points")
    lg.add_argument("--last", type=int, default=None, metavar="N",
                    help="show only the N most recent")
    lg.set_defaults(func=cmd_log)

    vf = sub.add_parser("verify", parents=[common], help="verify the receipt hash-chain")
    vf.add_argument("--anchor", action="store_true",
                    help="seal unanchored tails across both chains before verifying")
    vf.set_defaults(func=cmd_verify)

    rp = sub.add_parser("report", parents=[common], help="summarise recorded decisions (shadow report)")
    rp.set_defaults(func=cmd_report)

    # Alias: `demo_cli receipts` lists entries; `demo_cli receipt` prints a proof card.
    rc = sub.add_parser("receipt", parents=[common], aliases=["receipts"],
                        help="show a copy-pasteable proof card, or list receipts (`demo_cli receipts`)")
    rc.add_argument("id", nargs="?", default=None,
                    help="receipt id (see `demo_cli receipts`); default: latest")
    rc.add_argument("--share", action="store_true",
                    help="print the shareable proof card (default action for `demo_cli receipt`)")
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
    # Mutually exclusive host selection flags.
    ih_host = ih.add_mutually_exclusive_group()
    ih_host.add_argument("--claude", action="store_true",
                          help="install the Claude Code PreToolUse hook (the default)")
    ih_host.add_argument("--cursor", action="store_true",
                          help="install the Cursor beforeShellExecution hook (into .cursor/hooks.json) "
                               "instead of the Claude Code PreToolUse hook")
    ih_host.add_argument("--codex", action="store_true",
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
    mt.add_argument("--no-wait", action="store_true", help=argparse.SUPPRESS)
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

    st = sub.add_parser("setup", parents=[common],
                        help="make a project guarded: config, hooks, protection, autostart")
    st.add_argument("project", nargs="?", help="the project (default: current directory)")
    st.add_argument("--mode", choices=["shadow", "enforce"], default="enforce")
    st.add_argument("--no-protect", action="store_true",
                    help="skip relocating the project (no filesystem guard)")
    st.add_argument("--port", type=int, default=None,
                    help="egress proxy port (default: 8080 or [egress] in config)")
    st.add_argument("--yes", action="store_true", help="skip confirmations")
    st.set_defaults(func=cmd_setup)

    td = sub.add_parser("teardown", parents=[common],
                        help="undo everything setup did, in any machine state")
    td.add_argument("project", nargs="?", help="the project (default: current directory)")
    td.add_argument("--yes", action="store_true", help="skip confirmations")
    td.set_defaults(func=cmd_teardown)

    ta = sub.add_parser("_teardown-admin", parents=[common],
                        help=argparse.SUPPRESS)
    ta.add_argument("project")
    ta.add_argument("--report", required=True)
    ta.set_defaults(func=cmd_teardown_admin)

    rt = sub.add_parser("_register-task", parents=[common],
                        help=argparse.SUPPRESS)
    rt.add_argument("project")
    rt.set_defaults(func=cmd_register_task)

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

    gd = sub.add_parser("guarded", parents=[common],
                        help="launch an agent with every layer that can be started, started")
    gd.add_argument("--port", type=int, default=None,
                    help="egress proxy port (default: 8080 or [egress] in config)")
    gd.add_argument("--no-egress", action="store_true",
                    help="do not start or use the egress proxy")
    gd.add_argument("--heartbeat", type=int, default=60, metavar="SECONDS",
                    help="re-check coverage this often and warn if a layer "
                         "drops mid-session (0 disables)")
    gd.add_argument("argv", nargs=argparse.REMAINDER,
                    help="the agent to run, e.g. `demo_cli guarded claude`")
    gd.set_defaults(func=cmd_guarded)

    eg = sub.add_parser("egress", parents=[common],
                        help="gate destructive external/SaaS API calls via an HTTP proxy (needs mitmdump)")
    eg.add_argument("--port", type=int, default=None,
                    help="proxy listen port (default: 8080 or [egress] in config)")
    eg.add_argument("--enforce", action="store_true", help="block/review destructive calls (else shadow)")

    eg.add_argument("--trust-ca", action="store_true",
                    help="[Windows] add mitmproxy's CA to your USER certificate "
                         "store, so Invoke-WebRequest/.NET/curl.exe can be "
                         "inspected. Prints what that means for your machine")
    eg.add_argument("--untrust-ca", action="store_true",
                    help="[Windows] remove it again. Do this when you are done")
    eg.set_defaults(func=cmd_egress)

    tg = sub.add_parser("target", parents=[common], aliases=["targets"],
                        help="manage declared environment & recovery targets")
    tg_sub = tg.add_subparsers(dest="target_action")

    tg_add = tg_sub.add_parser("add", parents=[common], help="add a target rule to .demo_cli.toml")
    tg_add.add_argument("pattern", help="path substring, glob (*.db), or connection URL pattern")
    tg_add.add_argument("--env", default="production",
                        choices=["production", "staging", "development", "test", "sandbox"],
                        help="environment this target belongs to (default: production)")
    tg_add.add_argument("--recovery", default="snapshot",
                        choices=["snapshot", "none", "attest"],
                        help="recovery strategy for this target (default: snapshot)")
    tg_add.set_defaults(func=cmd_target)

    tg_list = tg_sub.add_parser("list", parents=[common], help="list declared target rules")
    tg_list.set_defaults(func=cmd_target)

    tg.set_defaults(func=cmd_target)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Redirect output to elevated log sink if specified.
    log = getattr(args, "elevated_log", None)
    if log:
        try:
            sink = open(log, "a", encoding="utf-8", errors="replace", buffering=1)
            sys.stdout = sink
            sys.stderr = sink
        except OSError:
            pass                        # unwritable log: run anyway, silently
    if getattr(args, "no_color", False):
        render.set_color(False)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

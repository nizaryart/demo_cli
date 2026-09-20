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

# WINDOWS PROCESS-CREATION FLAGS, DEFINED ONCE.
#
# Every long-lived child demo_cli starts detached - the filesystem guard and
# the egress proxy - wants the same thing: no visible console, and no tie to
# the parent's Ctrl+C. The combination is not obvious, and getting it wrong is
# silent.
#
# CREATE_NO_WINDOW *without* DETACHED_PROCESS. Windows documents
# CREATE_NO_WINDOW as IGNORED when DETACHED_PROCESS or CREATE_NEW_CONSOLE is
# also set, so stacking them throws away the only flag that suppresses the
# window and the child runs with a console for its whole life - a window
# somebody eventually closes, and closing it kills the child. CREATE_NO_WINDOW
# still gives the child its own invisible console, so Ctrl+C in the parent's
# console does not reach it.
#
# Fixed in the mount path 2026-08-29 and missed in the egress path until a
# review on 2026-09-07. They are shared constants now because two copies of
# this reasoning is exactly how they drifted.
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
    # ALWAYS PASS THE ROOT, not only when the user typed one.
    #
    # The elevated child is launched by ShellExecute, which does not inherit
    # this process's working directory - it starts in C:\Windows\system32. So
    # an undo that relied on the current directory (the normal way to run it)
    # re-ran up there, resolved a project root of system32, and reported
    #
    #   No recovery point matched '93201f46'.
    #   searched  C:\Windows\system32\.demo_cli\recovery
    #
    # while the parent told the user their recovery needed Administrator - a
    # true statement with the wrong reason attached (dari, 2026-09-02). The
    # child had every right to read the file; it was looking in the wrong
    # place. rerun_elevated now sets lpDirectory too, but a recovery path must
    # not depend on inheriting a directory to find its own ledger.
    argv += ["--root", os.path.abspath(
        getattr(a, "root", None) or root or os.getcwd())]
    # This process already took the pre-restore snapshot - the target lives in
    # the mount and is readable unelevated, even when the recovery point is
    # not. Without this the elevated child would take a second one of bytes
    # nobody changed in between.
    argv.append("--no-presnapshot")
    return argv


def _undo_elevated(a, root: Optional[str] = None) -> Optional[int]:
    """Retry an undo that was refused for lack of privilege, via UAC.

    WHY ASK RATHER THAN INSTRUCT. The filesystem guard writes its recovery
    points into the ACL-locked backing on purpose: it is what stops the agent
    from deleting the evidence of what it did. The consequence is that undo of
    anything that layer caught needs Administrator - and on 2026-08-29 the
    user met that as "No recovery point could be restored", went away
    believing the file was gone, and only got it back by guessing to open an
    admin shell.

    Sending somebody to another shell mid-recovery is the manual step people
    skip. UAC is itself the consent prompt, so asking directly is both fewer
    steps and no less explicit about what is happening.

    Returns None when elevation is unavailable, refused, or pointless (already
    elevated) - the caller then prints the honest failure instead.
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
            # The elevated process owns its own console, which closes with it,
            # so its RESTORED banner is never seen. Say it here, in the shell
            # the person is actually looking at.
            render.render_restore(entry, True, __version__,
                                  recovery_dir=cfg.recovery_dir,
                                  requested_id=getattr(a, "id", None))
            _say_preserved(preserved)
            return 0
        if rc is not None:
            # AND STOP BLAMING PERMISSIONS. This branch is only reachable when
            # result.denied is True, so the banner underneath used to print
            # "This recovery point needs Administrator" - after a retry that
            # HAD Administrator and failed for some other reason. The honest
            # diagnosis is printed just below and was then contradicted two
            # lines later.
            #
            # The 2026-09-02 fix added the elevated output and left the banner
            # alone: half of the same incident, and the half that was still
            # lying. Found by review 2026-09-07 - the first defect in this
            # project found by reading rather than by running it.
            denied = False
            print(render.c("The elevated attempt did not restore it either "
                           f"(exit {rc}).", "red"))
            # SHOW WHAT IT SAID. The elevated console closes with the process,
            # so without this a completely diagnosable failure arrives as a
            # bare exit code - and the message printed underneath blames the
            # ACL, because that is the only reason this path knows about.
            #
            # On 2026-09-02 the log held the whole answer ("searched
            # C:\\Windows\\system32\\.demo_cli\\recovery") while the user was
            # told their recovery point needed Administrator. It already had
            # Administrator. teardown prints this; undo did not - the same
            # rule applied to one caller and not the other.
            from . import protect as protect_mod
            out = protect_mod.elevated_output()
            for line in (out.splitlines() or ["(it printed nothing)"]):
                print("  " + render.c(line, "dim"))

    # Pass the ledger we searched: "not found" is unactionable without it, and
    # the recovery dir follows the project root, which follows the directory a
    # guard was started from.
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
    # Absent on a project that has never been mounted - not a failure, and not
    # something to report as one. Only verified when the file exists.
    fs = verify_chain(fs_path) if os.path.exists(fs_path) else None

    from .receipts import verify_cross_links
    links = verify_cross_links(main_path, fs_path) if fs is not None else None

    # Audit on-disk recovery artifacts
    artifacts = recovery.audit_recovery_artifacts(cfg.recovery_dir)

    # No head for an empty ledger - GENESIS is not something to anchor, and
    # printing it as if it were a chain head would invite someone to record a
    # value that attests to nothing.
    heads = {}
    if v.ok and not v.absent:
        heads["main"] = v.head
    if fs is not None and fs.ok and not fs.absent:
        heads["fs"] = fs.head
    render.render_verify(v, __version__, fs=fs, heads=heads or None, links=links, artifacts=artifacts)

    # DAMAGE DOES NOT FAIL THE COMMAND. A torn line is a write that did not
    # finish; the entries around it are intact and verified. Exiting non-zero
    # would make every script treat a self-inflicted corruption as evidence of
    # tampering - which is the same false alarm the wording used to raise.
    #
    # AN UNRESOLVED CROSS-LINK DOES FAIL IT. That is not damage: it means a
    # receipt referenced a hash that is no longer in the other chain, which is
    # what removing entries looks like.
    #
    # AN UNPERFORMED CHECK IS NOT A COMMAND FAILURE, and that decision is made
    # HERE rather than inside CrossLinkResult.ok. The property now returns
    # False when checked is False, because a caller writing `if links.ok`
    # must not get a pass for a check that never ran. Whether the ABSENCE of
    # a second chain should fail `demo_cli verify` is a different question,
    # and the answer is no: a project whose filesystem guard has never written
    # is an ordinary state, not evidence of anything.
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
    # encoding="utf-8" writes NO byte-order mark. That matters: PowerShell's
    # Out-File -Encoding utf8 adds one, TOML parsers reject it, and the guard
    # used to fail open on every command as a result. `init` exists partly so a
    # user never has to hand-write this file.
    with open(path, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"Wrote {path}" + (f" (mode = {mode})" if mode else ""))
    return 0


def _report_reconcile(changed) -> None:
    """Say what a re-run actually DID.

    A re-install that repaired a stale entry printed the same "Installed..."
    line as one that changed nothing, so there was no way to tell a repair
    from a no-op - which is part of why the stale timeout survived unnoticed.
    """
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
        # WHAT THIS SAID UNTIL 2026-09-13, and why it was changed: it listed
        # approving the hook in /hooks as REQUIRED, and ended "Until then: no
        # gating, no receipts, no protection." On Codex 0.154.0 / Windows the
        # hook gated Bash and apply_patch, wrote receipts and snapshotted, with
        # no approval step at all - so the tool was telling the user they were
        # unprotected while it was protecting them. Wrong in the worse
        # direction: a user who believes the guard is off either stops trusting
        # what it says or turns it off for real.
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
            # Said out loud. Deleting a directory silently is precisely what
            # this tool exists not to do, even when it is provably empty.
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

    # Detach properly on both platforms: no console, no process group tie, so
    # closing the terminal or pressing Ctrl+C here does not take the guard down
    # with it.
    kwargs = {}
    if os.name == "nt":
        # See _CREATE_NO_WINDOW at the top of this module for why this
        # combination and not DETACHED_PROCESS.
        kwargs["creationflags"] = _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    with open(log, "a", encoding="utf-8") as fh:
        proc = subprocess.Popen(argv, stdout=fh, stderr=fh,
                                stdin=subprocess.DEVNULL, **kwargs)

    # WAIT FOR THE MOUNT POINT, not for a fixed number of seconds. Two seconds
    # was a guess: on a slow machine the child is still importing when it
    # expires, so poll() returns None, and the parent reports a guard that has
    # not started - `Last Result: 0` with nothing mounted (2026-08-29).
    # --no-wait: return as soon as the child is spawned.
    #
    # THE SCHEDULED TASK USES IT, and nothing else should. Its .cmd owns a
    # console window that stays open for as long as this process runs, so
    # waiting here would park a window on the user's desktop for minutes at
    # every logon. Setup does the waiting instead, in the shell the person is
    # looking at, where progress is wanted rather than alarming.
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
    """Re-check coverage while the agent runs, and shout if a layer drops.

    A daemon thread, so it cannot keep the process alive after the agent
    exits. It reports TRANSITIONS only - a status line every minute is noise,
    and noise is how a real warning gets missed.

    The warning goes to STDERR, so it appears even while the agent owns the
    terminal for its own output.
    """
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




def _relock_target(project: str, backing: Optional[str]) -> Optional[str]:
    """The backing to re-lock, when this project is ALREADY protected.

    `protect` is a move, so on an already-protected project it refuses:
    "<backing> already exists. Refusing to merge two trees." Correct as far as
    it goes - but doctor's remediation for an unlocked backing is `demo_cli
    protect`, so the fix we printed could never apply to the situation we
    printed it for. Found on real hardware 2026-09-05, and it is the same
    defect class as the winfspy message: a diagnostic naming a fix that does
    not fix.

    In that situation there are not two trees. There is ONE tree seen twice -
    the mount and its backing - so there is nothing to move and the only thing
    that can be missing is the lock.

    THE EVIDENCE HAS TO BE demo_cli'S OWN RECORD, not a guess. A false
    negative here just refuses as before, which is harmless. A false positive
    applies an Administrators-only ACL to an unrelated directory and locks
    somebody's data away - so this requires a mount record that NAMES this
    backing. A plain directory that happens to sit beside a plain `X.real`
    produces no such record and is refused exactly as it is today.

    Not gated on the guard RUNNING: a protected project whose guard is stopped
    still has a backing that ought to be locked.
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
            # THE CHILD'S OUTPUT IS NOT OURS TO REPORT. ShellExecuteExW gives
            # the elevated process its own console, which closes the moment it
            # exits - so everything it printed is gone, and this shell would
            # otherwise end on "Re-applying the lock on ..." with no outcome
            # at all. Observed on real hardware 2026-09-06: the lock HAD been
            # applied and the command still looked like it did nothing.
            #
            # So do not relay, and do not trust the exit code either: ask the
            # filesystem. The parent can read an ACL without elevation.
            state = protect_mod.is_locked(relock)
            if state is True:
                print("  " + render.c(f"locked {relock} to Administrators and SYSTEM", "green"))
                print("  " + render.c("no files were moved.", "dim") + "\n")
                return 0
            # None is not False. The whole reason this branch reads the ACL
            # instead of the exit code is that "I do not know" must not be
            # printed as an outcome - so it is not printed as the OTHER
            # outcome either.
            if state is False:
                print("  " + render.c(f"the elevated step exited {rc}, but {relock} is "
                                      f"still not locked", "red") + "\n")
            else:
                print("  " + render.c(f"the elevated step exited {rc}, and the ACL on "
                                      f"{relock} could not be read - whether it is "
                                      f"locked is unknown", "yellow") + "\n")
            return 1
        protect_mod.lock_directory(relock)
        # Believe is_locked, not lock_directory's return value. icacls has
        # exited 0 on a failed grant before (see protect.lock_directory), and
        # this project's rule is that a claim of protection needs evidence.
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
        # The same guard teardown has. `unprotect` is the way out, and the way
        # out must never end in a traceback.
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
    """Launch an agent with every layer that can be started, started.

    The value is as much the COVERAGE REPORT as the launch: it answers "am I
    actually protected?" at the one moment somebody is guaranteed to be
    looking, instead of leaving it to a `doctor` run nobody thinks to do.
    """
    import subprocess
    import time

    from . import guarded as g

    argv = [t for t in (getattr(a, "argv", None) or []) if t != "--"]
    if not argv:
        print("usage: demo_cli guarded <command> [args...]     e.g. demo_cli guarded claude")
        return 1

    cfg = load_config(getattr(a, "root", None))
    port = getattr(a, "port", 8080)
    started_egress = None

    # Start the proxy if it is not already up. Nothing else is auto-started:
    # the mount needs elevation and a relocated project, and hooks are
    # persistent host config that must not be written behind the user's back.
    if not getattr(a, "no_egress", False) and not g.port_open(port):
        mitm = __import__("shutil").which("mitmdump")
        if mitm:
            log = os.path.join(cfg.workspace, "egress.log")
            config_mod.ensure_workspace(cfg)
            here = os.path.dirname(os.path.abspath(__file__))
            env = dict(os.environ, DEMO_CLI_EGRESS_MODE=cfg.mode,
                       PYTHONPATH=os.path.dirname(here) + os.pathsep
                       + os.environ.get("PYTHONPATH", ""))
            # SAME FLAGS AS _mount_detached, and for the same reason. This
            # was DETACHED_PROCESS | CREATE_NO_WINDOW - the exact combination
            # _mount_detached documents as broken, because Windows IGNORES
            # CREATE_NO_WINDOW when DETACHED_PROCESS is also set. The guard
            # was fixed on 2026-08-29; the egress spawn was missed, so the
            # proxy kept a visible console for its whole life - a window
            # somebody eventually closes, and closing it kills the proxy
            # after `guarded` has already reported [+] egress.
            #
            # Note the premise is one recorded observation, not a re-test:
            # CREATE_NO_WINDOW is still on the unverified list. The two call
            # sites agreeing matters either way, and one check settles both.
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
    # Flush before handing the terminal over. Python buffers stdout when it is
    # not a tty, the child does not, so without this the coverage report lands
    # AFTER the agent's own output - and a report you read afterwards is not a
    # report, it is a log entry.
    sys.stdout.flush()

    extra_np = None
    if getattr(cfg, "egress", None) and isinstance(cfg.egress, dict):
        extra_np = cfg.egress.get("no_proxy")
    env = g.child_env(dict(os.environ), port, g.port_open(port), extra_no_proxy=extra_np)

    # Resolve the executable OURSELVES. On Windows subprocess goes through
    # CreateProcess, which does not consult PATHEXT - so `claude`, installed
    # as claude.cmd, is invisible to it while working perfectly in the shell
    # the user just typed it into. shutil.which does honour PATHEXT.
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
        # Only what we started. A proxy the user already had running in another
        # terminal is theirs, and killing it would be a surprise.
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="demo_cli",
        description="A pre-execution safety layer for AI coding agents: "
                    "preview, snapshot, undo, and a hash-chained receipt of every decision.",
    )
    p.add_argument("--version", action="version", version=f"demo_cli {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="disable coloured output")
    # The elevated child writes its own output here. Not for users: it is how
    # the parent recovers what happened on the other side of a UAC prompt,
    # now that the elevation path no longer routes through `cmd /c ... > log`.
    # See protect.rerun_elevated for why that shell wrapper had to go.
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

    # `receipts` is an ALIAS for `receipt`. A user running `demo_cli receipts` (plural)
    # expects to view the recorded receipts ledger (`--list` by default).
    # `demo_cli receipt` (singular) prints a shareable proof card for the latest (or by id).
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
    # Claude Code is the default host, and was reachable ONLY as the bare form.
    # Two hosts had a flag and the third did not, so `--claude` failed with a
    # usage dump listing every subcommand - and the bare form is the one that
    # writes host config with no host named in the command.
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
    st.add_argument("--port", type=int, default=8080)
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
    gd.add_argument("--port", type=int, default=8080, help="egress proxy port (default 8080)")
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
    eg.add_argument("--port", type=int, default=8080, help="proxy listen port (default 8080)")
    eg.add_argument("--enforce", action="store_true", help="block/review destructive calls (else shadow)")
    eg.add_argument("--trust-ca", action="store_true",
                    help="[Windows] add mitmproxy's CA to your USER certificate "
                         "store, so Invoke-WebRequest/.NET/curl.exe can be "
                         "inspected. Prints what that means for your machine")
    eg.add_argument("--untrust-ca", action="store_true",
                    help="[Windows] remove it again. Do this when you are done")
    eg.set_defaults(func=cmd_egress)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # REDIRECT BEFORE ANYTHING PRINTS. ShellExecute cannot redirect handles,
    # and the elevated console is launched hidden and closes with the process,
    # so without this a failure on the far side of the UAC prompt arrives as a
    # bare exit code with the actual error already gone. The parent used to
    # get this by wrapping the child in `cmd /c "... > log 2>&1"`, which is
    # what let shell metacharacters in an argument reach an elevated shell.
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

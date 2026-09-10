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
from .receipts import verify_chain, find_receipt, share_card, load_receipts
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

_CONFIG_TEMPLATE = """\
# demo_cli configuration. All fields are optional; defaults are safe.
# Docs: https://github.com/nizaryart/DEMO_LOADING

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
    from .receipts import CHAIN_FS, chain_path

    cfg = load_config(getattr(a, "root", None))
    main_path = cfg.receipts_path
    fs_path = chain_path(main_path, CHAIN_FS)

    v = verify_chain(main_path)
    # Absent on a project that has never been mounted - not a failure, and not
    # something to report as one. Only verified when the file exists.
    fs = verify_chain(fs_path) if os.path.exists(fs_path) else None

    from .receipts import verify_cross_links
    links = verify_cross_links(main_path, fs_path) if fs is not None else None

    # No head for an empty ledger - GENESIS is not something to anchor, and
    # printing it as if it were a chain head would invite someone to record a
    # value that attests to nothing.
    heads = {}
    if v.ok and not v.absent:
        heads["main"] = v.head
    if fs is not None and fs.ok and not fs.absent:
        heads["fs"] = fs.head
    render.render_verify(v, __version__, fs=fs, heads=heads or None, links=links)

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
    ok = v.ok and (fs.ok if fs else True) and cross_ok
    return 0 if ok else 1


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
    from . import deps as deps_mod
    checks.extend(d.as_check() for d in deps_mod.check_all(cfg.project_root))

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
    print(render.kv("note", "receipts untouched (hash-chained audit trail)"))
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


def _step(n: int, text: str) -> None:
    print(f"\n  {render.c(f'{n}.', 'dim')} {text}")


def _protected_children(directory: str) -> List[str]:
    """Protected projects directly inside `directory`.

    Both setup and teardown default to the current directory, and a protected
    project is very often one level down - you stand in `lab` and the guarded
    thing is `lab\\myproj`. Naming what we found beats reporting "not
    protected" while the backing directory sits in plain view.

    Searched by looking for BACKING directories, not for projects. When the
    mount is not running the project path does not exist at all - it is a
    reparse point served by a dead process, or gone entirely - so scanning for
    projects finds nothing precisely when you most need the answer. The
    backing directory is the durable half; it is always there.
    """
    from . import protect as protect_mod
    suffix = protect_mod.BACKING_SUFFIX
    found = []
    try:
        for name in sorted(os.listdir(directory)):
            if not name.endswith(suffix):
                continue
            backing = os.path.join(directory, name)
            if os.path.isdir(backing):
                found.append(backing[: -len(suffix)])
    except OSError:
        pass
    return found


def _install_hook_for(project: str, label: str) -> None:
    """Install one host's hook into `project`, reusing that host's own
    installer rather than writing its config shape here - the Codex adapter
    already learned once that a hand-built config is silently ignored."""
    if label == "claude code":
        from .hooks.claude_code import install_into_settings
        install_into_settings(os.path.join(project, ".claude", "settings.json"))
    elif label == "cursor":
        from .hooks.cursor import install_into_hooks_json
        install_into_hooks_json(os.path.join(project, ".cursor", "hooks.json"))
    elif label == "codex":
        from .hooks.codex import install_into_hooks_json
        install_into_hooks_json(os.path.join(project, ".codex", "hooks.json"))


def _remove_hooks(project: str) -> List[str]:
    """Delete our entries from each host's config, leaving anything else in it.

    Removing the whole file would take the user's own settings with it - and
    somebody running teardown is often already having a bad day.
    """
    removed = []
    for label, directory, filename, event, command, nested in _HOSTS:
        path = os.path.join(project, directory, filename)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.load(f)
            if _strip_hook_entries(data, event, command):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                removed.append(label)
        except Exception:
            continue        # a config we cannot parse is one we must not rewrite
    return removed


def _strip_hook_entries(data, event: str, command: str) -> bool:
    """Remove our handlers from a host config in place. True if anything went.

    Handles both shapes: Claude Code / Codex nest handlers in a group
    ({matcher, hooks:[{type, command}]}); Cursor lists them flat.
    """
    hooks = data.get("hooks")
    if not isinstance(hooks, dict) or event not in hooks:
        return False
    groups, kept, changed = hooks[event], [], False
    if not isinstance(groups, list):
        return False
    for group in groups:
        if isinstance(group, dict) and "hooks" in group:
            inner = [h for h in group.get("hooks", [])
                     if command not in str(h.get("command", ""))]
            if len(inner) != len(group.get("hooks", [])):
                changed = True
            if inner:
                group["hooks"] = inner
                kept.append(group)
        elif isinstance(group, dict) and command in str(group.get("command", "")):
            changed = True
        else:
            kept.append(group)
    if changed:
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event)
    return changed


def cmd_setup(a) -> int:
    """One command to make a project guarded, and to say what that means.

    Setup used to be six commands across two shells with an implicit order and
    elevation at unpredictable points. Nothing told anyone how far they had
    got, and "installed but inert" has been the dangerous state six times in
    this project - four independent manual steps is how a seventh happens.

    What it will NOT do without asking: move your files. That is printed in
    full and confirmed, every time.
    """
    from . import guarded as g, protect as protect_mod, schedule

    project = os.path.abspath(getattr(a, "project", None) or os.getcwd())
    yes = getattr(a, "yes", False)
    print(render.c(f"\ndemo_cli {__version__}  setup  ->  {project}\n", "dim"))

    # PROTECTION STATUS FIRST, because it decides WHERE the config may be
    # written. Once a project is protected, its own path IS the mount point -
    # so writing a file there creates a real directory that BLOCKS mounting,
    # and a second config competing with the real one. That is exactly what
    # happened on 2026-08-28: setup wrote myproj\.demo_cli.toml, the logon
    # task's `rmdir` could not remove a non-empty directory, and the mount
    # refused because the path existed.
    already_protected = os.path.isdir(protect_mod.backing_for(project))

    # WHERE CONFIG AND HOOKS GO, and why the order changes.
    #
    # They belong INSIDE the project. For an unprotected one that is just the
    # project path. For a protected one the only legitimate route to those
    # files is THROUGH THE MOUNT - writing into the backing directly is
    # reaching around our own guard, which is exactly what the ACL exists to
    # prevent, and it fails anyway because the backing is Administrators-only.
    #
    # So when a project is already protected we DEFER these steps until the
    # mount is up, and do them through it. Trying to write into the locked
    # backing was a crash on 2026-08-28, from a fix made an hour earlier.
    from . import mountstate as _ms
    mounted_now = _ms.status(load_config(project)).running
    defer = already_protected and not mounted_now
    config_home = project

    if defer:
        print(render.c("  This project is protected but not mounted, so its "
                       "config and hooks", "dim"))
        print(render.c("  are set up after the guard starts, through the "
                       "mount.", "dim"))

    # 1. Config -----------------------------------------------------------
    cfg_path = os.path.join(config_home, CONFIG_NAME)
    mode = getattr(a, "mode", None) or "enforce"
    if defer:
        _step(1, "config: deferred until the guard is mounted")
    elif os.path.exists(cfg_path):
        _step(1, f"config already present ({cfg_path})")
    else:
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(_CONFIG_TEMPLATE.replace('mode = "shadow"', f'mode = "{mode}"'))
        _step(1, f"wrote {cfg_path}  (mode = {mode})")

    # 2. Hooks, for hosts that are actually present ------------------------
    installed = []
    for label, directory, filename, event, command, nested in ([] if defer else _HOSTS):
        home_dir = os.path.join(os.path.expanduser("~"), directory)
        if not os.path.isdir(home_dir) and label != "claude code":
            continue                    # host not installed on this machine
        try:
            _install_hook_for(config_home, label)
            installed.append(label)
        except Exception as exc:
            print(f"      could not install the {label} hook: {exc}")
    _step(2, "hooks: deferred until the guard is mounted" if defer else
             f"hooks: {', '.join(installed) if installed else 'none installed'}")

    # 3. Protection, which MOVES FILES and therefore always asks -----------
    if os.name != "nt":
        _step(3, "no filesystem guard on Linux - the behavioural layer is "
                 "`demo_cli run <cmd>`, wrapped per command")
    elif getattr(a, "no_protect", False):
        _step(3, "skipped (--no-protect)")
    else:
        backing = protect_mod.backing_for(project)
        if already_protected:
            _step(3, f"already protected  (files live in {backing})")
        else:
            plan = protect_mod.plan_protect(project)
            _step(3, "protect this project")
            print(f"      your files move to   {plan.backing}")
            print(f"      {project} becomes the guarded mount")
            for w in plan.warnings:
                print("      " + render.c("! " + w, "yellow"))
            for p in plan.problems:
                print("      " + render.c("x " + p, "red"))
            if not plan.ok:
                return 1
            if not yes and input("\n      Type 'yes' to move your project: "
                                 ).strip().lower() != "yes":
                print("\n  Nothing was moved. Setup stopped.\n")
                return 1
            # Elevation happens HERE, after the user has agreed - not at the
            # start, and not by sending them to another shell to start over.
            if protect_mod.is_elevated():
                for line in protect_mod.protect(plan):
                    print("      " + render.c(line, "green"))
            else:
                print("      requesting administrator rights...")
                rc = protect_mod.rerun_elevated(["protect", project, "--yes"])
                if rc is None:
                    print("      " + render.c(
                        "elevation was refused; nothing was moved. Re-run "
                        "from an Administrator shell.", "red"))
                    return 1
                if rc != 0:
                    print("      " + render.c("the elevated step failed:", "red"))
                    for line in (protect_mod.elevated_output() or
                                 "(it printed nothing)").splitlines():
                        print("        " + line)
                    return 1
                print("      " + render.c("protected", "green"))

        # 4. Come back after a reboot --------------------------------------
        if schedule.status(project).exists:
            _step(4, "logon task already registered")
        elif protect_mod.is_elevated():
            ok = schedule.register(project, protect_mod.backing_for(project))
            _step(4, "registered a logon task so the guard returns after a reboot"
                     if ok else "could NOT register the logon task")
        else:
            rc = protect_mod.rerun_elevated(["_register-task", project])
            if rc == 0:
                _step(4, "registered a logon task so the guard returns after a reboot")
            else:
                _step(4, "could NOT register the logon task - the guard will "
                         "not come back automatically after a reboot")
                out = protect_mod.elevated_output()
                for line in out.splitlines()[:6]:
                    print("      " + line)

    # 5. Bring the guard up NOW ------------------------------------------
    # Registering a logon task is not enough: without this, setup ends with a
    # protected project and NO filesystem guard until the next reboot - the
    # manual step the whole command exists to remove. Running the task uses
    # the elevation it already stores, so there is no second UAC prompt.
    if os.name == "nt" and not getattr(a, "no_protect", False):
        from . import mountstate as _ms
        if _ms.status(load_config(project)).running:
            _step(5, "filesystem guard already running")
        elif schedule.run_now(project):
            # The old wait here was 15 x 0.4s. Six seconds, silent - and this
            # machine took closer to four minutes between `schtasks /run` and
            # a live mount, so setup reported "not mounted" about a guard that
            # was still starting, and we spent an hour debugging a success.
            _step(5, "starting the filesystem guard")
            up = _wait_until(lambda: _ms.status(load_config(project)).running,
                             timeout=WAIT_MOUNT,
                             label="waiting for the guard")
            if up:
                print("      " + render.c("the filesystem guard is running", "green"))
            else:
                # NOT "failed". We do not know that. Saying so would be the
                # same unearned certainty as reporting a mount that is not up.
                print("      " + render.c(
                    f"still starting after {int(WAIT_MOUNT)}s. It may yet come "
                    f"up - check:  demo_cli doctor --root {project}", "yellow"))
                log = os.path.join(protect_mod.backing_for(project),
                                   ".demo_cli", "mount.log")
                print("      " + render.c(f"if not, the reason is in {log} "
                                          f"(needs an Administrator shell)", "dim"))
        else:
            _step(5, "could not start the guard now. It will come up at your "
                     "next logon, or run: demo_cli mount (elevated)")

    if defer and _ms.status(load_config(project)).running:
        # Through the mount now, which is the only honest route to a
        # protected project's files.
        try:
            if not os.path.exists(cfg_path):
                with open(cfg_path, "w", encoding="utf-8") as f:
                    f.write(_CONFIG_TEMPLATE.replace('mode = "shadow"',
                                                     f'mode = {mode!r}'))
            done = []
            for label, *_ in _HOSTS:
                try:
                    _install_hook_for(project, label)
                    done.append(label)
                except Exception:
                    pass
            _step(6, f"config and hooks written through the mount"
                     + (f" ({', '.join(done)})" if done else ""))
        except OSError as exc:
            _step(6, f"could not write through the mount: {exc}")
    elif defer:
        _step(6, "config and hooks still deferred - the guard is not mounted")

    # 7. What is actually on right now ------------------------------------
    cfg = load_config(project)
    port = getattr(a, "port", 8080)
    print(render.c("\n  coverage\n", "dim"))
    for layer in g.assess(cfg, port, _host_hook_status(cfg)):
        mark = render.c("[+]", "green") if layer.ok else render.c("[!]", "yellow")
        print(f"  {mark} {layer.name:<16} {layer.detail}")
        if layer.fixable:
            print(f"      {render.c('turn it on: ' + layer.fixable, 'dim')}")

    print(f"\n  {render.c('Start your agent with:  demo_cli guarded claude', 'dim')}")
    print(f"  {render.c('Undo everything:        demo_cli teardown', 'dim')}\n")
    return 0


WAIT_MOUNT = 240.0        # a guard coming up
WAIT_UNMOUNT = 120.0      # a guard letting go


def _wait_until(check, timeout: float = WAIT_MOUNT, interval: float = 0.5,
                label: Optional[str] = None) -> bool:
    """Poll until check() is true. Returns whether it happened in time.

    --------------------------------------------------------------------
    THE SAME BUG IN THREE PLACES
    --------------------------------------------------------------------
    Every one of these assumed a state transition had completed because the
    call that started it returned:

      _mount_detached          sleep(2), then assume the child started
      setup step 5             schtasks /run returned, so assume the guard is up
      teardown step 1 -> 3     the kill returned, so assume the mount is gone

    All three are wrong, and on 2026-08-29 all three fired on the same machine
    in one evening. Setup reported "protected but not mounted" about a guard
    that came up three minutes later; teardown's rename hit ERROR_ACCESS_DENIED
    because WinFsp still held the directory a fraction of a second after the
    kill - and that error code is indistinguishable from a permissions
    failure, so the message blamed the ACL.

    Starting something is not the same as it having started. The only honest
    test is to look at the thing itself.

    WHY IT PRINTS. Setup's old wait was 15 x 0.4s - six seconds, silent. The
    machine needed four minutes, and silence is what made a slow success read
    as a failure to both of us for an hour. A progress line costs nothing and
    removes the whole class of misreading.

    The timeout is a CEILING, not a wait: a fast machine returns on the first
    poll. It is generous because a slow one is not broken.
    """
    import time
    start = time.monotonic()
    shown = 0.0
    while True:
        try:
            if check():
                return True
        except Exception:
            pass                       # a check that raises is just "not yet"
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return False
        if label and elapsed - shown >= 5.0:
            shown = elapsed
            print(f"      {label}... {int(elapsed)}s", flush=True)
        time.sleep(interval)


def _teardown_admin_steps(project: str, cfg) -> List[dict]:
    """The three teardown steps that need Administrator, as data.

    Returned rather than printed, because on Windows these run inside an
    ELEVATED CHILD whose console closes with it. The parent renders them into
    the shell the person is actually looking at. Same problem `undo` has, and
    the same reason mount.log exists: anything that runs where you cannot see
    it must write down what it did.
    """
    from . import mountstate, protect as protect_mod, schedule
    out: List[dict] = []

    st = mountstate.status(cfg)
    if st.running:
        try:
            import signal
            os.kill(st.pid, signal.SIGTERM)
            mountstate.clear(cfg)
            # WinFsp does not let go the instant the process is signalled, and
            # step 3's rename of a directory it still holds fails with
            # ERROR_ACCESS_DENIED - the same code as a permissions failure, so
            # the message blamed the ACL and told the user to do what they
            # were already doing (2026-08-29).
            gone = _wait_until(
                lambda: not mountstate.pid_alive(st.pid)
                and not os.path.lexists(st.mountpoint or project),
                timeout=WAIT_UNMOUNT, label="waiting for the guard to let go")
            out.append({"n": 1, "ok": True,
                        "text": f"stopped the filesystem guard (pid {st.pid})"
                                + ("" if gone else " - it has not released the "
                                   "mount point yet; re-run teardown")})
        except Exception as exc:
            # DO NOT clear the record. The guard is still running; erasing our
            # note of it would leave a live process nobody can see - doctor
            # would report "not recorded" while a filesystem is being served.
            out.append({"n": 1, "ok": False,
                        "text": f"could not stop the filesystem guard (pid {st.pid})",
                        "detail": [str(exc), "The record is KEPT so the guard stays visible."],
                        "remedy": f"demo_cli unmount --root {cfg.project_root}"})
            return out               # nothing below can succeed while it runs
    else:
        mountstate.clear(cfg)
        out.append({"n": 1, "ok": True, "text": "filesystem guard not running"})

    # "Absent" and "removed" are different facts, and reporting the first as
    # the second is how a teardown looks complete while leaving things behind.
    had = schedule.status(project).exists
    if not had:
        out.append({"n": 2, "ok": True, "text": "no logon task was registered for this project"})
    else:
        schedule.unregister(project)
        still = schedule.status(project).exists
        if not still:
            out.append({"n": 2, "ok": True, "text": "removed the logon task"})
        else:
            # This line used to be four words with no cause and no remedy,
            # while step 1 above named the pid, the reason and the command.
            # The task survived a "successful" teardown on 2026-08-29 and
            # would have fired at every logon, mounting a backing that had
            # just been moved away - silently, forever.
            out.append({"n": 2, "ok": False, "text": "could not remove the logon task",
                        "detail": [f"it is still registered as: {schedule.task_name(project)}",
                                   "it will run at every logon and fail, because the "
                                   "backing it mounts has been moved back"],
                        "remedy": f'schtasks /delete /tn "{schedule.task_name(project)}" /f'})

    backing = protect_mod.backing_for(project)
    if not os.path.isdir(backing):
        out.append({"n": 3, "ok": True, "text": "project was not protected"})
        return out

    if os.path.lexists(project):        # the junction must go or the rename has nowhere to land
        try:
            os.rmdir(project)
        except OSError:
            pass
    plan = protect_mod.plan_unprotect(project)
    if not plan.ok:
        out.append({"n": 3, "ok": False, "text": "could not restore your files",
                    "detail": plan.problems,
                    "remedy": f"demo_cli unprotect {project}"})
        return out
    try:
        for line in protect_mod.unprotect(plan):
            pass
        detail = [f"now at {project}"]
        # CLEAR THE MOUNT RECORD AGAIN, HERE, AT ITS FINAL LOCATION.
        #
        # Step 1 already called mountstate.clear(), but that ran while the
        # guard was being killed and it deleted THROUGH the mount - so the
        # unlink hit a filesystem that was going away, failed, and clear()
        # swallows OSError. The record then rode along inside .demo_cli when
        # the backing was moved back, and doctor reported
        #
        #   [x] filesystem guard  RECORDED BUT NOT RUNNING - pid 18792 is gone
        #
        # about a project that had just been torn down correctly (2026-09-02).
        # A clean teardown that ends in a red FAIL teaches people to ignore
        # doctor, which is the opposite of what it is for.
        #
        # Now the files are back on real disk, so this delete is an ordinary
        # one - and it is CHECKED, because a silent best-effort is what
        # produced the stale record in the first place.
        leftover = os.path.join(project, cfg.workspace_dir, "mount.json")
        if os.path.exists(leftover):
            try:
                os.unlink(leftover)
            except OSError as exc:
                detail.append(f"the stale mount record could not be removed "
                              f"({exc.strerror}); doctor will report a guard "
                              f"that is not running until it is deleted: {leftover}")
        out.append({"n": 3, "ok": True, "text": "your files were moved back",
                    "detail": detail})
    except (PermissionError, OSError) as exc:
        out.append({"n": 3, "ok": False, "text": "could not restore your files",
                    "detail": [str(exc), f"they are safe at {backing}"],
                    "remedy": f"demo_cli unprotect {project}"})
    return out


def _teardown_needs_admin(project: str, cfg) -> bool:
    from . import mountstate, protect as protect_mod, schedule
    return bool(mountstate.status(cfg).running
                or schedule.status(project).exists
                or os.path.isdir(protect_mod.backing_for(project)))


def cmd_teardown_admin(a) -> int:
    """(internal) The elevated half of teardown. Writes its results as JSON so
    the unelevated parent can render them; its own console closes with it."""
    project = os.path.abspath(a.project)
    steps = _teardown_admin_steps(project, load_config(project))
    try:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(steps, f)
    except OSError:
        return 2
    return 0 if all(x["ok"] for x in steps) else 1


def _show_step(x: dict) -> None:
    _step(x["n"], x["text"] if x["ok"] else render.c(x["text"], "yellow"))
    for line in x.get("detail") or []:
        print("      " + render.c(line, "dim"))
    if x.get("remedy"):
        print("      " + render.c("fix it with:  " + x["remedy"], "dim"))


def cmd_teardown(a) -> int:
    """Remove everything setup added, in reverse, on a machine in any state.

    It never refuses to continue because a step was already done. A teardown
    that only works when everything is healthy is not a way out - and the
    moment somebody reaches for it is usually the moment something is broken.

    ONE UAC PROMPT, UP FRONT. Three of the four steps need Administrator - the
    mount runs elevated, the logon task is /rl highest, and the backing is
    locked to Administrators. The first version discovered that one step at a
    time: it stopped, told you to open an admin shell, and asked you to re-run.
    Tearing down `demo` on 2026-08-29 took THREE invocations across two shells,
    and still left the logon task registered. Teardown is what somebody reaches
    for when things are already wrong; it is the last place to make them
    assemble the fix themselves.
    """
    from . import protect as protect_mod

    project = os.path.abspath(getattr(a, "project", None) or os.getcwd())
    print(render.c(f"\ndemo_cli {__version__}  teardown  ->  {project}\n", "dim"))

    cfg = load_config(project)
    needs_admin = os.name == "nt" and _teardown_needs_admin(project, cfg)

    # Nothing here at all is a WRONG TARGET, not a clean teardown. Four
    # "nothing to do" lines for a path that does not exist read as success and
    # send somebody away while their real project is still mounted and locked
    # (observed 2026-08-29: `demo_cli teardown demo` run one directory up).
    if not needs_admin and not os.path.isdir(project) and not _any_hook_installed(cfg):
        print(render.c(f"  {project} does not exist, and nothing is registered "
                       f"for it.", "red"))
        print(render.c("  Nothing was torn down. Did you mean an absolute path?\n", "dim"))
        return 1

    if not getattr(a, "yes", False):
        print("  This removes the hooks, the logon task, and moves your files back.")
        if input("  Type 'yes' to continue: ").strip().lower() != "yes":
            print("  Nothing was changed.\n")
            return 1

    steps: List[dict] = []
    if os.name != "nt":
        steps = _teardown_admin_steps(project, cfg)
    elif protect_mod.is_elevated():
        steps = _teardown_admin_steps(project, cfg)
    elif needs_admin:
        print(render.c("  [demo_cli] stopping the guard, removing the logon task and "
                       "moving your files back all need Administrator; asking once.",
                       "yellow"))
        report = os.path.join(tempfile.gettempdir(),
                              f"demo_cli-teardown-{os.getpid()}.json")
        rc = protect_mod.rerun_elevated(["_teardown-admin", project, "--report", report])
        try:
            with open(report, encoding="utf-8") as f:
                steps = json.load(f)
            os.unlink(report)
        except Exception:
            steps = [{"n": 1, "ok": False,
                      "text": "the elevated teardown did not report back"
                              + ("" if rc is not None else " (elevation refused)"),
                      "remedy": f"demo_cli teardown {project}   (from an Administrator shell)"}]
    else:
        steps = _teardown_admin_steps(project, cfg)

    for x in steps:
        _show_step(x)

    # Hooks are the user's own config files and need no elevation, so they are
    # removed HERE rather than in the elevated child - an elevated process is
    # the wrong thing to be editing a user profile with.
    removed = _remove_hooks(project)
    steps.append({"n": 4, "ok": True,
                  "text": f"removed hooks: {', '.join(removed)}" if removed
                          else "no hooks to remove"})
    _show_step(steps[-1])

    failed = [x for x in steps if not x["ok"]]
    if failed:
        # A teardown that ends on the cheerful audit-trail note while two
        # steps failed is the same lie as "installed" when nothing is active.
        print(render.c(f"\n  {len(failed)} step(s) did not complete: "
                       + ", ".join(str(x["n"]) for x in failed), "red"))
        print(render.c("  Re-run this teardown once you have dealt with them.\n", "dim"))
        return 1

    print(f"\n  {render.c('The config and receipts are left in place - they are ', 'dim')}"
          f"{render.c('your audit trail.', 'dim')}")
    print(f"  {render.c('Remove them yourself if you want: ' + cfg.workspace, 'dim')}\n")
    return 0


def cmd_register_task(a) -> int:
    """(internal) Register the logon task. Its own subcommand only so setup can
    re-run itself elevated for this one step."""
    from . import protect as protect_mod, schedule
    project = os.path.abspath(a.project)
    return 0 if schedule.register(project, protect_mod.backing_for(project)) else 1


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


_MITM_DIR = "~/.mitmproxy"
_CA_PEM_NAME = "mitmproxy-ca-cert.pem"    # Python / Node clients
_CA_CER_NAME = "mitmproxy-ca-cert.cer"    # the Windows certificate store


def _ca_path(name: str) -> str:
    """Expand and NORMALISE, in that order.

    expanduser only replaces the '~'. Building the rest of the path with
    forward slashes therefore printed
    `C:\\Users\\pc/.mitmproxy/mitmproxy-ca-cert.pem` on Windows - which works,
    and looks broken enough that a user reasonably assumes it is.
    """
    return os.path.normpath(os.path.join(os.path.expanduser(_MITM_DIR), name))


def egress_setup_lines(port: int, windows: bool) -> List[str]:
    """The steps a person has to perform, in their own shell's language.

    Separate from cmd_egress so the two dialects can be asserted in tests
    without launching a proxy. Printing `export VAR=value` to somebody running
    PowerShell is the same class of mistake as telling them to write a config
    with Out-File - it looks helpful and does not work.
    """
    pem = _ca_path(_CA_PEM_NAME)
    if windows:
        return [
            "1) point the agent's traffic at the proxy:",
            f'     $env:HTTPS_PROXY = "http://localhost:{port}"',
            f'     $env:HTTP_PROXY  = "http://localhost:{port}"',
            "2) let it read TLS. Python and Node honour these:",
            f'     $env:REQUESTS_CA_BUNDLE = "{pem}"',
            f'     $env:NODE_EXTRA_CA_CERTS = "{pem}"',
            "   Windows-native clients (Invoke-WebRequest, .NET, curl.exe) ignore",
            "   those and read the certificate store instead:",
            "     demo_cli egress --trust-ca        (undo: --untrust-ca)",
            "3) relaunch the agent from that shell. Ctrl-C here stops the guard.",
        ]
    return [
        "1) point the agent's traffic at the proxy:",
        f"     export HTTPS_PROXY=http://localhost:{port}  HTTP_PROXY=http://localhost:{port}",
        "2) let it read TLS by trusting mitmproxy's CA (first run generates it):",
        f"     export REQUESTS_CA_BUNDLE={pem}   NODE_EXTRA_CA_CERTS={pem}",
        "3) relaunch the agent from that shell. Ctrl-C here stops the guard.",
    ]


def _trust_ca(remove: bool = False) -> int:
    """Add or remove mitmproxy's root CA in the CURRENT USER's trust store.

    -user, never -machine: a per-user store is the smaller blast radius and
    needs no elevation. Installing a root CA machine-wide to read one agent's
    traffic is not a trade this tool should make for you.

    A trusted root CA is a real change to what this machine believes. While it
    is installed, anything holding mitmproxy's private key can transparently
    read and rewrite your HTTPS - which is exactly how the guard works, and
    exactly why --untrust-ca exists and is printed every time.
    """
    import subprocess
    if os.name != "nt":
        print("--trust-ca is Windows-only (the certificate store).")
        print(f"On Linux, point clients at {_ca_path(_CA_PEM_NAME)} with")
        print("REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS, or add it to your")
        print("distribution's CA bundle.")
        return 1
    cer = _ca_path(_CA_CER_NAME)
    if not remove and not os.path.exists(cer):
        print(f"{cer} does not exist yet.")
        print("mitmproxy generates its CA on first run:  demo_cli egress")
        return 1
    verb = "delstore" if remove else "addstore"
    args = ["certutil", "-user", "-" + verb, "Root",
            "mitmproxy" if remove else cer]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"certutil failed:\n{(r.stdout or '') + (r.stderr or '')}".rstrip())
        return 1
    if remove:
        print("Removed mitmproxy's CA from your user trust store.")
    else:
        print(f"Trusted {cer} in your USER certificate store.")
        print()
        print("  While this is installed, anything holding mitmproxy's private")
        print("  key can read and rewrite your HTTPS traffic. That is how the")
        print("  guard inspects requests - and why you should remove it when")
        print("  you are done:   demo_cli egress --untrust-ca")
    return 0


def cmd_egress(a) -> int:
    """Start the egress guard: an mitmproxy addon that gates destructive external
    / SaaS API calls on the network wire. Shells out to the installed `mitmdump`
    (demo_cli never imports mitmproxy), mirroring how recovery.py uses pg_dump."""
    import shutil
    import subprocess

    if getattr(a, "trust_ca", False) or getattr(a, "untrust_ca", False):
        return _trust_ca(remove=getattr(a, "untrust_ca", False))

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

    print(render.c(f"\ndemo_cli egress guard  (mode={mode}, port={port})\n", "dim"))
    for line in egress_setup_lines(port, windows=os.name == "nt"):
        print(line)
    print()

    # mitmdump runs its OWN Python; add demo_cli's location so the addon imports.
    env = dict(os.environ, DEMO_CLI_EGRESS_MODE=mode,
               PYTHONPATH=pkg_parent + os.pathsep + os.environ.get("PYTHONPATH", ""))
    argv = [mitm, "-s", loader, "--listen-port", str(port), "-q"]

    if os.name == "nt":
        # NOT os.execve. On Windows the exec family does not replace the
        # process the way POSIX does - it spawns a new one and terminates this
        # one, so the prompt returns immediately, the proxy is orphaned, and
        # Ctrl-C never reaches it. subprocess.run keeps it a child of this
        # shell, so Ctrl-C works and the exit code is real.
        try:
            return subprocess.run(argv, env=env).returncode
        except KeyboardInterrupt:
            return 0
    # os.execve REPLACES this process image without flushing Python's stdio
    # buffers. Redirected to a file or a pipe, stdout is block-buffered, so
    # every setup instruction printed above is discarded and the user sees
    # nothing before mitmdump takes over. cmd_guarded already flushes for the
    # same reason; this path did not.
    sys.stdout.flush()
    os.execve(mitm, argv, env)


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
            for _ in range(20):                 # up to ~4s for the port to open
                if g.port_open(port):
                    break
                time.sleep(0.2)

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

    env = g.child_env(dict(os.environ), port, g.port_open(port))

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

    # `receipts` is an ALIAS, not a second command. Two different agents have
    # now guessed `demo_cli receipts` and got an argparse usage error - the
    # workspace file is called receipts.jsonl and doctor talks about "agent
    # receipts", so the name is one the tool teaches people. A guessable name
    # that errors is a small failure the guard can simply not have.
    lg = sub.add_parser("log", parents=[common], aliases=["receipts"],
                        help="list captured recovery points")
    lg.add_argument("--last", type=int, default=None, metavar="N",
                    help="show only the N most recent")
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

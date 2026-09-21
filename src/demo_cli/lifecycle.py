"""Setup and teardown lifecycle management.

Handles project protection lifecycle:
- Initial project setup, hook configuration, and guard bootstrapping (`cmd_setup`)
- Clean project teardown, hook removal, and file restoration (`cmd_teardown`, `cmd_teardown_admin`)
- Scheduled task registration (`cmd_register_task`)
- Polling transitions and progress feedback (`_wait_until`)
"""
from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
from typing import List, Optional, Callable

from . import config as config_mod
from .config import CONFIG_NAME, load_config
from . import fsmount, mountstate, protect as protect_mod, schedule, guarded as g, render
from .doctor import _HOSTS, _host_hook_status, _any_hook_installed
from .version import __version__

CONFIG_TEMPLATE = """\
# demo_cli configuration. All fields are optional; defaults are safe.
# Docs: https://github.com/nizaryart/DEMO_LOADING

mode = "shadow"            # "shadow" observes only; "enforce" gates actions

[workspace]
dir = ".demo_cli"          # receipts + recovery points live here (per project)

# [egress]
# port = 8080              # network proxy listen port (default: 8080 or [egress] in config)
# mode = "shadow"          # "shadow" logs SaaS calls; "enforce" blocks destructive calls
# strict_unknown_hosts = false  # block writes to unlisted external SaaS hosts
# saas_hosts = ["api.stripe.com", "api.github.com"]  # hosts treated as SaaS APIs
# no_proxy = ["localhost", "127.0.0.1"]               # hosts bypassing the egress proxy

# [cloak]
# enabled = true           # hides sensitive credential files from the virtual mount
# patterns = ["*.env", ".env*", ".demo_cli.toml", "*.key"]

# [env]
# strip = ["AWS_*", "*_SECRET*", "*_TOKEN", "DATABASE_URL"]
# preserve = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]

# [checkpoint]
# enabled = false          # take whole-workspace checkpoints when targets cannot be resolved

# [approval]
# key_env = "DEMO_CLI_APPROVER_KEY"   # env var holding the structural-approval key

# Declare your real targets so environment is known, not guessed.
# Tip: You can also manage targets with `demo_cli target add <pattern> --env production`
# [[target]]
# match = "production"     # substring or glob (*.db) matched against the resolved target ref
# env = "production"       # production | staging | development
# recovery = "snapshot"    # snapshot | none   (attest is reserved)
"""
_CONFIG_TEMPLATE = CONFIG_TEMPLATE

WAIT_MOUNT = 240.0        # a guard coming up
WAIT_UNMOUNT = 120.0      # a guard letting go


def _show_plan(plan, title: str, next_steps: List[str]) -> int:
    """Print what is about to happen, then require the word 'yes'.

    This command MOVES SOMEBODY'S PROJECT. It prints the exact before and after
    paths and waits, every time, unless --yes is passed deliberately. A y/N
    prompt is too easy to hit by reflex for an operation this size.
    """
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
    for label, directory, filename, event, command, nested, _module in _HOSTS:
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


def _wait_until(check: Callable[[], bool], timeout: float = WAIT_MOUNT, interval: float = 0.5,
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
    out: List[dict] = []

    st = mountstate.status(cfg)
    if st.running:
        try:
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
    return bool(mountstate.status(cfg).running
                or schedule.status(project).exists
                or os.path.isdir(protect_mod.backing_for(project)))


def cmd_teardown_admin(a) -> int:
    """(internal) The elevated half of teardown. Writes its results as JSON so
    the unelevated parent can render them; its own console closes with it."""
    project = os.path.abspath(a.project)
    admin_steps_fn = getattr(sys.modules.get("demo_cli.cli"), "_teardown_admin_steps", _teardown_admin_steps)
    steps = admin_steps_fn(project, load_config(project))
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
    admin_steps_fn = getattr(sys.modules.get("demo_cli.cli"), "_teardown_admin_steps", _teardown_admin_steps)
    if os.name != "nt":
        steps = admin_steps_fn(project, cfg)
    elif protect_mod.is_elevated():
        steps = admin_steps_fn(project, cfg)
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
        steps = admin_steps_fn(project, cfg)

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
    project = os.path.abspath(a.project)
    return 0 if schedule.register(project, protect_mod.backing_for(project)) else 1


def cmd_setup(a) -> int:
    """One command to make a project guarded, and to say what that means.

    Setup used to be six commands across two shells with an implicit order and
    elevation at unpredictable points. Nothing told anyone how far they had
    got, and "installed but inert" has been the dangerous state six times in
    this project - four independent manual steps is how a seventh happens.

    What it will NOT do without asking: move your files. That is printed in
    full and confirmed, every time.
    """
    project = os.path.abspath(getattr(a, "project", None) or os.getcwd())
    yes = getattr(a, "yes", False)
    print(render.c(f"\ndemo_cli {__version__}  setup  ->  {project}\n", "dim"))

    # PROTECTION STATUS FIRST, because it decides WHERE the config may be
    # written. Once a project is protected, its own path IS the mount point -
    # so writing a file there creates a real directory that BLOCKS mounting,
    # and a second config competing with the real one. That is exactly what
    # happened on 2026-08-28: setup wrote myproj\\.demo_cli.toml, the logon
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
    mounted_now = mountstate.status(load_config(project)).running
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
    for label, directory, filename, event, command, nested, _module in ([] if defer else _HOSTS):
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
        if mountstate.status(load_config(project)).running:
            _step(5, "filesystem guard already running")
        elif schedule.run_now(project):
            # The old wait here was 15 x 0.4s. Six seconds, silent - and this
            # machine took closer to four minutes between `schtasks /run` and
            # a live mount, so setup reported "not mounted" about a guard that
            # was still starting, and we spent an hour debugging a success.
            _step(5, "starting the filesystem guard")
            up = _wait_until(lambda: mountstate.status(load_config(project)).running,
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

    if defer and mountstate.status(load_config(project)).running:
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
    port, err = cfg.resolve_egress_port(getattr(a, "port", None))
    if err:
        print(render.c(f"  demo_cli setup: {err}", "red"))
        return 1
    print(render.c("\n  coverage\n", "dim"))
    for layer in g.assess(cfg, port, _host_hook_status(cfg)):
        mark = render.c("[+]", "green") if layer.ok else render.c("[!]", "yellow")
        print(f"  {mark} {layer.name:<16} {layer.detail}")
        if layer.fixable:
            print(f"      {render.c('turn it on: ' + layer.fixable, 'dim')}")

    print(f"\n  {render.c('Start your agent with:  demo_cli guarded claude', 'dim')}")
    print(f"  {render.c('Undo everything:        demo_cli teardown', 'dim')}\n")
    return 0


__all__ = [
    "CONFIG_TEMPLATE",
    "_CONFIG_TEMPLATE",
    "WAIT_MOUNT",
    "WAIT_UNMOUNT",
    "_show_plan",
    "_step",
    "_protected_children",
    "_install_hook_for",
    "_remove_hooks",
    "_strip_hook_entries",
    "_wait_until",
    "_teardown_admin_steps",
    "_teardown_needs_admin",
    "cmd_teardown_admin",
    "_show_step",
    "cmd_teardown",
    "cmd_register_task",
    "cmd_setup",
]

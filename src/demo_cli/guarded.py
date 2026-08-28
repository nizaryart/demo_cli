"""Run an agent with every layer that can be brought up, brought up.

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
Setup had become four separate things with four different lifetimes: hooks
(persistent, per host), the filesystem mount (detached, needs admin), the
egress proxy (a second terminal), and environment variables (per shell). A
person has to remember all four, and nothing tells them how many are actually
on. "Installed but inert" has been the dangerous state five times in this
project; four independent setup steps is how a sixth happens.

The agent is the unit being guarded, so one command brings up what it can for
exactly that agent's lifetime, REPORTS THE COVERAGE HONESTLY, and launches it.

    demo_cli guarded claude

--------------------------------------------------------------------------
WHY ENVIRONMENT VARIABLES REACH A FRESH SHELL
--------------------------------------------------------------------------
Claude Code spawns a new `powershell -NoProfile` (or bash) for every tool
call, and we verified that a variable set INSIDE one tool call is gone by the
next - each shell dies with its call. That is siblings.

This sets the variables one level UP, on the agent process itself:

    demo_cli guarded claude
      └─ claude                  <- environment set here, once
           ├─ powershell         <- inherits
           │    └─ python        <- inherits
           └─ powershell         <- inherits (new shell, same parent)

Every fresh shell is a child of the agent, so it inherits at spawn. -NoProfile
skips profile SCRIPTS; it does not clear the environment.

Which is also why only two layers need this. The mount is a PATH - anything
touching it is guarded with nothing to inherit - and hooks are config files the
host reads. Only egress and the bash shell guard travel through the
environment.

--------------------------------------------------------------------------
WHAT IT WILL NOT DO
--------------------------------------------------------------------------
Start the mount        it needs elevation, and the project has to have been
                       relocated first (`demo_cli protect`). Silently moving
                       somebody's project because they typed `guarded` is not
                       a thing this should do.
Install hooks          they are persistent host config. Verified, never
                       written behind the user's back.
Trust the CA           a root CA must never appear on a machine without being
                       asked for.
Everything it cannot start, it REPORTS. A layer that is off should be visible
at the moment the agent launches, not discoverable later by running doctor.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional

from .config import Config

# localhost must never be proxied: the agent talking to a local dev server, or
# to the guard's own port, would otherwise loop back through the proxy.
_NO_PROXY = "localhost,127.0.0.1,::1"


@dataclass
class Layer:
    """One protection layer, and whether it is actually on right now."""
    name: str
    ok: bool
    detail: str
    fixable: Optional[str] = None      # the command that would turn it on


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    """Is something listening? The only honest test for 'is the proxy up'.

    A recorded pid would not do: mitmdump is started separately, may be run by
    hand in another terminal, and may have died. Connecting is the question
    actually being asked.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ca_bundle() -> Optional[str]:
    path = os.path.normpath(
        os.path.join(os.path.expanduser("~/.mitmproxy"), "mitmproxy-ca-cert.pem"))
    return path if os.path.exists(path) else None


def shell_guard_script() -> Optional[str]:
    path = os.path.expanduser("~/.demo_cli_shellguard.sh")
    return path if os.path.exists(path) else None


def child_env(base: Dict[str, str], port: int, egress_up: bool) -> Dict[str, str]:
    """The environment the agent is launched with.

    Only variables whose layer is ACTUALLY RUNNING are set. Pointing
    HTTPS_PROXY at a dead port is the footgun that makes people uninstall the
    tool: every network call in every child then fails, long after anyone
    remembers setting it. This is also why the variables are scoped to the
    child instead of written with setx - they cannot outlive the thing they
    describe.
    """
    env = dict(base)
    if egress_up:
        env["HTTPS_PROXY"] = env["https_proxy"] = f"http://localhost:{port}"
        env["HTTP_PROXY"] = env["http_proxy"] = f"http://localhost:{port}"
        env["NO_PROXY"] = env["no_proxy"] = _NO_PROXY
        ca = ca_bundle()
        if ca:
            # Python (requests/httpx) and Node respectively. Without these the
            # proxy is in the path but every TLS handshake fails, which looks
            # like the guard broke the internet.
            env["REQUESTS_CA_BUNDLE"] = ca
            env["NODE_EXTRA_CA_CERTS"] = ca
    guard = shell_guard_script()
    if guard and os.name != "nt":
        # Makes a non-interactive `bash -c` source the DEBUG trap - the same
        # mechanism install-shell-guard writes into .bashrc, scoped here to
        # the agent instead of to every shell the human opens.
        env["BASH_ENV"] = guard
    return env


def assess(cfg: Config, port: int, hooks: List[tuple],
           egress_up: Optional[bool] = None) -> List[Layer]:
    """Which layers are protecting this project, right now.

    `hooks` comes from the caller (cli._host_hook_status) so this module stays
    free of the CLI's host table, and the whole function stays testable
    without a filesystem full of host configs.
    """
    from . import fsmount, mountstate, protect as protect_mod

    layers: List[Layer] = []

    installed = [label for label, path in hooks if path]
    layers.append(Layer(
        "string layer", bool(installed),
        f"hook active ({', '.join(installed)})" if installed
        else "no host hook installed - tool calls are not classified",
        None if installed else "demo_cli install-hook"))

    st = mountstate.status(cfg)
    if st.running:
        locked = protect_mod.is_locked(st.backing) if st.backing else None
        note = (" (backing locked)" if locked else
                " (backing NOT locked - writable directly)" if locked is False else "")
        layers.append(Layer("filesystem", True, f"mounted at {st.mountpoint}{note}"))
    elif st.stale:
        layers.append(Layer("filesystem", False,
                            f"RECORDED BUT NOT RUNNING (pid {st.pid} is gone)",
                            "demo_cli unmount, then demo_cli mount ..."))
    elif os.name == "nt":
        layers.append(Layer("filesystem", False, "not mounted",
                            "demo_cli protect <project>  (then mount, elevated)"))
    else:
        # No always-on equivalent on Linux: the syscall guard wraps one command
        # rather than standing between the agent and the disk.
        layers.append(Layer("filesystem", False,
                            "no always-on layer on Linux; use demo_cli run <cmd>"))

    up = port_open(port) if egress_up is None else egress_up
    ca = ca_bundle()
    layers.append(Layer(
        "egress", up,
        (f"proxy on :{port}" + ("" if ca else ", but no CA yet - TLS will fail"))
        if up else f"nothing listening on :{port}",
        None if up else f"demo_cli egress --port {port}"))

    if os.name != "nt":
        guard = shell_guard_script()
        layers.append(Layer("shell guard", bool(guard),
                            guard or "not installed - !-mode is unguarded",
                            None if guard else "demo_cli install-shell-guard"))
    return layers


def summary(layers: List[Layer]) -> str:
    on = sum(1 for x in layers if x.ok)
    return f"{on} of {len(layers)} layers active"


def dropped(before: List[Layer], after: List[Layer]) -> List[Layer]:
    """Layers that were up and are not any more.

    WHY A HEARTBEAT AT ALL. The coverage report prints once, at launch. If the
    mount crashes an hour into a session - or someone runs `demo_cli unmount`
    in another window, or the egress proxy dies - nothing says so, and the
    person keeps working while believing they are covered. That is the SIXTH
    appearance of "is this thing actually protecting me?" in this project, and
    the one place it had no answer.

    Only TRANSITIONS are reported, never the current state. A guard that
    prints its status every minute is noise, and noise is how a real warning
    gets missed.
    """
    was_ok = {x.name for x in before if x.ok}
    return [x for x in after if not x.ok and x.name in was_ok]


def recovered(before: List[Layer], after: List[Layer]) -> List[Layer]:
    """The other direction: a layer that came back. Worth saying, because it
    tells the user the earlier warning no longer applies - otherwise they act
    on stale information for the rest of the session."""
    was_down = {x.name for x in before if not x.ok}
    return [x for x in after if x.ok and x.name in was_down]

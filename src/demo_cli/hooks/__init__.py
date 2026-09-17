"""Agent-harness integrations (auto-fire entrypoints)."""
import json
import os

TAG = "[demo_cli]"


class HostConfigUnreadable(RuntimeError):
    """The host's config exists and could not be understood, so we will not
    rewrite it. _remove_hooks already obeys this rule (cli.py: "a config we
    cannot parse is one we must not rewrite"); the install path did not, and
    it is the path that rewrites the whole file."""


def load_host_config(path: str) -> dict:
    """The host's existing config, or {} when there is nothing to preserve.

    Reads utf-8-SIG because PowerShell writes a BOM and this project has been
    bitten by one three times. A file that still will not parse RAISES: the
    old behaviour was to treat it as {} and then dump our hooks over the top,
    which replaces every permission, model and plugin the user had - silently,
    exit 0, with "Installed..." printed.

    An EMPTY file is treated as absent. It holds nothing to lose, and
    refusing on `touch settings.json` would be an error with no cause.
    """
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as exc:
        raise HostConfigUnreadable(f"{path} could not be read ({exc})") from exc
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise HostConfigUnreadable(
            f"{path} is not valid JSON ({exc}). demo_cli will NOT rewrite it: "
            f"that would replace everything else the file holds. Fix it or move "
            f"it aside, then re-run. A UTF-8 BOM is the usual cause when "
            f"PowerShell wrote the file.") from exc
    if not isinstance(data, dict):
        raise HostConfigUnreadable(
            f"{path} holds a JSON {type(data).__name__}, not an object; "
            f"demo_cli will not rewrite it.")
    return data


def event_list(settings: dict, event: str) -> list:
    """The handler list for `event`, created when absent.

    Refuses instead of crashing when a container is the wrong shape:
    {"hooks": []} raised AttributeError out of setdefault and
    {"hooks": {"PreToolUse": {}}} out of append, straight past the CLI with
    no handler anywhere. Same rule as above - a shape we do not understand is
    one we must not write into.
    """
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise HostConfigUnreadable(
            f'"hooks" is a JSON {type(hooks).__name__}, not an object')
    handlers = hooks.setdefault(event, [])
    if not isinstance(handlers, list):
        raise HostConfigUnreadable(
            f'"hooks.{event}" is a JSON {type(handlers).__name__}, not an array')
    return handlers


def attributed(reason: str) -> str:
    """Prefix a message the AGENT will read with who is speaking.

    The hosts render our decision reason as their own denial text, with no
    indication of where it came from. Observed 2026-08-26: a block reading

        No recovery path for a mutating action on 'unknown';
        cannot auto-recover. Human input required.

    left the agent guessing - it told the user "this looks like a safety gate
    in the environment", then advised running the command outside the session
    to get around it. Which is exactly the wrong conclusion, and it reached it
    honestly, because nothing in the message says demo_cli.

    Two reasons this matters more than tidiness:
      * an agent that cannot attribute a block cannot report it usefully, and
        may route around what it thinks is a flaky environment
      * a person seeing an unexplained refusal blames whatever they installed
        most recently, which is a bad way to find out it was us

    Applied only to text leaving for a host. Receipt reasons stay clean: the
    ledger records what was decided, not who printed it.
    """
    reason = (reason or "").strip()
    if reason.startswith(TAG):
        return reason
    return f"{TAG} {reason}" if reason else TAG

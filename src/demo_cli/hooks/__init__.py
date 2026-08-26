"""Agent-harness integrations (auto-fire entrypoints)."""

TAG = "[demo_cli]"


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

"""Three defects found by review on 2026-09-07, in cli.py.

None of them produces a false REVERSIBLE, so none is severe by this project's
one severity axis. Two are honesty defects all the same - a layer that goes
inert after coverage has reported it up, and a failure message that blames a
cause the code already knows is wrong.

The third is the more interesting one for the record: it is the first defect
in this project found by READING rather than by running the tool. Every other
one - ten on 2026-09-02, six on 2026-09-05/06 - came from a lab run.
"""
import inspect
import os
import re

import pytest

from demo_cli import cli


# --------------------------------------------------------------------------
# 1. Both detached children must use the same process-creation flags.
# --------------------------------------------------------------------------

def test_the_windows_console_flags_are_defined_once():
    """They were defined twice, and the copies disagreed.

    _mount_detached was fixed on 2026-08-29 to drop DETACHED_PROCESS, because
    Windows ignores CREATE_NO_WINDOW when it is set - so the guard ran with a
    visible console for its whole life. cmd_guarded's egress spawn kept the
    broken pair for nine days.
    """
    src = inspect.getsource(cli)
    # The literal 0x00000008 may appear once, as the documented-but-unused
    # reference constant. It must not appear in any creationflags expression.
    for m in re.finditer(r"creationflags[^\n]*", src):
        assert "0x00000008" not in m.group(0), \
            f"DETACHED_PROCESS is back in a creationflags expression: {m.group(0)}"
        assert "0x08000000" not in m.group(0), \
            "raw flag literal in creationflags - use the module constants"


def test_every_detached_child_uses_the_same_combination():
    src = inspect.getsource(cli)
    exprs = re.findall(r"creationflags[\"']?\]?\s*[:=]\s*([^\n,}]+)", src)
    assert len(exprs) >= 2, "expected the mount and the egress spawn"
    normalised = {e.strip().strip("}") for e in exprs}
    assert len(normalised) == 1, \
        f"detached children disagree on their flags: {normalised}"


def test_the_constants_are_the_documented_values():
    assert cli._CREATE_NO_WINDOW == 0x08000000
    assert cli._CREATE_NEW_PROCESS_GROUP == 0x00000200
    assert cli._DETACHED_PROCESS == 0x00000008, \
        "kept as a reference for the comment that explains why it is not used"


# --------------------------------------------------------------------------
# 2. os.execve does not flush Python's buffers.
# --------------------------------------------------------------------------

def test_the_egress_exec_flushes_first():
    """cmd_egress prints the proxy and TLS setup instructions and then replaces
    its own process image. Redirected to a file or a pipe, stdout is
    block-buffered and every one of those lines is discarded - the user is
    told nothing and mitmdump takes over. cmd_guarded already flushed for
    exactly this reason; this path did not."""
    src = inspect.getsource(cli.cmd_egress)
    # The CALL, not the comment above the Windows branch that says "NOT
    # os.execve" - matching that instead is how this test first passed for
    # the wrong reason.
    m = re.search(r"^\s*os\.execve\(", src, re.M)
    assert m, "cmd_egress no longer execs; this test needs rewriting"
    assert "sys.stdout.flush()" in src[:m.start()], \
        "os.execve replaces the process without flushing stdio"


# --------------------------------------------------------------------------
# 3. undo must not blame permissions after a retry that had them.
# --------------------------------------------------------------------------

def test_undo_stops_claiming_administrator_after_an_elevated_retry_failed():
    """The branch is entered only when result.denied is True, so passing
    result.denied straight through meant the banner always said "This recovery
    point needs Administrator" - printed directly under the elevated child's
    own output explaining the real reason.

    On 2026-09-02 the log said "searched C:\\Windows\\system32\\.demo_cli\\
    recovery" while the user was told they needed Administrator. They had it.
    That incident produced the elevated-output print; the banner underneath
    was left as it was.
    """
    src = inspect.getsource(cli.cmd_undo)
    assert "denied=result.denied" not in src, \
        "the render call still forwards the pre-retry denial verdict"
    assert re.search(r"^\s+denied = False", src, re.M), \
        "nothing clears the denial after a failed elevated retry"
    # And the cleared value has to be the one that reaches render.
    assert "denied=denied" in src


def test_denied_is_bound_on_every_path_through_undo():
    """The obvious way to write this fix - assigning `denied` only inside the
    retry branch - leaves it unbound on every other path, so an ordinary
    successful undo raises NameError. Caught while writing it."""
    src = inspect.getsource(cli.cmd_undo)
    first_assign = src.index("denied = ")
    first_use = src.index("denied=denied")
    assert first_assign < first_use
    # The initial binding must sit outside the `if not result.ok` block, i.e.
    # at the function's own indentation level.
    assert re.search(r"\n    denied = result\.denied", src), \
        "denied is not initialised at function scope"

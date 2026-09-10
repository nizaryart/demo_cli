"""A test named for a platform must be gated to that platform.

TWICE IN ONE DAY (2026-09-10):

    test_reading_an_acl_off_windows_is_unknown   asserted _read_dacl is None
    test_the_sddl_calls_are_inert_off_windows    asserted _sddl_of is None

Both had no skipif. Both passed on Linux, where the function under test does
nothing, and failed on Windows, where it does the thing it exists for. A
third instance is a habit, so this makes the class impossible instead of
fixing the instances.

The rule is narrow on purpose: it only judges tests whose own NAME claims a
platform. Naming a platform in the name and then running everywhere is the
mistake; everything else is left alone.
"""
import ast
import pathlib

import pytest

_CLAIMS = ("_off_windows", "_on_windows", "_off_linux", "_on_linux",
           "_windows_only", "_posix_only")

_ROOT = pathlib.Path(__file__).parent


# Tests whose NAME mentions a platform but which are deliberately
# cross-platform. Both assert pure logic ABOUT Windows that runs anywhere -
# which is the opposite of the defect above, where a test asserted that
# Windows-only code does nothing. Listed rather than pattern-matched, so
# adding one is a decision somebody makes on purpose.
_CROSS_PLATFORM_ON_PURPOSE = {
    # the PowerShell dialect is a parser flag, not a platform
    "test_unbalanced_quotes_degrade_on_windows_too",
    # says so in its own name: the predicate must work everywhere
    "test_the_windows_error_code_is_recognised_even_off_windows",
}


def _gated(node: ast.FunctionDef, src: str) -> bool:
    """Gated by a skipif, or branching on os.name inside the body.

    The second form is not as clear as a skipif, but it IS a platform check -
    the test knows where it is. What must not exist is a test that names a
    platform and then asserts the same thing everywhere.
    """
    if any("skipif" in ast.dump(d) for d in node.decorator_list):
        return True
    return "os.name" in ast.get_source_segment(src, node)


def _claims_a_platform():
    for path in sorted(_ROOT.glob("test_*.py")):
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                if any(c in node.name for c in _CLAIMS):
                    yield path.name, node, src


def test_every_test_that_names_a_platform_is_gated_to_it():
    ungated = [f"{f}::{n.name}" for f, n, src in _claims_a_platform()
               if not _gated(n, src) and n.name not in _CROSS_PLATFORM_ON_PURPOSE]
    assert not ungated, (
        "these tests name a platform but run on every one of them:\n  "
        + "\n  ".join(ungated))


def test_this_guard_can_actually_see_something():
    """A rule that matches nothing passes forever. If the naming convention
    changes, this fails and says so rather than going quietly green."""
    found = list(_claims_a_platform())
    assert found, "no test names a platform any more; this guard is now dead code"


def test_the_exemption_list_has_not_rotted():
    """An exemption for a test that no longer exists is a comment pretending
    to be a rule."""
    names = {n.name for _, n, _ in _claims_a_platform()}
    stale = _CROSS_PLATFORM_ON_PURPOSE - names
    assert not stale, f"exempted tests that no longer exist: {sorted(stale)}"

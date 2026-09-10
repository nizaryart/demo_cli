"""Suite-wide safety: no test may change a real ACL.

WHY THIS EXISTS. On 2026-09-10 the Windows suite passed 1067 tests and then
crashed in pytest's own teardown:

    PermissionError: [WinError 5] Access is denied:
    'C:\\Users\\pc\\AppData\\Local\\Temp\\pytest-of-pc\\pytest-current'

Nothing had failed. The tests had locked a temp directory for real and left
it that way, and pytest could not clean up after itself.

The mechanism: protect() and unprotect() take the lock branch when
is_elevated() says so, and MOST tests stub that - but a test only has to
forget, and on an elevated Windows run the real is_elevated answers True and
a real icacls runs against a real directory. The tests are green either way,
because the damage lands outside the assertions.

Auditing the call sites fixes today's tests and not tomorrow's. Closing the
seam fixes both: is_elevated is False for every test unless the test says
otherwise, which is what the four tests that need it already do.

A test that genuinely wants the real thing marks itself @pytest.mark.real_acl
and takes responsibility for cleaning up at the privilege it used - the same
rule that cost four failed Windows setups earlier in this project.
"""
import pytest

from demo_cli import protect as _protect


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_acl: this test may write a real ACL; it cleans up after itself")


@pytest.fixture(autouse=True)
def _no_real_acl_writes(request, monkeypatch):
    if request.node.get_closest_marker("real_acl"):
        return
    # A test that stubs this itself overrides what is set here, and both are
    # undone at teardown.
    monkeypatch.setattr(_protect, "is_elevated", lambda: False)

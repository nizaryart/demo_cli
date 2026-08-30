"""Starting something is not the same as it having started.

On 2026-08-29 the same assumption fired three times on one machine in one
evening:

  _mount_detached        sleep(2), then assume the child started. The child
                         was still importing; poll() returned None; the parent
                         wrote the state file and exited 0. `Last Result: 0`
                         with nothing mounted.
  setup step 5           polled for 15 x 0.4s = SIX SECONDS, silently. The
                         machine took ~4 minutes, so setup reported
                         "protected but not mounted" about a guard that came
                         up three minutes later - and we spent an hour
                         debugging a success.
  teardown step 1 -> 3   the kill returned, so assume the mount is gone.
                         WinFsp still held the directory, the rename failed
                         with ERROR_ACCESS_DENIED, and because that is the
                         same code as a permissions failure the message
                         blamed the ACL and told the user to use an
                         Administrator shell they were already in.

One helper, one rule: look at the thing itself.
"""
import time

from demo_cli import cli


def test_returns_true_as_soon_as_the_condition_holds():
    assert cli._wait_until(lambda: True, timeout=5) is True


def test_a_fast_condition_does_not_wait_out_the_timeout():
    """The timeout is a CEILING, not a wait. A generous ceiling must not slow
    a healthy machine down."""
    start = time.monotonic()
    assert cli._wait_until(lambda: True, timeout=240)
    assert time.monotonic() - start < 1.0


def test_returns_false_on_timeout():
    assert cli._wait_until(lambda: False, timeout=0.4, interval=0.05) is False


def test_it_waits_for_a_condition_that_becomes_true():
    calls = {"n": 0}

    def check():
        calls["n"] += 1
        return calls["n"] >= 3

    assert cli._wait_until(check, timeout=5, interval=0.01)
    assert calls["n"] == 3


def test_a_check_that_raises_means_not_yet_not_crash():
    """A mount point on a filesystem that is still coming up raises OSError
    when you stat it. That is 'not yet', not a failure of the wait."""
    calls = {"n": 0}

    def check():
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError("still coming up")
        return True

    assert cli._wait_until(check, timeout=5, interval=0.01)


def test_progress_is_printed_while_waiting(capsys):
    """Six silent seconds is what made a slow success look like a failure.
    A waiting guard must say it is waiting."""
    cli._wait_until(lambda: False, timeout=11, interval=0.01,
                    label="waiting for the guard")
    out = capsys.readouterr().out
    assert "waiting for the guard" in out
    assert "s" in out, "say how long it has been"


def test_nothing_is_printed_without_a_label(capsys):
    """The helper is used in places where output would be noise."""
    cli._wait_until(lambda: False, timeout=0.3, interval=0.05)
    assert capsys.readouterr().out == ""


def test_the_timeouts_are_generous_enough_for_a_slow_machine():
    """Named constants, not magic numbers - the previous magic number was 2.0
    seconds and it was wrong by two orders of magnitude."""
    assert cli.WAIT_MOUNT >= 240
    assert cli.WAIT_UNMOUNT >= 60

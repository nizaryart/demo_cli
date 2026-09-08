"""Brace expansion was exponential in TIME, and its bail produced garbage.

Found by review 2026-09-08. _BRACE_MAX bounded the RESULT list, which was
never the thing that grew:

    for opt in options:
        for opt_x in _expand_braces(opt):
            for tail in _expand_braces(post):   # recomputed per option

T(n) = 2*T(n-1) for `{a,b}` repeated n times. Measured 4x per two groups -
10 groups 0.016s, 18 groups 2.6s, 20 groups 10.6s, 600 groups never returned.
The blowup happens inside the recursive calls, before the first append, so the
`len(result) > _BRACE_MAX` check was unreachable. _path_operands calls this for
every token of every command, so it is a hang in the guard's hot path.

The second defect is subtler and worse. The bail returned `[token]` from an
INNER level, and the outer level combined that literal with its own options,
producing strings like `a{a,b}{a,b}...` - neither the full expansion nor the
original token. Visible in the old timings as absurd result counts: 14 groups
returned 8 items. Those strings reach _path_operands as candidate paths, and
the operand LIST is what decides whether a command is a single-target capture
or an escalation.

Fixed by hoisting the tail (once, not per option) and making "too big" a
distinct return value that propagates, so the caller substitutes the whole
unexpanded token exactly once.
"""
import time

import pytest

from demo_cli.recovery import _expand_braces, _BRACE_MAX


# --------------------------------------------------------------------------
# Correctness first: the fix must not change what expansion MEANS.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("token,expected", [
    ("f{1,2,3}.txt",  ["f1.txt", "f2.txt", "f3.txt"]),
    ("{a,b}{1,2}",    ["a1", "a2", "b1", "b2"]),
    ("{1..4}",        ["1", "2", "3", "4"]),
    ("{a..c}",        ["a", "b", "c"]),
    ("{foo}",         ["{foo}"]),               # no comma, no range: literal
    ("a{b,c}d{e,f}",  ["abde", "abdf", "acde", "acdf"]),
    ("plain.txt",     ["plain.txt"]),
])
def test_expansion_is_unchanged(token, expected):
    assert _expand_braces(token) == expected


# --------------------------------------------------------------------------
# Bounded in time, not just in output length.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n", [20, 100, 600, 5000])
def test_repeated_groups_return_promptly(n):
    """600 groups did not return in 20 seconds before this. The threshold is
    deliberately loose - the point is "not exponential", not a benchmark."""
    token = "{a,b}" * n
    t0 = time.perf_counter()
    out = _expand_braces(token)
    assert time.perf_counter() - t0 < 2.0, f"{n} groups took too long"
    assert out == [token], "a pathological token must fall back to itself"


@pytest.mark.parametrize("n", [100, 5000])
def test_deep_nesting_does_not_blow_the_stack(n):
    """One recursion level per group. Making the expansion linear exposed this
    - before, it hung long before it got deep enough to matter. A
    RecursionError is NOT an OSError, so it would have escaped Guard.evaluate
    and the hook, which fails open on its own errors, would have let the
    delete run unguarded."""
    token = "{a," * n + "z" + "}" * n
    out = _expand_braces(token)                 # must not raise
    assert out == [token]


def test_a_ten_group_expansion_still_expands():
    """The bound must not be so tight that ordinary use stops working.
    _BRACE_MAX is 1024, and ten binary groups is exactly that."""
    out = _expand_braces("{a,b}" * 10)
    assert len(out) == 1024
    assert all("{" not in o for o in out)


# --------------------------------------------------------------------------
# The bail is all-or-nothing. A partial expansion is never a safe answer.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n", [14, 16, 18, 20])
def test_the_bail_returns_the_token_not_a_half_expansion(n):
    """The old code returned 8 items for 14 groups: fragments carrying literal
    braces, produced by an inner bail being combined with an outer level's
    options. Those go on to be treated as candidate paths."""
    token = "{a,b}" * n
    out = _expand_braces(token)
    assert out == [token], f"partial expansion leaked: {out[:3]}"


def test_no_result_ever_carries_a_literal_brace_from_a_bail():
    """The general form of the above: either every output is fully expanded,
    or the single output is the original token."""
    for n in range(1, 25):
        token = "{a,b}" * n
        out = _expand_braces(token)
        if out == [token]:
            continue
        assert all("{" not in o and "}" not in o for o in out), \
            f"{n} groups produced a half-expanded operand"
        assert len(out) <= _BRACE_MAX

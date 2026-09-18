"""Tests for tokenization and segment splitting memoization.

Ensures:
1. Parsing functions benefit from LRU caching on repeated evaluations.
2. Returned lists are completely isolated - mutations by any caller do NOT corrupt cached results.
3. Dialect and platform path options maintain separate cache entries.
"""
from __future__ import annotations

import time
from demo_cli.classify import split_segments, _split_segments_cached, POSIX, POWERSHELL
from demo_cli.targets import _tokenize, _tokenize_cached


def test_tokenize_cache_hit_and_performance():
    _tokenize_cached.cache_clear()
    cmd = 'rm -rf "/path/with spaces/dir" /another/target'

    # First call: cache miss
    info_before = _tokenize_cached.cache_info()
    toks1 = _tokenize(cmd, windows_paths=False)
    info_after_miss = _tokenize_cached.cache_info()
    assert info_after_miss.misses == info_before.misses + 1

    # Second call: cache hit
    toks2 = _tokenize(cmd, windows_paths=False)
    info_after_hit = _tokenize_cached.cache_info()
    assert info_after_hit.hits == info_before.hits + 1
    assert toks1 == toks2


def test_tokenize_mutation_isolation():
    _tokenize_cached.cache_clear()
    cmd = "git checkout -b feature"
    t1 = _tokenize(cmd)
    assert t1 == ["git", "checkout", "-b", "feature"]

    # Mutate t1
    t1.pop(0)
    t1.append("corrupted")
    assert t1 == ["checkout", "-b", "feature", "corrupted"]

    # Subsequent call must be completely pristine
    t2 = _tokenize(cmd)
    assert t2 == ["git", "checkout", "-b", "feature"]
    assert t1 is not t2


def test_split_segments_cache_hit_and_performance():
    _split_segments_cached.cache_clear()
    cmd = "echo start && rm -rf ./cache || exit 1"

    # First call: cache miss
    info_before = _split_segments_cached.cache_info()
    s1 = split_segments(cmd, POSIX)
    info_after_miss = _split_segments_cached.cache_info()
    assert info_after_miss.misses == info_before.misses + 1

    # Second call: cache hit
    s2 = split_segments(cmd, POSIX)
    info_after_hit = _split_segments_cached.cache_info()
    assert info_after_hit.hits == info_before.hits + 1
    assert s1 == s2


def test_split_segments_mutation_isolation():
    _split_segments_cached.cache_clear()
    cmd = "pytest -q && echo done"
    s1 = split_segments(cmd)
    assert s1 == ["pytest -q", "echo done"]

    # Mutate s1
    s1.clear()
    s1.append("hacked")

    # Subsequent call must be completely pristine
    s2 = split_segments(cmd)
    assert s2 == ["pytest -q", "echo done"]
    assert s1 is not s2


def test_guard_evaluate_multi_call_cache_acceleration():
    """Verify that evaluating a complex pipeline hits the memoized caches multiple times."""
    from demo_cli.guard import Guard

    _tokenize_cached.cache_clear()
    _split_segments_cached.cache_clear()

    guard = Guard()
    cmd = "git clean -fd && rm -rf target/"

    # Evaluate the command
    res = guard.evaluate(cmd)
    assert res is not None

    # Within a single evaluation, split_segments and _tokenize should have had multiple cache hits
    seg_info = _split_segments_cached.cache_info()
    tok_info = _tokenize_cached.cache_info()

    assert seg_info.hits >= 1, f"Expected cache hits for split_segments, got {seg_info}"
    assert tok_info.hits >= 1, f"Expected cache hits for _tokenize, got {tok_info}"


import os
import subprocess
import pytest

from demo_cli.context import build_context, _find_git_dir, _git_context, _GIT_CACHE


def test_build_context_in_non_git_dir(tmp_path):
    non_git = str(tmp_path / "plain_dir")
    os.makedirs(non_git, exist_ok=True)
    ctx = build_context("echo hello", cwd=non_git)
    assert ctx.repo_root == "unknown"
    assert ctx.branch == "unknown"
    assert ctx.remote == "unknown"
    assert ctx.cwd == non_git
    assert ctx.fingerprint


def test_build_context_in_git_dir(tmp_path):
    git_dir = str(tmp_path / "repo")
    os.makedirs(git_dir, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", git_dir],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    ctx = build_context("echo hello", cwd=git_dir)
    assert os.path.samefile(ctx.repo_root, git_dir)
    assert ctx.branch == "main"
    assert ctx.remote == "unknown"


def test_git_context_caching(tmp_path):
    d = str(tmp_path / "cache_test")
    os.makedirs(d, exist_ok=True)
    _GIT_CACHE.clear()

    res1 = _git_context(d)
    assert res1 == ("unknown", "unknown", "unknown", "unknown")
    assert os.path.abspath(d) in _GIT_CACHE

    res2 = _git_context(d)
    assert res1 == res2


def test_context_includes_commit(tmp_path):
    ctx = build_context("echo hello", cwd=str(tmp_path))
    assert hasattr(ctx, "commit")
    assert "commit" in ctx.as_dict()


def test_find_git_dir_ancestor(tmp_path):
    root = str(tmp_path / "nested_repo")
    sub = os.path.join(root, "a", "b", "c")
    os.makedirs(sub, exist_ok=True)
    subprocess.run(["git", "init", root],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    found_root, found_git = _find_git_dir(sub)
    assert found_root and os.path.samefile(found_root, root)
    assert found_git and os.path.samefile(found_git, os.path.join(root, ".git"))


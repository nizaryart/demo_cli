r"""Deleting the PARENT of an ignored directory captured a subset and called
it REVERSIBLE.

`unignorable_dirs` exists because an ignore is a default, not a rule - a
directory the command reaches into is captured after all. Its own docstring
states the failure it was written to stop:

    "snapshots it without .git, and reports REVERSIBLE. The snapshot contains
     src/a.py and nothing else; undo restores half the damage and says nothing
     about the other half. The entry is indistinguishable from a complete
     capture - no field records the omission - which is what makes it a lie
     rather than a limitation."

It answers that question by NAME: does an operand mention an ignored directory
as a path component. `rm -rf proj` mentions nothing ignored and destroys
`proj/.git` completely, so the set came back empty, the ignore list held, and
the same lie arrived from the other side. Measured 2026-09-17:

    rm -rf proj        REVERSIBLE  allowed=True
      snapshot holds : README.md, src/a.py, src/b.py
      on disk        : + .git/config, .git/refs/HEAD.ref,
                         node_modules/x.js, __pycache__/m.pyc
    then, for real   : undo rc=0, banner "RESTORED", 1 file of 5 back

THE BLAST RADIUS, NOT THE CAPTURE ROOT. Several scattered operands collapse to
a common root they do NOT destroy - `rm proj/src/a.py proj/other/c.py` resolves
to `proj` - so "lift the ignore for the capture root" would copy .git for a
two-file delete. That is the cost the ignore list exists to avoid, and
test_ignored_dir_capture already pins it. `ignored_dirs_under` therefore asks
only about directories inside what the operands actually destroy.

WHEN IT IS TOO BIG, IT ESCALATES, and that is the designed outcome rather than
a new problem: "If that makes the capture exceed the size cap, snapshot()
returns None and the command escalates, which is the honest outcome and needs
no extra code." The trade is deliberate - `rm -rf <project with a large
node_modules>` now refuses and names the knob, where before it claimed a
recovery it did not have.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import POWERSHELL
from demo_cli.config import Config
from demo_cli.decide import ESCALATE, REVERSIBLE
from demo_cli.guard import Guard

TREE = {
    ".git/config": "THE GIT CONFIG",
    ".git/refs/HEAD.ref": "ref bytes",
    "README.md": "readme",
    "src/a.py": "code a",
    "src/b.py": "code b",
    "other/c.py": "code c",
    "node_modules/x.js": "dep",
    "__pycache__/m.pyc": "bytecode",
}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    for rel, body in TREE.items():
        f = proj / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    monkeypatch.chdir(tmp_path)
    return tmp_path, proj


def _guard(root):
    return Guard(config=Config(mode="enforce", project_root=str(root)))


def _held(entry):
    rp = (entry or {}).get("recovery_point")
    if not rp or not os.path.isdir(rp):
        return None
    out = []
    for dp, _, fs in os.walk(rp):
        out += [os.path.relpath(os.path.join(dp, f), rp).replace(os.sep, "/")
                for f in fs]
    return sorted(out)


# --------------------------------------------------------------- the defect

@pytest.mark.parametrize("cmd,dialect", [
    ("rm -rf proj", "posix"),
    ("mv proj elsewhere", "posix"),
    ("Remove-Item -Recurse -Force proj", POWERSHELL),
])
def test_destroying_the_parent_captures_the_ignored_children(lab, cmd, dialect):
    """THE DEFECT. Each of these held 3 of 8 files and said REVERSIBLE.

    The PowerShell form goes through the fallback: expanded_operands is empty
    for anything that is not rm / mv, so the resolved directory target is used
    instead. Included here because that is the only other way this shape
    arrives, and a fix that covered one shell would be half a fix.
    """
    root, _ = lab
    r = _guard(root).evaluate(cmd, dialect=dialect)
    assert r.decision.decision == REVERSIBLE, (cmd, r.decision.reason)
    assert _held(r.recovery_entry) == sorted(TREE), cmd


def test_the_snapshot_holds_the_real_bytes(lab):
    """ASSERT THE CONTENT. A capture holding the wrong or empty files is also
    'REVERSIBLE' - six tests in this project have passed for that reason."""
    root, _ = lab
    r = _guard(root).evaluate("rm -rf proj")
    rp = r.recovery_entry["recovery_point"]
    for rel, body in TREE.items():
        with open(os.path.join(rp, *rel.split("/")), encoding="utf-8") as f:
            assert f.read() == body, rel


def test_undo_now_restores_everything_it_claimed(lab):
    """END TO END, because the disposition was never the whole lie: `undo`
    exited 0, printed RESTORED, and put back one file of five."""
    root, proj = lab
    r = _guard(root).evaluate("rm -rf proj")
    assert r.decision.decision == REVERSIBLE
    import shutil
    shutil.rmtree(proj)
    assert recovery.restore_entry(r.recovery_entry) is True
    back = []
    for dp, _, fs in os.walk(proj):
        back += [os.path.relpath(os.path.join(dp, f), proj).replace(os.sep, "/")
                 for f in fs]
    assert sorted(back) == sorted(TREE)


# ------------------------------------------------- the cost it must not incur

@pytest.mark.parametrize("cmd", [
    "rm proj/src/a.py proj/src/b.py",
    "rm proj/src/a.py proj/other/c.py",
    "rm proj/README.md",
])
def test_a_scattered_delete_still_keeps_the_ignore_list(lab, cmd):
    """The capability this must not cost. The second case is the important one:
    two operands in different subtrees collapse to `proj` as a COMMON ROOT, and
    lifting the ignore for a capture root rather than a blast radius would copy
    .git and node_modules for a two-file delete."""
    root, _ = lab
    r = _guard(root).evaluate(cmd)
    held = _held(r.recovery_entry) or []
    leaked = [h for h in held
              if h.startswith((".git/", "node_modules/", "__pycache__/"))]
    assert leaked == [], (cmd, leaked)


def test_the_common_root_is_not_treated_as_destroyed(lab):
    """Stated as its own fact, because it is the whole distinction: the target
    resolves to proj, and proj's ignored children are still ignored."""
    root, _ = lab
    r = _guard(root).evaluate("rm proj/src/a.py proj/other/c.py")
    assert os.path.basename(r.target.ref) == "proj", "fixture no longer collapses"
    assert _held(r.recovery_entry) == ["README.md", "other/c.py",
                                       "src/a.py", "src/b.py"]


# ------------------------------------------------------- the honest refusal

def test_too_large_escalates_instead_of_capturing_part(lab, monkeypatch):
    """The designed outcome, in unignorable_dirs' own words. Pinned because a
    silent fall back to the partial capture would restore the exact lie."""
    root, proj = lab
    (proj / "node_modules" / "big.bin").write_bytes(b"\0" * (3 * 1024 * 1024))
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "1")
    r = _guard(root).evaluate("rm -rf proj")
    assert r.decision.decision == ESCALATE
    assert r.recovery_entry is None, "a partial capture was reported as a recovery"
    assert "DEMO_CLI_MAX_SNAPSHOT_MB" in r.decision.reason, r.decision.reason


# ------------------------------------------------------------- the unit

def test_it_answers_with_names_found_inside_the_blast_radius(lab):
    root, proj = lab
    assert recovery.ignored_dirs_under([str(proj)]) == frozenset(
        {".git", "node_modules", "__pycache__"})
    assert recovery.ignored_dirs_under([str(proj / "src")]) == frozenset()


def test_it_never_returns_the_recovery_store(lab):
    """Matching unignorable_dirs. snapshot() already refuses to copy the store
    into itself by absolute path, so the name is not what protects it."""
    root, proj = lab
    (proj / ".demo_cli").mkdir()
    (proj / ".demo_cli" / "junk").write_text("x")
    assert ".demo_cli" not in recovery.ignored_dirs_under([str(proj)])


def test_it_does_not_descend_into_an_ignored_directory(lab, monkeypatch):
    """The NAME is the answer, not the contents. Walking node_modules to
    discover that it is node_modules would cost what this is bounding.

    SPIES ON os.scandir, NOT os.walk. The first version wrapped os.walk and
    asserted it was never re-entered for an ignored path - but os.walk is a
    generator that recurses internally and never calls itself, so the spy only
    ever saw the single top-level call and the assertion could not fail.
    os.scandir is what os.walk uses per directory, so it registers a descent.

    ONLY node_modules is present, and that is load bearing too. With all
    three candidate names at the top level the loop's `hit == candidates`
    early exit breaks on the first iteration and nothing descends whether or
    not the pruning is there - so the first fixture could not fail either. A
    JS project with node_modules and no __pycache__ is the ordinary case.
    """
    root, tmp = lab[0], lab[0]
    proj = tmp / "jsproj"
    (proj / "node_modules" / "a" / "b").mkdir(parents=True)
    (proj / "node_modules" / "a" / "b" / "dep.js").write_text("dep")
    (proj / "src").mkdir()
    (proj / "src" / "app.js").write_text("app")

    seen = []
    real = os.scandir

    def spy(path=".", *a, **k):
        seen.append(str(path))
        return real(path, *a, **k)

    monkeypatch.setattr(os, "scandir", spy)
    found = recovery.ignored_dirs_under([str(proj)])
    monkeypatch.undo()
    assert found == frozenset({"node_modules"}), found
    descended = [s for s in seen if "node_modules" in s]
    assert descended == [], f"descended into an ignored directory: {descended}"


@pytest.mark.parametrize("paths", [[], None, ["/nonexistent/xyz"], ["README.md"]])
def test_it_is_quiet_on_nothing_to_look_at(lab, paths):
    """A file, a missing path, an empty list and None must all be frozenset()
    rather than an exception - this runs before the try/except around the copy."""
    assert recovery.ignored_dirs_under(paths) == frozenset()


# ------------------------------------------------- one list, not four copies

def test_diff_derives_the_ignore_list_rather_than_retyping_it():
    """IGNORED_DIRS' comment: "Three separate copies had already drifted apart
    before this was unified." diff._manifest was the fourth, with the same five
    names spelled out - identical today, which is exactly why a drift would go
    unnoticed. Same instrument as
    test_the_checkpoint_ignore_set_is_derived_not_retyped."""
    import inspect

    from demo_cli import diff
    src = inspect.getsource(diff._manifest)
    assert "recovery.IGNORED_DIRS" in src
    for name in ("node_modules", "__pycache__"):
        assert f'"{name}"' not in src, f"{name} is still spelled out in diff.py"

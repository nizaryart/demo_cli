r"""The rule promised to snapshot a path, and never found one.

    _FILE_WRITERS' own comment: "They rarely look destructive, but they rewrite
    the working tree - snapshot the path first so the change is visible and
    reversible."

Measured 2026-09-17 in a real project with node_modules and a package.json,
enforce mode. 18 of 18:

    ESCALATE  rule=None  captured=False  npm install
    ESCALATE  rule=None  captured=False  pip install -r requirements.txt
    ESCALATE  rule=None  captured=False  prettier --write src/app.js
    ESCALATE  rule=None  captured=False  black app.py
    ESCALATE  rule=None  captured=False  eslint --fix .

No target ever resolved, so decide step 6 fail-closed on every one. In enforce
mode an agent could not run a formatter or install a dependency. TWELFTH
comment in this project stating a rule the code does not implement.
`npm update` is in test_sql_verb_is_not_sql's BENIGN list; `npm install` is
not, so nothing was looking.

THE MACHINERY WAS ALREADY THERE, AND ONE LINE WAS THE GATE. Nizar asked
whether something already understood paths before any of this was designed.
It did, and generically:

    _path_operands('prettier --write src/app.js') -> ['prettier', 'src/app.js']
    _path_operands('gofmt -w app.py')             -> ['gofmt', 'app.py']

Tokenising, brace and glob expansion, ~ expansion, cd-base resolution, quote
stripping, existence filtering AND FLAG SKIPPING were all present - `--write`
and `-w` were skipped for free. What stopped it was

    if i < len(toks) and toks[i] in ("rm", "mv"):

a hardcoded two-element tuple, so every other verb stayed in the operand list
as a phantom path and `black app.py` counted TWO operands, collapsing to a
common root instead of naming the file. _MATCHERS - the (does this act?, what
is its target?) table - simply had no row. _rm's handler is reused unchanged,
because one-operand-or-common-root is already a formatter's semantics.

THE FINDING SPLITS IN THREE, AND ONLY ONE PART IS ABOUT PATHS:

  * writers POINTED AT a path      -> fixed here
  * `black .` / `black src/ tests/` -> collapse to the project root, which
    guard.py refuses as a capture surface on purpose. Still escalate, and
    that is pinned below as a deliberate limit rather than left to be
    rediscovered as a bug.
  * `npm install` / `pip install`  -> no path in the text, ever. Nizar's
    call: KEEP THE ESCALATION. Fail-closed is honest - nothing captured,
    nothing claimed - and `checkpoint` stays the opt-in way to cover them.

AND A CHECK IS NOT A WRITE. Once the extractor learned these verbs,
`black --check app.py` came back REVERSIBLE with a real snapshot of a file
that was never going to change. black/isort/rustfmt write by default and stop
on --check/--diff; gofmt is the reverse and needs -w. The rule now says so, so
the same command is a read at both layers.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.classify import (FILE_WRITER_TARGET_VERBS, classify_pipeline,
                               is_file_writer_command)
from demo_cli.config import Config
from demo_cli.decide import ALLOW, ESCALATE, REVERSIBLE
from demo_cli.guard import Guard

ORIGINAL = "the bytes that existed before the formatter ran\n"

# (command, the path it must capture)
WRITES = [
    ("black app.py", "app.py"),
    ("isort app.py", "app.py"),
    ("rustfmt app.py", "app.py"),
    ("gofmt -w app.py", "app.py"),
    ("prettier --write src/app.js", "src/app.js"),
    ("eslint --fix src/app.js", "src/app.js"),
    ("sudo black app.py", "app.py"),
    ("X=1 black app.py", "app.py"),
]

# Read-only forms. Neither escalation nor snapshot is acceptable.
READS = [
    "black --check app.py", "black --diff app.py",
    "isort --check-only app.py", "isort --check app.py",
    "rustfmt --check app.py",
    "gofmt app.py", "gofmt -l app.py",
    "prettier src/app.js", "eslint src/app.js",
]


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    for p in ("app.py", "src/app.js", "src/util.js", "tests/t.js", "package.json"):
        (tmp_path / p).write_text(ORIGINAL)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _guard(root):
    return Guard(config=Config(mode="enforce", project_root=str(root)))


# ------------------------------------------------------------- it captures now

@pytest.mark.parametrize("cmd,path", WRITES)
def test_a_writer_pointed_at_a_file_snapshots_it(project, cmd, path):
    """THE DEFECT: every one of these was ESCALATE with captured=False."""
    r = _guard(project).evaluate(cmd)
    assert r.decision.decision == REVERSIBLE, (cmd, r.decision.reason)
    assert r.recovery_entry is not None, cmd
    assert os.path.abspath(r.target.ref) == str(project / path), (
        f"{cmd}: captured {r.target.ref}, wanted {path}")


@pytest.mark.parametrize("cmd,path", WRITES)
def test_the_snapshot_holds_the_real_bytes(project, cmd, path):
    """ASSERT THE CONTENT, NOT THE DISPOSITION. test_hook_cwd's lesson: a
    recovery point holding the wrong file is also 'REVERSIBLE'."""
    r = _guard(project).evaluate(cmd)
    with open(r.recovery_entry["recovery_point"], encoding="utf-8") as f:
        assert f.read() == ORIGINAL, cmd


def test_a_directory_target_is_captured_whole(project):
    r = _guard(project).evaluate("prettier --write src/")
    assert r.decision.decision == REVERSIBLE
    assert os.path.abspath(r.target.ref) == str(project / "src")
    snap = r.recovery_entry["recovery_point"]
    assert sorted(os.listdir(snap)) == ["app.js", "util.js"]


# ------------------------------------------------------- reads stay reads

@pytest.mark.parametrize("cmd", READS)
def test_a_check_is_neither_blocked_nor_snapshotted(project, cmd):
    r = _guard(project).evaluate(cmd)
    assert r.decision.decision == ALLOW, (cmd, r.decision.reason)
    assert r.recovery_entry is None, (
        f"{cmd}: snapshotted a file it was never going to change")


@pytest.mark.parametrize("cmd", READS)
def test_the_classifier_agrees_a_check_is_a_read(cmd):
    """Both layers must say the same thing about the same command, or the
    extractor looks for a path in text the classifier never flagged."""
    assert is_file_writer_command(cmd) is False, cmd
    assert classify_pipeline(cmd).is_file_writer is False, cmd


# --------------------------------------------- the limits, pinned deliberately

@pytest.mark.parametrize("cmd", ["black .", "prettier --write .",
                                 "black src/ tests/", "eslint --fix ."])
def test_a_whole_project_target_still_escalates(project, cmd):
    """NOT A BUG. These collapse to the project root, which guard.py refuses as
    a capture surface ("a two-file change would copy the whole tree"). Pinned
    so the partialness of this fix is a recorded decision, not a discovery."""
    r = _guard(project).evaluate(cmd)
    assert r.decision.decision == ESCALATE, (cmd, r.decision.decision)
    assert r.recovery_entry is None, cmd


@pytest.mark.parametrize("cmd", ["npm install", "npm install lodash", "npm i",
                                 "npm add lodash", "yarn add react",
                                 "pnpm install", "pip install requests",
                                 "pip install -r requirements.txt"])
def test_the_no_path_writers_keep_escalating(project, cmd):
    """NIZAR'S CALL, 2026-09-17. There is no path in the text, so nothing can
    be extracted and fail-closed is the honest answer: nothing is captured and
    nothing is claimed. `checkpoint` remains the opt-in way to cover these.
    Pinned so it reads as a decision rather than an oversight."""
    r = _guard(project).evaluate(cmd)
    assert r.decision.decision == ESCALATE, (cmd, r.decision.decision)
    assert r.recovery_entry is None, cmd


def test_a_wrapped_binary_is_a_stated_miss(project):
    """Only a BARE verb is recognised. Recorded because a silent miss that
    nobody wrote down is how the `bash -lc` gap survived to 09-16."""
    r = _guard(project).evaluate("./node_modules/.bin/prettier --write src/app.js")
    assert r.recovery_entry is None
    assert r.decision.decision == ESCALATE


# ------------------------------------------------- multiplicity is still honest

def test_two_acting_segments_refuse_a_partial_snapshot(project):
    """The writer row must be counted in `acting`, or `rm a && black b` would
    snapshot one and claim a recovery while the other was rewritten - the
    partial-recovery lie FIX #5 exists to prevent."""
    r = _guard(project).evaluate("rm app.py && prettier --write src/app.js")
    assert r.decision.decision == ESCALATE
    assert r.recovery_entry is None


def test_a_read_beside_a_delete_does_not_steal_the_snapshot(project):
    """The mirror: a read must NOT count as acting, or adding these verbs would
    have turned working snapshots into escalations."""
    r = _guard(project).evaluate("rm app.py && prettier src/app.js")
    assert r.decision.decision == REVERSIBLE
    assert os.path.abspath(r.target.ref) == str(project / "app.py")


# ------------------------------------------------------------ the shared gate

@pytest.mark.parametrize("verb,writing_form", [
    ("prettier", "prettier --write x.js"),
    ("eslint", "eslint --fix x.js"),
    ("black", "black x.py"),
    ("isort", "isort x.py"),
    ("gofmt", "gofmt -w x.go"),
    ("rustfmt", "rustfmt x.rs"),
])
def test_every_target_verb_is_one_the_classifier_flags(verb, writing_form):
    """THE ANTI-DRIFT PIN. FILE_WRITER_TARGET_VERBS must be a SUBSET of what
    the classifier calls a writer. If a verb is added here but not there, the
    extractor resolves a target for a command that was never marked mutating -
    so nothing is captured and the target is silently unused."""
    assert verb in FILE_WRITER_TARGET_VERBS
    assert is_file_writer_command(writing_form) is True, writing_form


def test_the_command_word_is_dropped_before_looking_for_paths(project):
    """The one line that was the gate, pinned at unit level. Before the fix
    this returned ['black', 'app.py'] - two operands for a one-file command."""
    assert recovery._path_operands("black app.py", None) == ["app.py"]
    assert recovery._path_operands("prettier --write src/app.js", None) == ["src/app.js"]
    # rm / mv must be untouched by the widening.
    assert recovery._path_operands("rm app.py", None) == ["app.py"]


def test_an_unknown_verb_still_keeps_its_command_word(project):
    """The widening is a list, not "drop the first token always" - a tool we
    have not reasoned about must not have its name silently read as a path."""
    assert recovery._path_operands("sometool app.py", None) == ["sometool", "app.py"]

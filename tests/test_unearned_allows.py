r"""Container, keystore and registry destruction: 18 of 19 forms measured ALLOW.

ALLOW is the bottom of this project's ladder - nothing was captured, so nothing
was claimed - but it is still a command that destroys data the tool never
mentions. Measured end to end through Guard.evaluate on 2026-09-17:

    ALLOW   redis-cli FLUSHALL / FLUSHDB / -h host FLUSHALL
    ALLOW   docker volume rm | volume prune | system prune [-af] | image prune
    ALLOW   docker rm x | docker rmi -f x | docker container prune
    ALLOW   docker compose down -v
    ALLOW   npm unpublish mypkg@1.0.0

AND THE ONE THAT WAS CAUGHT WAS CAUGHT BY ACCIDENT. `docker rm -f` matched
`rm_rf` - `\brm\b` plus lookaheads for an r-flag and an f-flag - so it escalated
under a rule that believes it is a local recursive delete, while `docker rm`
without -f was ALLOW. rm_local, the rule directly below, excludes `docker rm`
deliberately and says so in twelve lines of comment; rm_rf never did, because it
is unanchored on purpose.

    THE ONLY DOCKER COMMAND THE TOOL STOPPED WAS STOPPED UNDER THE WRONG NAME,
    AND WOULD HAVE GONE SILENT THE DAY ANYONE ANCHORED rm_rf.

Same shape as 09-16, where `git branch --delete --force`, `curl -X DELETE` and
`kubectl delete pod` reached ESCALATE only through the SQL word-list accident.

SURFACES, NOT PLAIN DESTRUCTIVE RULES, and that makes them MORE overridable
rather than less: decide.py step 3 honours a structural approval token and step
6 never checks one. A legitimate `docker volume rm` has no path otherwise. The
same inversion as the service and account rules.

ANCHORED, WHICH IS THE WHOLE REASON THEY ARE SAFE. The ORDINARY corpus below is
half this file, because an unanchored `\bdocker\s+rm\b` escalates
`git commit -m 'docker rm cleanup script'` and an unanchored `\bnpm\s+unpublish\b`
escalates `rg 'npm unpublish' docs/`. That is the SQL-verb-is-an-English-word
bug, which cost 21 of 61 ordinary commands on 09-14. The two corpora are
asserted together on purpose: a rule table is only as good as what it releases.
"""
import pytest

from demo_cli import approval
from demo_cli.classify import classify_pipeline
from demo_cli.config import Config
from demo_cli.decide import ALLOW, ESCALATE, _RECOVERY_HINTS
from demo_cli.guard import Guard

# (command, expected surface). Every one of these was ALLOW before 2026-09-17,
# except `docker rm -f`, which was ESCALATE under the name rm_rf.
DESTRUCTIVE = [
    ("redis-cli FLUSHALL", "datastore_flush"),
    ("redis-cli flushall", "datastore_flush"),
    ("redis-cli FLUSHDB", "datastore_flush"),
    ("redis-cli -h 10.0.0.5 -p 6379 FLUSHALL", "datastore_flush"),
    ("redis-cli --cluster call x FLUSHALL", "datastore_flush"),
    ("docker volume rm myvol", "container_runtime"),
    ("docker volume prune -f", "container_runtime"),
    ("docker system prune", "container_runtime"),
    ("docker system prune -af", "container_runtime"),
    ("docker system prune -af --volumes", "container_runtime"),
    ("docker image prune -a", "container_runtime"),
    ("docker container prune -f", "container_runtime"),
    ("docker builder prune -af", "container_runtime"),
    ("docker network prune -f", "container_runtime"),
    ("docker rm mycontainer", "container_runtime"),
    ("docker rm -f mycontainer", "container_runtime"),
    ("docker rm $(docker ps -aq)", "container_runtime"),
    ("docker rmi -f myimage", "container_runtime"),
    ("docker compose down -v", "container_runtime"),
    ("docker compose down --volumes", "container_runtime"),
    ("docker-compose down --volumes", "container_runtime"),
    ("podman rm c", "container_runtime"),
    ("podman volume rm v", "container_runtime"),
    ("sudo docker volume rm v", "container_runtime"),
    ("npm unpublish mypkg@1.0.0", "package_registry"),
    ("npm unpublish --force mypkg", "package_registry"),
    ("pnpm unpublish mypkg", "package_registry"),
    ("yarn unpublish mypkg", "package_registry"),
    ("cargo yank --version 1.0.0", "package_registry"),
    ("gem yank mygem -v 1.0.0", "package_registry"),
]

# Not one of these may escalate. The prose entries are the anchor's whole job.
ORDINARY = [
    "docker ps", "docker ps -a", "docker build -t app .", "docker run --rm app",
    "docker compose up -d", "docker compose down", "docker logs -f app",
    "docker exec -it app sh", "docker images", "docker inspect app",
    "docker pull node:20", "docker volume ls", "docker system df",
    "docker stats", "docker tag a b", "docker push myrepo/app",
    "redis-cli ping", "redis-cli GET mykey", "redis-cli INFO",
    "redis-cli --scan --pattern 'user:*'", "redis-cli CONFIG GET maxmemory",
    "redis-cli LLEN queue",
    "npm publish", "npm run build", "npm test", "npm ci", "npm view mypkg",
    "npm deprecate mypkg@1.0.0 'use v2'",
    "cargo build", "cargo test", "gem install rails",
    # Prose. Each of these escalates against an unanchored version of the rule.
    "grep -rn 'FLUSHALL' src/",
    "echo 'docker rm is destructive' >> notes.md",
    "git commit -m 'docker rm cleanup script'",
    "git commit -m 'npm unpublish notes'",
    "git commit -m 'document cargo yank'",
    "cat docker-compose.yml",
    "rg 'npm unpublish' docs/",
    "man docker-rm",
]


@pytest.fixture
def guard(tmp_path):
    return Guard(config=Config(mode="enforce", project_root=str(tmp_path)))


# ------------------------------------------------------------- it stops them

@pytest.mark.parametrize("cmd,surface", DESTRUCTIVE)
def test_it_no_longer_walks_past(guard, cmd, surface):
    r = guard.evaluate(cmd)
    assert r.decision.decision == ESCALATE, (cmd, r.decision.decision)
    assert r.classification.nonrecoverable_surface == surface, cmd
    assert r.decision.surface == surface, cmd
    assert r.recovery_entry is None, (
        f"{cmd}: nothing local could cover this, so nothing may be captured")


@pytest.mark.parametrize("cmd,surface", DESTRUCTIVE)
def test_the_receipt_records_the_surface(guard, cmd, surface):
    """Asserted on the receipt FIELD, not on rendered text."""
    assert guard.evaluate(cmd).receipt.nonrecoverable_surface == surface, cmd


# ------------------------------------------------------- and releases the rest

@pytest.mark.parametrize("cmd", ORDINARY)
def test_ordinary_work_is_untouched(guard, cmd):
    r = guard.evaluate(cmd)
    assert r.decision.decision == ALLOW, (cmd, r.decision.decision)
    assert r.classification.nonrecoverable_surface is None, cmd


def test_the_prose_cases_are_the_point(guard):
    """Kept as its own named test so a future edit cannot quietly drop them
    from the list above and still look green."""
    for cmd in ["git commit -m 'docker rm cleanup script'",
                "rg 'npm unpublish' docs/",
                "grep -rn 'FLUSHALL' src/"]:
        assert guard.evaluate(cmd).decision.decision == ALLOW, cmd


# --------------------------------------------------- the accident, by its name

def test_docker_rm_f_is_no_longer_wearing_rm_rf(guard):
    """It escalated before, under a rule that thought it was a local delete."""
    c = classify_pipeline("docker rm -f mycontainer")
    assert c.matched_rule != "rm_rf", "still reporting the accident's name"
    assert c.nonrecoverable_surface == "container_runtime"


@pytest.mark.parametrize("cmd,rule", [
    ("rm -rf build", "rm_rf"),
    ("sudo rm -rf out", "rm_rf"),
    ("X=1 rm -rf tmp", "rm_rf"),
    ("cd build && rm -rf ./out", "rm_rf"),
    ("rm -f app.db", "rm_local"),
    ("rm app.db", "rm_local"),
])
def test_the_docker_exclusion_did_not_touch_real_rm(cmd, rule):
    """The lookbehind is on the most load-bearing regex in the table, so what
    it must NOT change is pinned as tightly as what it must."""
    assert classify_pipeline(cmd).matched_rule == rule, cmd


def test_excluding_docker_from_rm_rf_cannot_silently_allow_it(guard):
    """The exclusion is only safe BECAUSE container_runtime covers it. If that
    rule is ever removed, this fails instead of going quiet - which is what
    the 09-16 'load bearing accident' lesson asks for."""
    r = guard.evaluate("docker rm -f x")
    assert r.decision.decision == ESCALATE
    assert r.allowed is False


# ------------------------------------------------------------- the honest exit

@pytest.mark.parametrize("surface", ["container_runtime", "datastore_flush",
                                     "package_registry"])
def test_every_new_surface_says_where_to_restore_from(surface):
    assert surface in _RECOVERY_HINTS, surface
    assert _RECOVERY_HINTS[surface].strip(), surface


@pytest.mark.parametrize("cmd", ["docker volume rm v", "redis-cli FLUSHALL",
                                 "npm unpublish p@1.0.0"])
def test_the_escalation_names_the_restore_route(guard, cmd):
    r = guard.evaluate(cmd)
    hint = _RECOVERY_HINTS[r.decision.surface]
    assert hint in " ".join(r.decision.next_steps), (cmd, r.decision.next_steps)


def test_a_surface_is_overridable_and_a_plain_rule_is_not(tmp_path, monkeypatch):
    """WHY THESE ARE SURFACES. decide step 3 honours an approval token; step 6
    never checks one. Marking them surfaces is what gives a legitimate
    `docker volume rm` any path at all - it makes them more overridable, not
    less, which inverts the obvious reading."""
    monkeypatch.setenv("DEMO_CLI_APPROVER_KEY", "k" * 32)
    cfg = Config(mode="enforce", project_root=str(tmp_path),
                 approval_key_env="DEMO_CLI_APPROVER_KEY")
    g = Guard(config=cfg)
    cmd = "docker volume rm myvol"

    assert g.evaluate(cmd).decision.decision == ESCALATE
    token = approval.sign(cmd, "k" * 32)
    approved = g.evaluate(cmd, approval_token=token)
    assert approved.decision.decision == ALLOW, approved.decision.reason
    assert approved.decision.surface == "container_runtime"
    assert approved.decision.recoverable is False, (
        "an approval authorises the action; it does not make it recoverable")

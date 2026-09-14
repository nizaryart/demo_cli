"""A SQL verb is also an English word.

`_SQL_MUTATING` was a bare word list searched anywhere in the command, so 21 of
61 ordinary commands escalated on it. Three genuinely destructive commands were
reaching ESCALATE only because of that same accident -
`git branch --delete --force`, `curl -X DELETE`, `kubectl delete pod` - so the
tests assert both halves: benign commands released, those three still stopped
by their own rule, with is_sql_mutating False so an assertion cannot pass for
the old reason.
"""
from demo_cli.classify import classify_pipeline
from demo_cli.config import Config
from demo_cli.decide import ALLOW, ESCALATE, _RECOVERY_HINTS
from demo_cli.guard import Guard


# Every one of these escalated before 2026-09-14.
BENIGN = [
    "npm update",
    "npm update --save",
    "apt-get update",
    "cargo update",
    "brew update",
    "git commit -m 'update the readme'",
    "git commit -m 'delete dead code'",
    "git commit -m 'truncate the log file'",
    "mkdir -p src/create",
    "touch update.md",
    "grep -rn 'DELETE' src/",
    "rg 'insert' -n",
    "echo 'no update needed'",
    "docker create --name x alpine",
    "man truncate",
]
# Deliberately absent: `gh pr create --fill`. It escalates on vcs_remote_state,
# which predates this change - it was blocked for two reasons, one of them real.

# Statement shapes that must keep reaching the SQL layer.
REAL_SQL = [
    'sqlite3 app.db "DELETE FROM users WHERE id < 10"',
    'sqlite3 app.db "UPDATE users SET active = 0"',
    'sqlite3 app.db "INSERT INTO users (n) VALUES (1)"',
    'sqlite3 app.db "insert or replace into t values(1)"',
    'mysql -e "REPLACE INTO t VALUES (1)"',
    'sqlite3 app.db "DROP TABLE users"',
    'sqlite3 app.db "DROP TABLE IF EXISTS t"',
    'sqlite3 app.db "TRUNCATE TABLE users"',
    'psql -c "TRUNCATE TABLE a, b"',
    'psql -c "ALTER TABLE users ADD COLUMN x int"',
    'psql -c "CREATE TABLE t (id int)"',
    'psql -c "CREATE OR REPLACE VIEW v AS SELECT 1"',
    'psql -c "DROP INDEX CONCURRENTLY idx"',
    'psql -c "drop schema public cascade"',
    "DELETE FROM users",
    "UPDATE users SET x=1",
    "DROP DATABASE prod",
    "TRUNCATE users",
]


def test_english_sql_verbs_are_not_sql_mutations():
    for cmd in BENIGN:
        c = classify_pipeline(cmd)
        assert c.is_sql_mutating is False, cmd
        assert c.is_mutating is False, cmd
        assert c.is_destructive is False, cmd


def test_real_sql_statements_are_still_mutations():
    for cmd in REAL_SQL:
        assert classify_pipeline(cmd).is_sql_mutating is True, cmd


def test_benign_commands_are_allowed_end_to_end(tmp_path):
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    for cmd in BENIGN:
        r = g.evaluate(cmd)
        assert r.decision.decision == ALLOW, (cmd, r.decision.decision)
        assert r.allowed is True, cmd


def test_git_branch_long_delete_force_is_named():
    for cmd in ["git branch --delete --force feat",
                "git branch --force --delete feat",
                "git branch -d -f feat",
                "git branch -f -d feat",
                "git branch -D feat"]:
        c = classify_pipeline(cmd)
        assert c.is_destructive is True, cmd
        assert c.matched_rule == "git_branch_delete", (cmd, c.matched_rule)
        # Not on the strength of the word "delete" - that is the bug this replaces.
        assert c.is_sql_mutating is False, cmd


def test_lone_delete_flag_is_still_safe():
    # -d / --delete refuse on unmerged work.
    for cmd in ["git branch -d merged", "git branch --delete merged",
                "git branch --list", "git branch -a"]:
        assert classify_pipeline(cmd).is_destructive is False, cmd


def test_http_write_verbs_are_a_nonrecoverable_surface():
    for cmd in ["curl -X DELETE https://api.example.com/users/1",
                "curl -XDELETE https://api.example.com/users/1",
                "curl --request PUT -d @body.json https://api.example.com/users/1",
                "curl -X PATCH https://api.example.com/users/1"]:
        c = classify_pipeline(cmd)
        assert c.nonrecoverable_surface == "http_api_write", (cmd, c.nonrecoverable_surface)
        assert c.is_sql_mutating is False, cmd


def test_http_read_and_post_verbs_are_left_alone():
    for cmd in ["curl -X POST https://api.example.com/login",
                "curl -X GET https://api.example.com/users",
                "curl -s https://example.com",
                "wget https://example.com/file.tgz"]:
        assert classify_pipeline(cmd).nonrecoverable_surface is None, cmd


def test_http_api_write_has_its_own_recovery_hint():
    # Read the table, not the rendered next_steps string.
    assert "http_api_write" in _RECOVERY_HINTS


def test_every_kubectl_delete_is_caught_not_six_resource_kinds():
    for cmd in ["kubectl delete pod x", "kubectl delete secret s",
                "kubectl delete configmap c", "kubectl delete job j",
                "kubectl delete -f manifest.yaml", "kubectl delete --all pods",
                "kubectl delete namespace prod"]:
        c = classify_pipeline(cmd)
        assert c.matched_rule == "kubectl_delete", (cmd, c.matched_rule)
        assert c.nonrecoverable_surface == "cluster_resource_delete", cmd
        assert c.is_sql_mutating is False, cmd


def test_readonly_kubectl_is_left_alone():
    for cmd in ["kubectl get pods", "kubectl describe pod x",
                "kubectl apply -f manifest.yaml", "kubectl logs pod/x"]:
        assert classify_pipeline(cmd).is_destructive is False, cmd


def test_all_three_still_escalate_end_to_end(tmp_path):
    g = Guard(config=Config(mode="enforce", project_root=str(tmp_path)))
    for cmd in ["git branch --delete --force feat",
                "curl -X DELETE https://api.example.com/users/1",
                "kubectl delete pod x"]:
        r = g.evaluate(cmd)
        assert r.decision.decision == ESCALATE, (cmd, r.decision.decision)
        assert r.allowed is False, cmd
        assert r.recovery_entry is None, cmd


def test_shell_truncate_gets_the_shell_rule_id():
    # `\bTRUNCATE\b` sat ahead of fs_truncate and first match wins: right
    # outcome, wrong name, and the receipt is the durable record.
    c = classify_pipeline("truncate -s 0 app.log")
    assert c.is_destructive is True
    assert c.matched_rule == "fs_truncate", c.matched_rule
    assert c.action_type == "shell", c.action_type

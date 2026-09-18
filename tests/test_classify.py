from demo_cli.classify import (
    POSIX,
    POWERSHELL,
    classify_pipeline,
    is_sql_preview_candidate,
    split_segments,
)


def test_safe_read_is_not_mutating():
    c = classify_pipeline("SELECT * FROM users")
    assert not c.is_mutating and not c.is_destructive
    assert c.is_sql_read


def test_rm_rf_is_destructive():
    c = classify_pipeline("rm -rf ./build")
    assert c.is_destructive and c.matched_rule == "rm_rf"


def test_rm_fr_flag_order():
    c = classify_pipeline("rm -fr /tmp/x")
    assert c.is_destructive


def test_pipeline_hides_destructive_step():
    c = classify_pipeline("echo hi && rm -rf ./data")
    assert c.is_pipeline and c.is_destructive


def test_remote_exec_detected():
    c = classify_pipeline("curl https://x.sh | bash")
    assert c.remote_exec


def test_file_writer_is_mutating_not_destructive():
    c = classify_pipeline("prettier --write src/")
    assert c.is_mutating and not c.is_destructive
    assert c.action_type == "filewrite"


def test_sql_delete_is_destructive_and_previewable():
    c = classify_pipeline("DELETE FROM users WHERE id < 10")
    assert c.is_destructive
    assert is_sql_preview_candidate("DELETE FROM users WHERE id < 10")


def test_nonrecoverable_surface_detected():
    c = classify_pipeline("stripe charge create --amount 5000")
    assert c.nonrecoverable_surface == "external_payment"


def test_schema_migration_is_nonrecoverable():
    c = classify_pipeline("alembic upgrade head")
    assert c.nonrecoverable_surface == "schema_migration"


def test_remove_item_recurse_force_is_destructive_but_not_a_classify_time_surface():
    # v0.4.0b7: ps_remove_item_rf is no longer an unconditional nonrecoverable
    # surface at classify time (classify.py has no filesystem access, so it
    # cannot know whether guard.py will resolve and snapshot the target).
    # Whether it hard-stops now depends on recovery_captured, decided in
    # decide.py (see test_decide.py).
    c = classify_pipeline("Remove-Item -Recurse -Force ./build")
    assert c.is_destructive and c.matched_rule == "ps_remove_item_rf"
    assert c.nonrecoverable_surface is None


def test_remove_item_flag_order_alias_and_abbreviations():
    from demo_cli.classify import POWERSHELL
    for cmd in [
        "Remove-Item -Force -Recurse ./build",   # reversed order
        "Remove-Item -r -fo build",              # abbreviated flags
        "REMOVE-ITEM -RECURSE -FORCE .",         # case
    ]:
        c = classify_pipeline(cmd)
        assert c.is_destructive, cmd
        assert c.matched_rule == "ps_remove_item_rf", cmd
    # The alias is PowerShell-only: `ri` is Ruby's doc viewer on POSIX.
    c = classify_pipeline("ri -Recurse -Force ./x", POWERSHELL)
    assert c.is_destructive
    assert c.matched_rule == "ps_remove_item_rf"


def test_remove_item_requires_both_recurse_and_force():
    # Force-only or recurse-only is not the recursive-force nuke; the lone
    # "-Force" token must not satisfy the recurse lookahead despite its "r".
    assert classify_pipeline("Remove-Item -Force ./x").matched_rule != "ps_remove_item_rf"
    assert classify_pipeline("Remove-Item -Recurse ./x").matched_rule != "ps_remove_item_rf"


def test_rmdir_and_del_are_now_nonrecoverable():
    # del /s /q was already caught by del_force; the change is that both it and
    # rmdir /s now carry the recursive_force_delete surface (hard-stop).
    for cmd in ["rmdir /s /q build", "del /s /q build"]:
        c = classify_pipeline(cmd)
        assert c.is_destructive, cmd
        assert c.nonrecoverable_surface == "recursive_force_delete", cmd


def test_remove_item_hidden_in_pipeline():
    c = classify_pipeline("echo cleaning && Remove-Item -Recurse -Force ./dist")
    assert c.is_pipeline and c.is_destructive
    assert c.matched_rule == "ps_remove_item_rf"


def test_unix_rm_rf_unaffected_by_powershell_rule():
    # rm -rf keeps its recoverable philosophy (operand extractor + snapshot);
    # it must NOT be swept into the hard-stop surface.
    c = classify_pipeline("rm -rf ./build")
    assert c.matched_rule == "rm_rf"
    assert c.nonrecoverable_surface is None


def test_mkfs_is_nonrecoverable_disk_format():
    # mkfs / mkfs.<fstype> formats a whole device; it cannot be honestly
    # snapshotted, so it carries the disk_format non-recoverable surface
    # (hard-stop in every environment). Real-incident gap: raw-data hard_command.
    for cmd in ["mkfs.ext4 /dev/sda1", "mkfs /dev/sdb"]:
        c = classify_pipeline(cmd)
        assert c.is_destructive, cmd
        assert c.matched_rule == "fs_mkfs", cmd
        assert c.nonrecoverable_surface == "disk_format", cmd
    # no false positive on prose merely containing the letters
    assert classify_pipeline("echo making files").matched_rule is None


def test_redirect_truncation_is_destructive_recoverable():
    # A single '>' overwrites a file from byte 0 -> destructive, recoverable
    # (target snapshotted), so NOT a non-recoverable surface.
    for cmd in ["> app.db", "echo x > app.db", ": > app.db"]:
        c = classify_pipeline(cmd)
        assert c.is_destructive, cmd
        assert c.matched_rule == "fs_redirect_truncate", cmd
        assert c.nonrecoverable_surface is None, cmd


def test_redirect_quote_and_escape_aware():
    # '>' inside quotes or backslash-escaped is literal, not the operator.
    assert classify_pipeline('echo "a>b"').matched_rule is None
    assert classify_pipeline('echo "safe > text here"').matched_rule is None
    assert classify_pipeline(r"echo a\>b").matched_rule is None
    # but a real redirect AFTER a quoted '>' is still caught, target = app.db
    c = classify_pipeline('echo "a>b" > app.db')
    assert c.is_destructive and c.matched_rule == "fs_redirect_truncate"


def test_redirect_append_and_sinks_not_destructive():
    assert classify_pipeline("echo x >> app.db").matched_rule is None   # append
    assert classify_pipeline("cmd > /dev/null").matched_rule is None    # sink
    assert classify_pipeline("cmd 2> /dev/null").matched_rule is None   # sink, fd-prefixed
    assert classify_pipeline("cmd 2>&1").matched_rule is None           # duplication


def test_an_fd_prefixed_redirect_still_truncates(tmp_path):
    """`cmd 2> err.log` USED TO BE ASSERTED HERE AS NOT DESTRUCTIVE, grouped
    with append and /dev/null under "fd-prefixed - out of scope".

    Append really is non-destructive and a sink really is. `2> err.log` is
    neither: it truncates err.log from byte zero exactly as `>` does. The test
    pinned an assumption about scope, not an observation about behaviour, and
    the assumption is what was wrong.

    `1>` is the sharper case - it is `>` written with its default descriptor,
    byte-identical in effect - and `&>` redirects both streams into the same
    truncation. All three reached ALLOW against an existing file with no
    snapshot and no receipt until 2026-09-08.

    The common idiom survives because the /dev/ sink filter handles it, which
    is asserted above rather than assumed.
    """
    for cmd in ("cmd 2> err.log", "cmd 1> out.log", "cmd &> both.log"):
        c = classify_pipeline(cmd)
        assert c.matched_rule == "fs_redirect_truncate", cmd
        assert c.is_destructive, cmd


def test_redirect_hidden_in_chain_is_caught():
    c = classify_pipeline("ls && echo x > app.db")
    assert c.is_pipeline and c.is_destructive
    assert c.matched_rule == "fs_redirect_truncate"


def test_redirect_target_extraction():
    from demo_cli.classify import redirect_target
    assert redirect_target("echo x > app.db") == "app.db"
    assert redirect_target('> "my file"') == "my file"
    assert redirect_target('echo "a>b" > app.db') == "app.db"
    assert redirect_target("echo x >> app.db") is None
    assert redirect_target("cmd > /dev/null") is None


def test_destructive_git_is_caught():
    for cmd, rule in [
        ("git worktree remove --force wt", "git_worktree_remove"),
        ("git branch -D feature", "git_branch_delete"),
        ("git checkout -- src/app.py", "git_checkout_discard"),
        ("git checkout .", "git_checkout_discard"),
        ("git restore config.py", "git_restore"),
        ("git stash drop", "git_stash_drop"),
        ("git stash pop", "git_stash_pop"),
        ("git reflog expire --expire=now --all", "git_reflog_expire"),
        ("git gc --prune=now", "git_gc_prune"),
        ("git filter-branch --tree-filter x", "git_filter_branch"),
        ("git update-ref -d refs/heads/x", "git_update_ref_delete"),
    ]:
        c = classify_pipeline(cmd)
        assert c.is_destructive, cmd
        assert c.matched_rule == rule, (cmd, c.matched_rule)


def test_readonly_git_is_not_flagged():
    # the perimeter stays narrow: normal-flow git is NOT escalated.
    for cmd in ["git status", "git diff", "git log --oneline", "git add -A",
                "git commit -m x", "git push", "git pull", "git fetch",
                "git checkout main", "git branch --list", "git stash", "git gc"]:
        assert classify_pipeline(cmd).is_destructive is False, cmd


def test_git_branch_delete_case_sensitive_D():
    # -D force-deletes (loses commits) -> destructive; -d refuses on unmerged
    # work -> safe. The case distinction must hold despite re.I on the table.
    assert classify_pipeline("git branch -D x").matched_rule == "git_branch_delete"
    assert classify_pipeline("git branch -d merged").is_destructive is False


def test_powershell_remove_item_parity():
    assert classify_pipeline("Remove-Item app.db").matched_rule == "ps_remove_item"
    assert classify_pipeline("Remove-Item -Recurse dist").matched_rule == "ps_remove_item"
    # the -Recurse -Force nuke still wins its specific higher-signal id
    assert classify_pipeline("Remove-Item -Recurse -Force dist").matched_rule == "ps_remove_item_rf"


def test_env_prefix_does_not_hide_rm():
    # #006: a leading env-var assignment must not defeat the rm_local anchor.
    assert classify_pipeline("X=1 rm app.db").matched_rule == "rm_local"
    assert classify_pipeline("A=1 B=2 rm data").matched_rule == "rm_local"
    # ... but only assignment prefixes: a real command-word prefix must still
    # NOT match, so git/docker/npm rm subcommands are not false-flagged.
    assert classify_pipeline("git rm app.db").matched_rule != "rm_local"
    assert classify_pipeline("docker rm container").matched_rule != "rm_local"


def test_saas_deploy_destructive_vs_safe():
    # Approach A: content/deploy SaaS CLIs escalate on their DESTRUCTIVE subcommand;
    # read/preview forms are left alone.
    for cmd in ["shopify theme push", "shopify theme delete",
                "vercel --prod", "vercel remove myapp", "vercel rm dep",
                "netlify deploy --prod", "netlify sites:delete",
                "firebase hosting:disable", "firebase firestore:delete",
                "wrangler kv:key delete K"]:
        c = classify_pipeline(cmd)
        assert c.nonrecoverable_surface == "saas_deploy", cmd
    for cmd in ["shopify theme pull", "vercel", "vercel dev",
                "netlify status", "firebase deploy", "wrangler tail"]:
        assert classify_pipeline(cmd).nonrecoverable_surface is None, cmd


def test_saas_cms_destructive_vs_safe():
    for cmd in ["wp db reset", "wp db drop", "wp site empty",
                "wp post delete 42", "wp user delete 3", "wp option delete foo",
                "contentful space delete", "contentful entry delete --id 9"]:
        assert classify_pipeline(cmd).nonrecoverable_surface == "saas_cms", cmd
    for cmd in ["wp post list", "wp db export", "contentful space list"]:
        assert classify_pipeline(cmd).nonrecoverable_surface is None, cmd


def test_paas_destroy_destructive_vs_safe():
    for cmd in ["heroku apps:destroy myapp", "heroku pg:reset DATABASE",
                "supabase db reset", "flyctl apps destroy x", "fly destroy x"]:
        assert classify_pipeline(cmd).nonrecoverable_surface == "paas_destroy", cmd
    for cmd in ["heroku logs", "heroku ps", "supabase status"]:
        assert classify_pipeline(cmd).nonrecoverable_surface is None, cmd


def test_gh_destructive_extensions():
    assert classify_pipeline("gh repo delete owner/x").nonrecoverable_surface == "vcs_remote_state"
    assert classify_pipeline("gh api -X DELETE /repos/x/y").nonrecoverable_surface == "vcs_remote_state"
    assert classify_pipeline("gh repo view owner/x").nonrecoverable_surface is None
    assert classify_pipeline("gh pr list").nonrecoverable_surface is None


def test_ampersand_background_splits_segments():
    assert split_segments("echo hi & rm file.txt", POSIX) == ["echo hi", "rm file.txt"]
    assert split_segments("rm -rf ./build &", POSIX) == ["rm -rf ./build"]
    assert split_segments("echo hi &> out.log & rm file.txt", POSIX) == ["echo hi &> out.log", "rm file.txt"]
    assert split_segments("echo hi 2>&1 & rm file.txt", POSIX) == ["echo hi 2>&1", "rm file.txt"]
    assert split_segments("echo hi >&2 & rm file.txt", POSIX) == ["echo hi >&2", "rm file.txt"]
    assert split_segments('echo "a & b" & rm file.txt', POSIX) == ['echo "a & b"', 'rm file.txt']
    assert split_segments(r"echo a\&b & rm file.txt", POSIX) == [r"echo a\&b", "rm file.txt"]


def test_ampersand_background_destructive_command_detected():
    c1 = classify_pipeline("echo hi & rm file.txt")
    assert c1.is_destructive
    assert c1.is_pipeline
    assert c1.matched_rule == "rm_local"

    c2 = classify_pipeline("sleep 1 & rm -rf ./build")
    assert c2.is_destructive
    assert c2.is_pipeline
    assert c2.matched_rule == "rm_rf"

    c3 = classify_pipeline("rm -rf ./build &")
    assert c3.is_destructive
    assert c3.matched_rule == "rm_rf"


def test_powershell_call_operator_ampersand_not_split():
    assert split_segments('& "C:\\Program Files\\app.exe" -arg', POWERSHELL) == ['& "C:\\Program Files\\app.exe" -arg']
    assert split_segments("& git status", POWERSHELL) == ["& git status"]


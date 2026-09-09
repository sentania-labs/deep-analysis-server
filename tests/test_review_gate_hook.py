"""Tests for the pre-push review gate hook.

The hook (``.claude/hooks/check-review-passed.sh``) is a PreToolUse gate:
the harness feeds it the tool call as JSON on stdin, exit 0 allows the
command and exit 2 blocks it. Issue #160: the hook resolved HEAD from the
harness cwd, which is always the PRIMARY checkout, so a commit made in a
``git worktree`` could never satisfy it, and ``git -C <path>`` pushes
were not matched at all.

These tests drive the hook through the same stdin contract the harness
uses, against a real throwaway repo plus worktree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "check-review-passed.sh"

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("jq") is None,
    reason="the review gate hook is a bash script and needs bash + jq",
)

ALLOW = 0
BLOCK = 2
PUSH = "push"


def _git(*args: str, cwd: Path) -> str:
    out = subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


@dataclass
class Fixture:
    """A primary checkout plus a linked worktree, each with its own HEAD."""

    primary: Path
    worktree: Path
    primary_head: str
    worktree_head: str

    def mark(self, tree: Path, sha: str) -> None:
        (tree / ".review-passed").write_text(sha + "\n")


@pytest.fixture
def repo(tmp_path: Path) -> Fixture:
    primary = tmp_path / "primary"
    primary.mkdir()
    _git("init", "-q", "-b", "main", ".", cwd=primary)
    _git("commit", "-q", "--allow-empty", "-m", "base", cwd=primary)
    worktree = tmp_path / "wt"
    _git("worktree", "add", "-q", "-b", "wtbranch", str(worktree), cwd=primary)
    _git("commit", "-q", "--allow-empty", "-m", "worktree work", cwd=worktree)
    return Fixture(
        primary=primary,
        worktree=worktree,
        primary_head=_git("rev-parse", "HEAD", cwd=primary),
        worktree_head=_git("rev-parse", "HEAD", cwd=worktree),
    )


def run_hook(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the hook exactly as the harness does: tool call JSON on stdin."""
    payload = json.dumps(
        {
            "session_id": "test",
            "cwd": str(cwd),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
    )
    return subprocess.run(["bash", str(HOOK)], input=payload, capture_output=True, text=True)


# --- worktree pushes: the harness cwd is always the primary checkout ---


def test_worktree_push_with_marker_is_allowed(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_worktree_push_without_marker_is_blocked(repo: Fixture) -> None:
    result = run_hook(f"git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK
    assert str(repo.worktree) in result.stderr


def test_cd_into_worktree_then_push_is_attributed_to_the_worktree(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"cd {repo.worktree} && git {PUSH} origin wtbranch", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_worktree_push_with_a_stale_marker_is_blocked(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.primary_head)
    result = run_hook(f"git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_flags_before_the_subcommand_are_still_matched(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    cmd = f"git -c core.pager=cat -C {repo.worktree} {PUSH} -u origin wtbranch"
    assert run_hook(cmd, cwd=repo.primary).returncode == ALLOW


def test_sticky_dash_c_form_is_matched(repo: Fixture) -> None:
    result = run_hook(f"git -C{repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


# --- primary checkout: no regression ---


def test_primary_push_with_marker_is_allowed(repo: Fixture) -> None:
    repo.mark(repo.primary, repo.primary_head)
    result = run_hook(f"git {PUSH}", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_primary_push_without_marker_is_blocked(repo: Fixture) -> None:
    assert run_hook(f"git {PUSH}", cwd=repo.primary).returncode == BLOCK


def test_marker_with_unresolvable_contents_is_blocked(repo: Fixture) -> None:
    (repo.primary / ".review-passed").write_text("not-a-sha\n")
    assert run_hook(f"git {PUSH}", cwd=repo.primary).returncode == BLOCK


# --- a marker in one tree must not satisfy a push from another ---


def test_worktree_marker_does_not_satisfy_a_primary_push(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    assert run_hook(f"git {PUSH}", cwd=repo.primary).returncode == BLOCK


def test_primary_marker_does_not_satisfy_a_worktree_push(repo: Fixture) -> None:
    repo.mark(repo.primary, repo.primary_head)
    result = run_hook(f"git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


# --- fail closed on anything undeterminable ---


def test_unresolvable_dash_c_path_is_blocked(repo: Fixture, tmp_path: Path) -> None:
    result = run_hook(f"git -C {tmp_path / 'nope'} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_unexpanded_variable_path_is_blocked(repo: Fixture) -> None:
    assert run_hook(f"git -C $WT {PUSH}", cwd=repo.primary).returncode == BLOCK


def test_unexpanded_subcommand_is_blocked(repo: Fixture) -> None:
    assert run_hook(f"git $SUB {PUSH}", cwd=repo.primary).returncode == BLOCK


def test_push_through_a_shell_wrapper_is_blocked(repo: Fixture) -> None:
    assert run_hook(f"bash -c 'git {PUSH}'", cwd=repo.primary).returncode == BLOCK


def test_push_from_a_non_repo_cwd_is_blocked(repo: Fixture, tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    assert run_hook(f"git {PUSH}", cwd=plain).returncode == BLOCK


def test_push_chained_after_another_command_is_gated(repo: Fixture) -> None:
    assert run_hook(f"echo hi && git {PUSH}", cwd=repo.primary).returncode == BLOCK


def test_unparseable_hook_input_is_blocked() -> None:
    result = subprocess.run(
        ["bash", str(HOOK)], input="not json, push", capture_output=True, text=True
    )
    assert result.returncode == BLOCK


# --- everything that is not a push must still flow ---


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "git log --oneline",
        "git fetch origin",
        "echo pushing a change",
    ],
)
def test_non_push_commands_are_allowed(repo: Fixture, command: str) -> None:
    assert run_hook(command, cwd=repo.primary).returncode == ALLOW


def test_allowing_a_push_writes_an_audit_line(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    assert run_hook(f"git -C {repo.worktree} {PUSH}", cwd=repo.primary).returncode == ALLOW
    audit = (repo.worktree / ".claude" / ".review-audit.log").read_text()
    assert repo.worktree_head in audit


# --- aliases must not be an escape hatch ---


def test_alias_expanding_to_push_is_gated(repo: Fixture) -> None:
    _git("config", "alias.deploy", PUSH, cwd=repo.worktree)
    result = run_hook(f"git -C {repo.worktree} deploy", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_shell_out_alias_is_blocked(repo: Fixture) -> None:
    _git("config", "alias.deploy", f"!git {PUSH}", cwd=repo.worktree)
    result = run_hook(f"git -C {repo.worktree} deploy", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_chained_alias_reaching_push_is_gated(repo: Fixture) -> None:
    _git("config", "alias.inner", PUSH, cwd=repo.worktree)
    _git("config", "alias.outer", "inner", cwd=repo.worktree)
    result = run_hook(f"git -C {repo.worktree} outer", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_harmless_alias_is_still_allowed(repo: Fixture) -> None:
    _git("config", "alias.st", "status", cwd=repo.worktree)
    result = run_hook(f"git -C {repo.worktree} st", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_send_pack_is_treated_as_a_push(repo: Fixture) -> None:
    result = run_hook(f"git -C {repo.worktree} send-pack origin wtbranch", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_dash_form_git_push_binary_is_gated(repo: Fixture) -> None:
    result = run_hook(f"cd {repo.worktree} && git-{PUSH} origin wtbranch", cwd=repo.primary)
    assert result.returncode == BLOCK


# --- forms that previously slipped past the parser ---


def test_builtin_command_prefix_is_gated(repo: Fixture) -> None:
    """`command git push` runs a real push, so the builtin must be stepped over."""
    result = run_hook(f"cd {repo.worktree} && command git {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_builtin_exec_prefix_is_gated(repo: Fixture) -> None:
    result = run_hook(f"exec git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_builtin_prefix_with_a_marker_still_passes(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"command git -C {repo.worktree} {PUSH}", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_command_scoped_alias_is_resolved(repo: Fixture) -> None:
    """`git -c alias.deploy=push deploy` pushes, and -c beats stored config."""
    cmd = f"git -c alias.deploy={PUSH} -C {repo.worktree} deploy"
    assert run_hook(cmd, cwd=repo.primary).returncode == BLOCK


def test_cd_in_a_pipeline_stage_does_not_carry_over(repo: Fixture) -> None:
    """A `cd` inside a pipeline dies with its subshell, so the push is from cwd."""
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"cd {repo.worktree} | git {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK
    assert str(repo.primary) in result.stderr


def test_cd_after_a_pipeline_is_not_inherited(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"cd {repo.worktree} | true ; git {PUSH}", cwd=repo.primary)
    assert result.returncode == BLOCK


def test_alias_whose_arguments_mention_push_is_not_a_push(repo: Fixture) -> None:
    """`alias.find = log --grep push` is a log, not a push."""
    _git("config", "alias.find", f"log --grep {PUSH}", cwd=repo.worktree)
    result = run_hook(f"git -C {repo.worktree} find", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


# --- separator boundaries must not be forgeable from command text ---


def test_forged_separator_tag_cannot_move_the_pushing_tree(repo: Fixture) -> None:
    """A line of user text that mimics an internal tag must not reset the cwd."""
    repo.mark(repo.primary, repo.primary_head)
    command = f"cd {repo.worktree}\nPIPE@ noop\ngit {PUSH}"
    result = run_hook(command, cwd=repo.primary)
    assert result.returncode == BLOCK
    assert str(repo.worktree) in result.stderr


def test_forged_seq_tag_cannot_move_the_pushing_tree(repo: Fixture) -> None:
    repo.mark(repo.primary, repo.primary_head)
    command = f"SEQ@ noop\ncd {repo.worktree}\ngit {PUSH}"
    result = run_hook(command, cwd=repo.primary)
    assert result.returncode == BLOCK
    assert str(repo.worktree) in result.stderr


def test_newline_separated_cd_then_push_follows_the_cd(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"cd {repo.worktree}\ngit {PUSH}", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr


def test_double_pipe_is_a_sequential_separator_not_a_pipeline(repo: Fixture) -> None:
    repo.mark(repo.worktree, repo.worktree_head)
    result = run_hook(f"cd {repo.worktree} || true ; git {PUSH}", cwd=repo.primary)
    assert result.returncode == ALLOW, result.stderr

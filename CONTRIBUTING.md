# Contributing to Deep Analysis Server

The general contribution flow (feature branch, PR, green CI before merge) is in
[README.md](README.md#contributing), along with the local pre-push compose smoke
tests. This file covers the pre-push review gate, which is a local hook rather
than a CI job.

## Pre-push review gate

`.claude/hooks/check-review-passed.sh` runs as a PreToolUse hook on every Bash
command and blocks pushes that have not been reviewed. What it checks:

- It works out which directory the push actually runs from, following `cd`,
  `git -C <path>`, `--git-dir`, and `--work-tree`, rather than assuming the
  harness working directory. Work done in a `git worktree` is therefore gated
  against that worktree's HEAD, not the primary checkout's. Worktrees are the
  normal dispatch pattern in this workspace, so this is the common case, not an
  edge case.
- A `.review-passed` marker must exist at the root of the tree being pushed (or
  at the main worktree root) and must resolve, in that tree, to the commit being
  pushed. `/self-review` writes the HEAD SHA there after an approving review.
  Hand-writing the marker is a bypass, not a workflow.
- It fails closed on anything it recognizes as a push but cannot resolve:
  missing `jq`, unreadable hook input, an unresolvable path, a subcommand behind
  a variable, a push wrapped in `bash -c` or `ssh`, an opaque or shell-out git
  alias. All of those block.
- Aliases are followed by their effective subcommand, including one set inline
  with `-c alias.x=push`, and `git send-pack` and the dash-form `git-push`
  binary count as pushes. Builtin prefixes (`command`, `builtin`, `exec`) are
  stepped over rather than treated as opaque wrappers.
- Pipeline stages run in their own subshells, so a `cd` in one stage is not
  carried into the next.

### What it is not

The gate is a guard against pushing unreviewed work by accident, not an
adversarial boundary. It reads command text with a shell-shaped parser rather
than a shell, so forms it does not model slip through and are ALLOWED:

- `&` as a separator, subshells `( ... )`, brace groups, shell keywords
  (`if`/`for`), and a backslash-newline line continuation.
- A quoted path containing whitespace (`git -C '/tmp/my tree' push`), because
  tokenization is whitespace-based.
- A leading redirection (`2>/dev/null git push`) or a prefix command (`time`,
  `nice`, `stdbuf`).
- A `GIT_DIR=` / `GIT_WORK_TREE=` environment prefix, which can point the push
  at a different tree than the one whose marker was checked.
- `git send-pack` or an alias-to-push inside a wrapper, since the wrapper branch
  only blocks on the literal words `git` and `push`.
- An alias defined only in a repo selected by `--git-dir`, since alias lookup
  uses the current directory's config.

A marker that resolves to HEAD by name rather than by SHA (the literal text
`HEAD`, or a branch name) also satisfies the gate permanently.

Do not treat a green gate as proof that a reviewer saw the diff. These are
tracked in issue #164. Any fix has to land in all three Deep Analysis repos at
once, because they deliberately carry the identical hook file.

One practical consequence of failing closed: a command that merely *contains*
something that parses as a push, for example a heredoc writing a doc or test
that includes that text at the start of a line, is also blocked. Restructure the
command (write the file with a placeholder and substitute, or use a different
tool) rather than weakening the gate.

`tests/test_review_gate_hook.py` covers the gate, and CI runs it in the
`test-common` job. Run it after touching the hook:

```bash
uv run pytest tests/test_review_gate_hook.py
```

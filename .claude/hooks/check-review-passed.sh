#!/usr/bin/env bash
# Pre-push gate: blocks any git push unless a .review-passed marker
# exists whose SHA matches the HEAD of the tree the push is actually
# coming from.
#
# Design notes:
#
#   * The harness cwd (hook input `.cwd`) is always the PRIMARY checkout,
#     even when the command pushes from a `git worktree`. So the pushing
#     directory is derived from the command itself: leading `cd`/`pushd`
#     segments, `git -C <path>`, and `--git-dir` / `--work-tree`. HEAD and
#     the repo root are then resolved by running git against THAT
#     directory, so a worktree commit is compared against the worktree's
#     own HEAD.
#   * The marker is looked for at the pushing tree's root first, then at
#     the main worktree's root. Either way the marker SHA must equal the
#     pushing tree's HEAD, so a stale or hand-copied marker from another
#     tree cannot satisfy the gate.
#   * Fail closed. Anything we cannot resolve (missing dependency,
#     unparseable hook input, a push through a shell wrapper, an
#     unresolvable -C path, a git subcommand hidden behind a variable, an
#     opaque or shell-out git alias) BLOCKS. Silent permission is the
#     failure mode this gate exists to avoid.
#   * Aliases are followed by their effective subcommand, including
#     `-c alias.x=push` set on the command line, and `git send-pack` and
#     the dash-form binaries count as pushes. Builtin prefixes
#     (`command`, `builtin`, `exec`) are stepped over.
#   * Pipeline stages run in subshells, so a `cd` in one stage is not
#     carried into the next: `cd <dir> | git push` is attributed to the
#     original directory, not to <dir>.
#
# Known limitation: the gate compares against HEAD, so an explicit
# refspec that pushes some other ref (git push origin other:main) is
# reviewed against HEAD rather than against the ref being pushed.

set -uo pipefail

block() {
  printf 'Push blocked: %s\n' "$*" >&2
  exit 2
}

for dep in jq git; do
  command -v "$dep" >/dev/null 2>&1 || block "review-gate dependency '$dep' is missing, failing closed."
done

input="$(cat)" || block "review-gate could not read hook input, failing closed."

if ! cmd="$(jq -r '.tool_input.command // ""' <<<"$input" 2>/dev/null)"; then
  block "review-gate could not parse hook input JSON, failing closed."
fi

# No command means no push to gate (non-Bash tool, or empty input).
[[ -n "$cmd" ]] || exit 0

# Cheap pre-filter: a command that mentions neither git nor a push
# cannot be a push, so skip the parsing work. Anything that mentions
# either one gets parsed, because a push can hide behind an alias
# (`git deploy`) or a plumbing command (`git send-pack`) with the word
# `push` nowhere in sight.
grep -qwE -- 'git|push' <<<"$cmd" || exit 0

hook_cwd="$(jq -r '.cwd // ""' <<<"$input" 2>/dev/null)"
[[ -n "$hook_cwd" && -d "$hook_cwd" ]] || hook_cwd="$PWD"

# Strip one layer of surrounding quotes from a token.
unquote() {
  local s="$1"
  s="${s%\"}"; s="${s#\"}"
  s="${s%\'}"; s="${s#\'}"
  printf '%s' "$s"
}

# Resolve $2 against base dir $1 (absolute paths win).
resolve_dir() {
  local base="$1" path="$2"
  [[ "$path" == /* ]] || path="$base/$path"
  printf '%s' "$path"
}

# Verify one push invocation. Exits 2 (via block) if it is not allowed.
check_push() {
  local dir="$1" gitdir="$2" worktree="$3"

  [[ -d "$dir" ]] || block "cannot resolve the directory this push runs from ('$dir'), failing closed."

  local gitargs=(-C "$dir")
  [[ -n "$gitdir" ]] && gitargs+=("--git-dir=$(resolve_dir "$dir" "$gitdir")")
  [[ -n "$worktree" ]] && gitargs+=("--work-tree=$(resolve_dir "$dir" "$worktree")")

  local head
  head="$(git "${gitargs[@]}" rev-parse HEAD 2>/dev/null)" \
    || block "'$dir' is not a git repo (or has no HEAD), failing closed."

  local top
  top="$(git "${gitargs[@]}" rev-parse --show-toplevel 2>/dev/null)"
  if [[ -z "$top" ]]; then
    top="$(resolve_dir "$dir" "${worktree:-$dir}")"
  fi

  # Main worktree root: parent of the shared git dir.
  local common main_root=""
  common="$(git "${gitargs[@]}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"
  if [[ -n "$common" && "$common" == */.git ]]; then
    main_root="${common%/.git}"
  fi

  local candidates=("$top/.review-passed")
  if [[ -n "$main_root" && "$main_root" != "$top" ]]; then
    candidates+=("$main_root/.review-passed")
  fi

  local marker found=0 raw resolved
  for marker in "${candidates[@]}"; do
    [[ -f "$marker" ]] || continue
    found=1
    raw="$(tr -d '[:space:]' < "$marker")"
    [[ -n "$raw" ]] || continue
    resolved="$(git "${gitargs[@]}" rev-parse --verify --quiet "${raw}^{commit}" 2>/dev/null)" || continue
    if [[ "$resolved" == "$head" ]]; then
      mkdir -p "$top/.claude" 2>/dev/null
      printf '%s push-allowed sha=%s tree=%s marker=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$head" "$top" "$marker" \
        >> "$top/.claude/.review-audit.log" 2>/dev/null
      return 0
    fi
  done

  if (( found )); then
    block "review marker does not match the commit being pushed (tree=$top, HEAD=$head). Re-run /self-review in that tree."
  fi
  block "no .review-passed marker for the tree being pushed (tree=$top, HEAD=$head). Run /self-review there before pushing."
}

# Classify a git subcommand, following alias chains. Echoes one of:
#   push    the invocation pushes (or is an alias that mentions a push)
#   other   a normal non-push subcommand
#   opaque  we cannot tell, so the caller must block
# A shell-out alias (`!...`) is opaque by definition: its body is an
# arbitrary command line this parser does not see.
resolve_subcommand() {
  local dir="$1" sub="$2" depth=0 expansion first
  local cfgdir="$dir"
  [[ -d "$cfgdir" ]] || cfgdir="$PWD"

  while (( depth < 5 )); do
    case "$sub" in
      push|send-pack) printf 'push'; return 0 ;;
    esac

    # `git -c alias.x=... x` beats stored config, so check inline first.
    expansion=""
    local entry
    for entry in "${INLINE_CONFIG[@]:-}"; do
      [[ "$entry" == "alias.$sub="* ]] && expansion="${entry#alias.$sub=}"
    done
    if [[ -z "$expansion" ]]; then
      expansion="$(git -C "$cfgdir" config --get "alias.$sub" 2>/dev/null)"
    fi

    if [[ -z "$expansion" ]]; then
      printf 'other'
      return 0
    fi
    if [[ "$expansion" == '!'* ]]; then
      printf 'opaque'
      return 0
    fi

    # The alias's effective subcommand is its first non-option token, so
    # `alias.find = log --grep push` classifies as `log`, not as a push.
    local -a alias_toks
    read -ra alias_toks <<< "$expansion"
    first=""
    local j=0
    while (( j < ${#alias_toks[@]} )); do
      case "${alias_toks[$j]}" in
        -c|--namespace|--exec-path|--super-prefix|--config-env|-C|--git-dir|--work-tree)
          ((j++)) ;;
        -*) ;;
        *) first="${alias_toks[$j]}"; break ;;
      esac
      ((j++))
    done

    if [[ -z "$first" || "$first" == *'$'* || "$first" == *'`'* ]]; then
      printf 'opaque'
      return 0
    fi
    sub="$first"
    ((depth++))
  done

  printf 'opaque'
}

# Wrappers that can hide a git invocation from this parser.
is_wrapper() {
  case "$1" in
    bash|sh|zsh|dash|ksh|env|sudo|xargs|nohup|timeout|eval|ssh|doas|setsid|script|watch) return 0 ;;
    *) return 1 ;;
  esac
}

# Split the command line into segments, recording for each segment the
# separator that preceded it. The separator is kept OUT OF BAND in a
# parallel array rather than prepended to the segment text, so no input
# string can forge a boundary. SEQ covers `;` `&&` `||` and newlines;
# PIPE covers `|`, and the distinction matters because each stage of a
# pipeline runs in its own subshell, so `cd <dir> | git push` does NOT
# push from <dir>.
#
# Quoting is not fully parsed: a mis-split simply leaves us with an
# unresolvable directory, which blocks.
declare -a SEG_TEXT=() SEG_SEP=()

split_command() {
  local rest="$1" pending="SEQ" s prefix i best_i best_sep
  local -a seps=('&&' '||' ';' '|' $'\n')

  while :; do
    best_i=-1
    best_sep=""
    for s in "${seps[@]}"; do
      prefix="${rest%%"$s"*}"
      [[ "$prefix" == "$rest" ]] && continue
      i=${#prefix}
      # Equal offsets keep list order, so `||` wins over `|`.
      if (( best_i < 0 || i < best_i )); then
        best_i=$i
        best_sep="$s"
      fi
    done

    if (( best_i < 0 )); then
      SEG_TEXT+=("$rest")
      SEG_SEP+=("$pending")
      return 0
    fi

    SEG_TEXT+=("${rest:0:best_i}")
    SEG_SEP+=("$pending")
    if [[ "$best_sep" == "|" ]]; then
      pending="PIPE"
    else
      pending="SEQ"
    fi
    rest="${rest:$((best_i + ${#best_sep}))}"
  done
}

split_command "$cmd"

curdir="$hook_cwd"
declare -a INLINE_CONFIG=()
# The directory a pipeline starts from: a `cd` inside one stage dies
# with that stage's subshell.
pipeline_base="$hook_cwd"

for idx in "${!SEG_TEXT[@]}"; do
  seg="${SEG_TEXT[$idx]}"
  if [[ "${SEG_SEP[$idx]}" == "PIPE" ]]; then
    curdir="$pipeline_base"
  else
    pipeline_base="$curdir"
  fi

  read -ra toks <<< "$seg"
  (( ${#toks[@]} )) || continue

  i=0
  # Skip leading VAR=value assignments.
  while [[ ${i} -lt ${#toks[@]} && "${toks[$i]}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do
    ((i++))
  done
  [[ ${i} -lt ${#toks[@]} ]] || continue

  first="$(unquote "${toks[$i]}")"
  base="${first##*/}"

  # `command git push`, `builtin cd`, `exec git push`: these builtins
  # just prefix a real command, so step over them (and their own flags)
  # and classify what they actually run.
  while [[ "$base" == "command" || "$base" == "builtin" || "$base" == "exec" ]]; do
    ((i++))
    while [[ ${i} -lt ${#toks[@]} && "$(unquote "${toks[$i]}")" == -* ]]; do
      ((i++))
    done
    [[ ${i} -lt ${#toks[@]} ]] || break
    first="$(unquote "${toks[$i]}")"
    base="${first##*/}"
  done
  [[ ${i} -lt ${#toks[@]} ]] || continue

  if [[ "$base" == "cd" || "$base" == "pushd" ]]; then
    target="$(unquote "${toks[$((i+1))]:-}")"
    if [[ -z "$target" || "$target" == "~" ]]; then
      curdir="$HOME"
    else
      curdir="$(resolve_dir "$curdir" "$target")"
    fi
    continue
  fi

  if is_wrapper "$base"; then
    if grep -qw -- 'push' <<< "$seg" && grep -qw -- 'git' <<< "$seg"; then
      block "a git-push wrapped in '$base' cannot be verified by the review gate. Run git directly."
    fi
    continue
  fi

  # Dash-form plumbing binaries take no `-C`, so they push from curdir.
  if [[ "$base" == "git-push" || "$base" == "git-send-pack" ]]; then
    check_push "$curdir" "" ""
    continue
  fi

  [[ "$base" == "git" ]] || continue

  ((i++))
  gitdir=""; worktree=""; dir="$curdir"; sub=""
  INLINE_CONFIG=()
  while [[ ${i} -lt ${#toks[@]} ]]; do
    t="$(unquote "${toks[$i]}")"
    case "$t" in
      -C)
        ((i++))
        p="$(unquote "${toks[$i]:-}")"
        [[ -n "$p" ]] || block "'git -C' with no path, cannot resolve the pushing tree, failing closed."
        dir="$(resolve_dir "$dir" "$p")"
        ;;
      -C*) dir="$(resolve_dir "$dir" "${t#-C}")" ;;
      --git-dir=*) gitdir="${t#--git-dir=}" ;;
      --git-dir) ((i++)); gitdir="$(unquote "${toks[$i]:-}")" ;;
      --work-tree=*) worktree="${t#--work-tree=}" ;;
      --work-tree) ((i++)); worktree="$(unquote "${toks[$i]:-}")" ;;
      -c)
        ((i++))
        INLINE_CONFIG+=("$(unquote "${toks[$i]:-}")") ;;
      -c*)
        INLINE_CONFIG+=("${t#-c}") ;;
      --namespace|--exec-path|--super-prefix|--config-env)
        ((i++)) ;;
      -*|--*) ;;
      *) sub="$t"; break ;;
    esac
    ((i++))
  done

  # A subcommand behind a variable or command substitution is opaque.
  if [[ "$sub" == *'$'* || "$sub" == *'`'* ]]; then
    block "cannot determine the git subcommand in '$seg', failing closed."
  fi

  [[ -n "$sub" ]] || continue

  case "$(resolve_subcommand "$dir" "$sub")" in
    push)   check_push "$dir" "$gitdir" "$worktree" ;;
    opaque) block "cannot resolve what git subcommand '$sub' does (opaque alias), failing closed." ;;
    *)      continue ;;
  esac
done

exit 0

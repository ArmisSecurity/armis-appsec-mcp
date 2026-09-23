#!/usr/bin/env python3
"""Shared gate logic for all client hook adapters.

Extracted from pre_commit_scan.py so that Gemini, Codex, and Cursor adapters
can reuse the same detection and validation without duplicating code.
Each adapter handles its own stdin/stdout JSON format; this module provides
the client-agnostic decision logic.
"""

import os
import re
import sys
from typing import NamedTuple

_plugin_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _plugin_root_dir not in sys.path:
    sys.path.insert(0, _plugin_root_dir)

from hash_utils import (  # noqa: E402
    compute_staged_hash,
    merge_or_rebase_in_progress,
    resolve_repo_toplevel,
    resolve_scan_pass_path,
)

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class GateResult(NamedTuple):
    decision: str  # "allow" | "deny"
    system_message: str  # scan instruction (empty string if allow)


# ---------------------------------------------------------------------------
# Shipping command patterns
# ---------------------------------------------------------------------------
#
# A shipping subcommand (commit / push / pr create) can be preceded by shell
# noise that the old anchor set ((?:^|&&|\|\||;)) ignored, so it shipped
# unscanned code. Each fragment below closes one bypass class:
#
#   _CMD_SEP      — command separators: start, &&, ||, ;, &, |, newline, CR,
#                   or an opening paren (subshell / $( … ) command subst).
#   _CMD_WRAP     — command wrappers that exec their argument as a new command:
#                   sudo/command/exec/eval/builtin/nice/time/timeout/xargs/…
#                   git …  Each wrapper may carry options, including a
#                   separate-token value (`sudo -u root git …`, `nice -n 10 …`)
#                   and `timeout`'s leading duration positional (`timeout 5 …`,
#                   `timeout 5s …`).
#   _ENV_PREFIX   — env-assignment / `env` prefixes: FOO=bar git …, env git …
#                   The value may be single/double quoted so a space inside it
#                   (`GIT_COMMITTER_NAME="John Doe" git commit`) is consumed.
#                   `env` may itself carry flags, including a separate-token
#                   value (`env -i git …`, `env -u FOO git …`), matched with the
#                   same non-dash-value rule as _CMD_WRAP so the run stays linear.
#   _PATH_PREFIX  — a path prefix on the binary: /usr/bin/git, ./git
#   _GIT_GLOBAL_OPTS — git/gh global options before the subcommand: -C <dir>,
#                   -c k=v, --no-pager, --git-dir=…, gh --repo <slug>.  A flag
#                   may take a separate-token value, but that value is matched as
#                   NON-dash (`[^-\s]\S*`): this removes the parse ambiguity that
#                   let an all-dash run (`git -x -x … -x`) be partitioned in
#                   exponentially many ways (catastrophic backtracking / ReDoS —
#                   `check_gate` could blow past the hook's 10s timeout, and a
#                   timed-out gate fails open → unscanned commit). With non-dash
#                   values each token has exactly one parse, so matching is
#                   linear while real `-C /repo` / `--git-dir /d` still match.
# A leading `\` (escaped binary, suppresses alias expansion) and an opening
# quote (`eval 'git commit'`) are also tolerated right before the binary name.
# NOTE: this is a regex over shell text, which is fundamentally leaky — wrapper
# enumeration is itself a blocklist. The durable fix is a tokenizing parser or
# an unforgeable scan-pass token (HMAC), tracked as a deferred follow-up.
_CMD_SEP = r"(?:^|&&|\|\||[;&|\n\r(])"
# armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
_CMD_WRAP = (
    # armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
    r"(?:(?:sudo|command|exec|eval|builtin|nice|time|timeout|xargs|stdbuf|nohup|setsid|doas)"
    r"\s+(?:[0-9]+[smhd]?\s+)?(?:-\S+\s+(?:[^-\s]\S*\s+)?)*)*"
)
# armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
_ENV_PREFIX = (
    # armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
    r"(?:(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)"
    r"|env(?:\s+-\S+(?:\s+[^-\s]\S*)?)*)\s+)*"
)
# Stops at shell operators (never part of an unquoted path) so each scan ends at
# the next _CMD_SEP start — `\S*` here was quadratic on `$($($(…`.
_PATH_PREFIX = r"(?:[^\s;&|()<>]*/)?"
# armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
_GIT_GLOBAL_OPTS = (
    # armis:ignore cwe:400 reason: provably linear (non-dash values); see TestRegexComplexity
    r"(?:(?:--\S+\s+[^-\s]\S*|--\S+|-[A-Za-z]\s+[^-\s]\S*|-[A-Za-z]\S*)\s+)*"
)

_GIT_PREFIX = (
    rf"{_CMD_SEP}\s*{_CMD_WRAP}{_ENV_PREFIX}{_PATH_PREFIX}['\"]?\\?git\s+{_GIT_GLOBAL_OPTS}"
)
# gh gets the same global-options segment as git, so `gh --repo o/r pr create`
# (and `gh -R o/r pr create`) is gated, not just a bare `gh pr create`.
_GH_PREFIX = rf"{_CMD_SEP}\s*{_CMD_WRAP}{_ENV_PREFIX}{_PATH_PREFIX}['\"]?\\?gh\s+{_GIT_GLOBAL_OPTS}"

# `commit(?![-\w])` / `push(?![-\w])` exclude hyphenated plumbing subcommands
# (git commit-tree, commit-graph, push-cert) that are NOT shipping commands.
GIT_SHIPPING_PATTERNS = [
    re.compile(rf"{_GIT_PREFIX}commit(?![-\w])"),
    re.compile(rf"{_GIT_PREFIX}push(?![-\w])"),
    re.compile(rf"{_GH_PREFIX}pr\s+create(?![-\w])"),
]

_COMMIT_PATTERN = GIT_SHIPPING_PATTERNS[0]

_PUSH_PR_PATTERNS = [
    re.compile(rf"{_GIT_PREFIX}push(?![-\w])"),
    re.compile(rf"{_GH_PREFIX}pr\s+create(?![-\w])"),
]

# git subcommands that change the index (or HEAD + index). One of these in the
# same command line as a commit runs *after* the gate hashed the staged diff,
# so the commit would record content the scan never saw.
# armis:ignore cwe:400 reason: same linear prefix as the shipping patterns; see TestRegexComplexity
_INDEX_MUTATING_PATTERN = re.compile(
    rf"{_GIT_PREFIX}(?P<sub>add|stage|rm|mv|stash|checkout|switch|restore|reset|apply|am"
    r"|update-index|read-tree|merge|mergetool|pull|rebase|cherry-pick|revert|submodule)(?![-\w])"
)

# Env vars that point git at a different index / repo than the one the gate
# hashed (`GIT_INDEX_FILE=/tmp/idx git commit`, `export GIT_DIR=…`).
_INDEX_REDIRECT_ENV = re.compile(r"(?<![\w])GIT_(?:INDEX_FILE|DIR|WORK_TREE|COMMON_DIR)=")

_COMMIT_ALL_FLAG = re.compile(rf"{_GIT_PREFIX}commit(?![-\w]).*(?:\s-a\b|\s--all\b)")

# Matches both the current "armis-scan-pass" and the legacy ".scan-pass".
_SCAN_PASS_NAMES = r"(?:\.scan-pass|armis-scan-pass)"  # noqa: S105 — filenames, not a secret
# Anti-forgery: the scan-pass content is just
# SHA-256(git diff --cached), which an agent can compute with read-only
# commands the gate allows — so the file must be unforgeable via shell. We deny
# WRITE *contexts* that target the basename, not any mention of it. Denying mere
# mentions blocked legitimate commands that name the file (commit messages like
# `git commit -m "fix armis-scan-pass"`, plus grep/cat/rm/pytest — this repo's
# own history references it), and surfaced the wrong "forgery" message because
# check_gate runs this check first. Write contexts: a redirect target, a
# file-writing command (tee/cp/mv/dd/sed -i/install/ln/truncate/sponge/editors/
# interpreters), or assigning the path to a shell variable. This is a blocklist
# of write verbs (inherently leaky); the hash match plus protect_scan_pass.py's
# Write/Edit guard backstop forgery, and an unforgeable HMAC token is the
# durable follow-up.
#
# Arm 3 (variable assignment) is a SAME-COMMAND-LINE tripwire only: it catches
# `F=<scan-pass>; … > $F` when assignment and use share one command string, but
# a bare `> $F` whose assignment happened in a *separate* tool call slips through
# (the gate sees one command at a time and the name isn't visible). That residual
# vector is intentionally out of scope here — it is backstopped by the hash match
# and protect_scan_pass.py, and closed for good by the deferred HMAC token. Don't
# mistake arm 3 for a complete defense against variable laundering.
# armis:ignore cwe:400 reason: provably linear (bounded alternation); see TestRegexComplexity
_SP_WRITE_VERBS = (
    # armis:ignore cwe:400 reason: provably linear (bounded alternation); see TestRegexComplexity
    r"(?:tee|cp|mv|dd|install|ln|truncate|sed|ex|vi|vim|nano|emacs|sponge"
    r"|python[0-9.]*|perl|ruby|node|awk|gawk|mawk|php)"
)
# The name as a bounded token (path component, quoted arg, or assignment value).
_SP_TOKEN = rf"(?:^|[\s/'\"=(]){_SCAN_PASS_NAMES}\b"
# armis:ignore cwe:400 reason: provably linear (anchored); see TestRegexComplexity
_SCAN_PASS_WRITE_PATTERN = re.compile(
    # 1. redirect (truncate/append) targeting the file. `\d*` allows an fd prefix
    #    (`1>`), `\|?` allows bash's noclobber-override `>|` (and `1>|`) — both
    #    were missed by the older `>>?` form and let `echo h >| <pass>` forge.
    # armis:ignore cwe:400 reason: provably linear (anchored); see TestRegexComplexity
    rf"\d*>>?\|?\s*(?:[^\s;&|>]*?/)?{_SCAN_PASS_NAMES}\b"
    # 2. a write-capable command naming the file in its arguments
    rf"|\b{_SP_WRITE_VERBS}\b[^\n;&|]*{_SP_TOKEN}"
    # 3. assigning the file's path to a shell variable (laundering setup).
    #    Anchor the assignment start (`(?:^|[\s;&|(])`) so `\w*` cannot begin at
    #    every interior word-char — an unanchored `[A-Za-z_]\w*=` backtracks
    #    quadratically on a long word-char token (a benign 60K-char arg blew the
    #    hook's 10s timeout); anchoring keeps it linear with identical matches.
    rf"|(?:^|[\s;&|(])[A-Za-z_]\w*=(?:[^\s;&|]*?/)?{_SCAN_PASS_NAMES}\b"
)


# ---------------------------------------------------------------------------
# Detection helpers (public for backward compat with existing tests)
# ---------------------------------------------------------------------------


def _is_shipping_command(cmd: str) -> bool:
    """Check if the command matches any git shipping pattern."""
    return any(p.search(cmd) for p in GIT_SHIPPING_PATTERNS)


def _is_commit(cmd: str) -> bool:
    """Check if the command contains a git commit."""
    return bool(_COMMIT_PATTERN.search(cmd))


def _is_push_or_pr(cmd: str) -> bool:
    """Check if the command is a git push or gh pr create."""
    return any(p.search(cmd) for p in _PUSH_PR_PATTERNS)


def _has_all_flag(cmd: str) -> bool:
    """Check if git commit has -a or --all flag."""
    return bool(_COMMIT_ALL_FLAG.search(cmd))


def _is_scan_pass_write_bash(cmd: str) -> bool:
    """Check if a Bash command attempts to write to .scan-pass."""
    return bool(_SCAN_PASS_WRITE_PATTERN.search(cmd))


def is_scan_pass_file(file_path: str) -> bool:
    """Check if a file path targets the scan-pass file (for Write/Edit guard).

    Matches both the current "armis-scan-pass" and the legacy ".scan-pass".
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return False
    return os.path.basename(file_path) in ("armis-scan-pass", ".scan-pass")


# ---------------------------------------------------------------------------
# Scan pass validation
# ---------------------------------------------------------------------------
#
# The gate (reader) MUST locate the scan-pass with the exact same logic as the
# scanner (writer). Both call hash_utils.resolve_scan_pass_path(), which uses
# `git rev-parse --absolute-git-dir`. A previous version resolved the path here
# with a private filesystem walker using os.path.isdir(".git"); inside a git
# worktree (every Conductor workspace) `.git` is a *file*, so that walker
# silently disagreed with the writer's os.path.exists check and the gate denied
# forever. Delegating to git removes that whole class of bug.


def _has_matching_scan_pass() -> bool:
    """Check if the scan-pass hash matches current staged changes."""
    scan_pass_path = resolve_scan_pass_path()
    try:
        if not os.path.isfile(scan_pass_path):
            return False
        with open(scan_pass_path) as f:
            stored_hash = f.read().strip()
        if not stored_hash:
            return False
        current_hash = compute_staged_hash()
        if not current_hash:
            return False
        return stored_hash == current_hash
    except (OSError, ValueError):
        # ValueError (incl. UnicodeDecodeError) must NOT escape to the hooks'
        # outer fail-open catch-all — fail *closed* (deny) on any recoverable
        # read/decode error so a non-UTF-8 staged diff can't bypass the gate.
        return False


def _has_scan_pass_for_push() -> bool:
    """For push/PR: check that a scan-pass file exists."""
    scan_pass_path = resolve_scan_pass_path()
    try:
        return os.path.isfile(scan_pass_path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Index-changing commits
# ---------------------------------------------------------------------------
#
# The hook runs BEFORE the Bash command, so _has_matching_scan_pass hashes the
# index as it is at that moment. Anything in the same command that changes what
# the commit records defeats the hash match:
#
#   - `git add -A && git commit …`: the add runs after the check.
#   - `git commit -a` / `-i` / `-o` / `-p` / `<pathspec>`: commit stages
#     working-tree content itself.
#
# So a commit is allowed only when it records the index exactly as scanned:
# no index-mutating git subcommand anywhere in the command line, and only
# allowlisted commit options (message/author/amend/signing/…) with no
# positional arguments. Unknown options (including git's abbreviated long
# options, e.g. `--al` for `--all`) are denied rather than guessed at. If the
# command can't be tokenized, or the commit isn't a direct `git … commit`
# invocation (`eval 'git commit -a'`), the gate fails closed.
#
# The tokenizer is a small subset of POSIX shell word splitting: quotes,
# backslash escapes, `$(…)` / backticks / `${…}` (kept whole, heredocs inside
# them skipped), top-level heredoc bodies, and `#` comments. It exists to parse
# the commit's argv, not to be a shell; the durable fix is re-checking the
# final index at commit time (git-level pre-commit hook).

_SHELL_OPERATOR_CHARS = frozenset("();<>|&")
_HEREDOC_START = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([^\s;&|<>()]+))")
_MAX_SUBST_DEPTH = 32

_COMMIT_VALUE_SHORT = frozenset("mFCct")  # value attached or in the next word
_COMMIT_OPTIONAL_VALUE_SHORT = frozenset("Su")  # value only when attached
_COMMIT_FLAG_SHORT = frozenset("sneqvz")
_COMMIT_VALUE_LONG = frozenset(
    {
        "message",
        "file",
        "reuse-message",
        "reedit-message",
        "template",
        "author",
        "date",
        "cleanup",
        "fixup",
        "squash",
        "trailer",
    }
)
_COMMIT_OPTIONAL_VALUE_LONG = frozenset({"gpg-sign", "untracked-files"})
_COMMIT_FLAG_LONG = frozenset(
    {
        "signoff",
        "no-signoff",
        "no-verify",
        "verify",
        "no-post-rewrite",
        "allow-empty",
        "allow-empty-message",
        "amend",
        "no-edit",
        "edit",
        "quiet",
        "verbose",
        "dry-run",
        "status",
        "no-status",
        "no-gpg-sign",
        "reset-author",
        "short",
        "porcelain",
        "long",
        "null",
        "branch",
    }
    | _COMMIT_OPTIONAL_VALUE_LONG
)
# git global options that take a separate-word value (`git -C dir commit`).
_GIT_GLOBAL_VALUE_OPTS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix"}
)


def _skip_heredoc_bodies(cmd: str, pos: int, pending: list[tuple[str, bool]]) -> int:
    """Skip heredoc bodies starting at ``pos`` (just past a newline)."""
    n = len(cmd)
    for delim, strip_tabs in pending:
        while pos < n:
            nl = cmd.find("\n", pos)
            end = n if nl < 0 else nl
            line = cmd[pos:end]
            pos = end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                break
    pending.clear()
    return min(pos, n)


def _skip_dquote(cmd: str, i: int, depth: int) -> int:
    """``cmd[i] == '"'``. Return the index past the closing quote, or -1."""
    n = len(cmd)
    i += 1
    while i < n:
        c = cmd[i]
        if c == '"':
            return i + 1
        if c == "\\":
            i += 2
        elif cmd.startswith("$(", i) or c == "`":
            i = _skip_subst(cmd, i, depth + 1)
            if i < 0:
                return -1
        else:
            i += 1
    return -1


def _skip_subst(cmd: str, i: int, depth: int) -> int:
    """Skip a ``$(…)``, backtick, or ``${…}`` expansion starting at ``cmd[i]``.

    Returns the index just past it, or -1 if it is unterminated or nested too
    deeply (the callers fail closed on -1).
    """
    if depth > _MAX_SUBST_DEPTH:
        return -1
    n = len(cmd)
    if cmd[i] == "`":
        j = i + 1
        while j < n and cmd[j] != "`":
            j += 2 if cmd[j] == "\\" else 1
        return j + 1 if j < n else -1
    if cmd.startswith("${", i):
        j = cmd.find("}", i + 2)
        return j + 1 if j >= 0 else -1
    # $( … ): count parens, skipping quotes, nested expansions and heredocs.
    i += 2
    parens = 1
    pending: list[tuple[str, bool]] = []
    while i < n:
        c = cmd[i]
        if c == "\\":
            i += 2
        elif c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                return -1
            i = j + 1
        elif c == '"':
            i = _skip_dquote(cmd, i, depth)
            if i < 0:
                return -1
        elif cmd.startswith("$(", i) or cmd.startswith("${", i) or c == "`":
            i = _skip_subst(cmd, i, depth + 1)
            if i < 0:
                return -1
        elif cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
            m = _HEREDOC_START.match(cmd, i)
            if m:
                delim = m.group(2) or m.group(3) or m.group(4) or ""
                pending.append((delim, bool(m.group(1))))
                i = m.end()
            else:
                i += 2
        elif c == "\n" and pending:
            i = _skip_heredoc_bodies(cmd, i + 1, pending)
        elif c == "(":
            parens += 1
            i += 1
        elif c == ")":
            parens -= 1
            i += 1
            if parens == 0:
                return i
        else:
            i += 1
    return -1


def _shell_words(cmd: str) -> list[tuple[str, bool]] | None:
    """Split a shell command into ``(text, is_operator)`` tokens.

    Operators are runs of ``();<>|&`` and single newlines. Returns None when
    the command can't be tokenized (unbalanced quotes / expansions).
    """
    words: list[tuple[str, bool]] = []
    buf: list[str] = []
    in_word = False
    pending_heredocs: list[tuple[str, bool]] = []
    expect_delim = False
    strip_tabs = False
    n = len(cmd)
    i = 0

    def flush() -> None:
        nonlocal in_word, expect_delim
        if not in_word:
            return
        text = "".join(buf)
        buf.clear()
        in_word = False
        if expect_delim:
            pending_heredocs.append((text, strip_tabs))
            expect_delim = False
        words.append((text, False))

    while i < n:
        c = cmd[i]
        if c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            words.append(("\n", True))
            i += 1
            if pending_heredocs:
                i = _skip_heredoc_bodies(cmd, i, pending_heredocs)
        elif c == "#" and not in_word:
            nl = cmd.find("\n", i)
            i = n if nl < 0 else nl
        elif c in _SHELL_OPERATOR_CHARS:
            j = i
            while j < n and cmd[j] in _SHELL_OPERATOR_CHARS:
                j += 1
            op = cmd[i:j]
            if in_word and ("<" in op or ">" in op) and "".join(buf).isdigit():
                buf.clear()  # fd number of a redirect (`2>&1`), not an argument
                in_word = False
            flush()
            words.append((op, True))
            if "<<" in op and "<<<" not in op:
                expect_delim = True
                strip_tabs = cmd.startswith("-", j)
                if strip_tabs:
                    j += 1
            i = j
        elif c == "\\":
            if i + 1 < n and cmd[i + 1] != "\n":
                buf.append(cmd[i + 1])
                in_word = True
            i += 2
        elif c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                return None
            buf.append(cmd[i + 1 : j])
            in_word = True
            i = j + 1
        elif cmd.startswith("$'", i):
            j = i + 2
            while j < n and cmd[j] != "'":
                j += 2 if cmd[j] == "\\" else 1
            if j >= n:
                return None
            buf.append(cmd[i + 2 : j])
            in_word = True
            i = j + 1
        elif c == '"':
            j = _skip_dquote(cmd, i, 0)
            if j < 0:
                return None
            buf.append(cmd[i + 1 : j - 1])
            in_word = True
            i = j
        elif cmd.startswith("$(", i) or cmd.startswith("${", i) or c == "`":
            j = _skip_subst(cmd, i, 0)
            if j < 0:
                return None
            buf.append(cmd[i:j])
            in_word = True
            i = j
        else:
            buf.append(c)
            in_word = True
            i += 1
    flush()
    return words


def _commit_invocations(words: list[tuple[str, bool]]) -> list[list[str]]:
    """Return the argument list of every direct ``git … commit`` invocation."""
    invocations: list[list[str]] = []
    n = len(words)
    i = 0
    while i < n:
        text, is_op = words[i]
        i += 1
        if is_op or text.rsplit("/", 1)[-1] != "git":
            continue
        while i < n and not words[i][1] and words[i][0].startswith("-"):
            i += 2 if words[i][0] in _GIT_GLOBAL_VALUE_OPTS else 1
        if i >= n or words[i] != ("commit", False):
            continue
        i += 1
        args: list[str] = []
        while i < n:
            text, is_op = words[i]
            if is_op:
                if "<" not in text and ">" not in text:
                    break  # command separator ends the commit's argv
                i += 1
                if i < n and not words[i][1]:
                    i += 1  # redirect target
                continue
            args.append(text)
            i += 1
        invocations.append(args)
    return invocations


def _commit_arg_problem(args: list[str]) -> str:
    """Return a description of the first argument that changes what the commit
    records (or isn't recognized), or "" if the commit records the index as-is.
    """
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            return f"pathspec {args[i]!r}" if i < len(args) else ""
        if arg.startswith("--"):
            name, eq, _ = arg[2:].partition("=")
            if eq:
                if name not in _COMMIT_VALUE_LONG | _COMMIT_OPTIONAL_VALUE_LONG:
                    return f"option {arg!r}"
            elif name in _COMMIT_VALUE_LONG:
                i += 1
            elif name not in _COMMIT_FLAG_LONG:
                return f"option {arg!r}"
        elif arg.startswith("-") and len(arg) > 1:
            for k in range(1, len(arg)):
                ch = arg[k]
                if ch in _COMMIT_VALUE_SHORT:
                    if k == len(arg) - 1:
                        i += 1
                    break
                if ch in _COMMIT_OPTIONAL_VALUE_SHORT:
                    break
                if ch not in _COMMIT_FLAG_SHORT:
                    return f"option '-{ch}'"
        else:
            return f"pathspec {arg!r}"
    return ""


def _index_changing_commit(cmd: str) -> str:
    """Return why this commit command would record more than the scanned
    index, or "" if it records the index exactly as the gate hashed it.
    """
    m = _INDEX_MUTATING_PATTERN.search(cmd)
    if m:
        return f"'git {m.group('sub')}' in the same command"
    m = _INDEX_REDIRECT_ENV.search(cmd)
    if m:
        return f"'{m.group(0)}' redirects git to a different index"
    words = _shell_words(cmd)
    if words is None:
        return "the command could not be parsed"
    invocations = _commit_invocations(words)
    if not invocations:
        return "git commit is not invoked directly"
    for args in invocations:
        problem = _commit_arg_problem(args)
        if problem:
            return problem
    return ""


# ---------------------------------------------------------------------------
# System message builder
# ---------------------------------------------------------------------------


def _scan_call(cmd: str, repo_path: str | None) -> str:
    """Build the ``scan_diff(...)`` call string for the given command.

    ``repo_path`` (the hook's own work-tree root) is injected so the MCP
    server scans — and writes the scan-pass into — the *same* repo the commit
    will happen in. The server is long-lived and pinned to its launch CWD,
    which in a Conductor setup is often the main checkout, not this worktree;
    without this argument the server would write the scan-pass into the wrong
    git dir and the gate (reading from here) would never see it.
    """
    # A commit is only ever allowed against the staged diff (check_gate denies
    # -a/--all and friends), so it takes precedence over a push/PR in the same
    # command: a ref scan's pass would never match the commit's staged hash.
    if _is_push_or_pr(cmd) and not _is_commit(cmd):
        args = ["ref='origin/HEAD'"]
    else:
        args = ["staged=True"]

    if repo_path:
        # repr() produces a valid, properly-escaped Python string literal so the
        # call stays syntactically valid even if the path contains a single
        # quote or backslash (the agent reproduces this call verbatim).
        args.append(f"repo_path={repo_path!r}")
    return f"scan_diff({', '.join(args)})"


def build_system_message(
    cmd: str, repo_path: str | None = None, merge_in_progress: bool | None = None
) -> str:
    """Build the scan instruction based on command type.

    ``repo_path`` defaults to the hook's resolved work-tree root; tests pass it
    explicitly. It is woven into the recommended ``scan_diff`` call so the
    scan-pass is written where this gate will read it.

    ``merge_in_progress`` defaults to detecting a merge/rebase in ``repo_path``.
    When True, the message gets a merge-aware branch (ticket.md): a merge diff
    can be huge and un-scannable (truncated), it is mostly already-landed
    upstream code, and it can't be split — so the agent is told upfront that an
    explicit human approve_findings is the intended path, instead of discovering
    that dead end after several failed attempts.
    """
    if repo_path is None:
        repo_path = resolve_repo_toplevel()

    if merge_in_progress is None:
        merge_in_progress = merge_or_rebase_in_progress(repo_path or None)

    scan_instruction = _scan_call(cmd, repo_path)

    base = (
        f"Security scan required before shipping. "
        f"Call {scan_instruction} to scan your changes. "
        f"After scanning:\n"
        f"- If clean (no HIGH/CRITICAL findings): retry the original command.\n"
        f"- If HIGH/CRITICAL findings: fix what you can (move secrets to env vars, "
        f"mask tokens, set debug=False), re-stage, and re-scan.\n"
        f"- If HIGH/CRITICAL findings remain after remediation: present them to the "
        f"user and ask whether to proceed. Do NOT call approve_findings on your own "
        f"- wait for the user to explicitly say to proceed. If the user approves, "
        f"call approve_findings(reason='<quote the user stated reason>') then retry "
        f"the original command.\n"
        f"MEDIUM/LOW/INFO findings can be ignored."
    )
    if merge_in_progress:
        base += (
            "\nNOTE: a merge/rebase is in progress. Its staged diff includes "
            "already-landed upstream code, not just your work, and may exceed the "
            "scan size limit (truncated). If the scan reports it was truncated and "
            "cannot auto-authorize the commit, the diff can't be split — present the "
            "situation to the user and, only if they explicitly accept shipping the "
            "un-scannable upstream content, call approve_findings(reason='<user "
            "reason>') to proceed."
        )
    return base


def build_index_change_message(problem: str, repo_path: str | None = None) -> str:
    """Deny message for a commit that would record more than the scanned index."""
    if repo_path is None:
        repo_path = resolve_repo_toplevel()
    return (
        f"BLOCKED: this git commit could record changes the security scan never "
        f"saw ({problem}). The gate checks the staged diff before the command "
        f"runs, so staging in the same command (git add/rm/mv/stash/checkout/"
        f"reset/...), commit -a/--all, -i/--include, -o/--only, -p/--patch, "
        f"pathspecs, and unrecognized commit options are not allowed. Stage your "
        f"changes in a separate command, call {_scan_call('git commit', repo_path)}, "
        f"then run git commit with only message/author/amend options "
        f"(e.g. git commit -m '...')."
    )


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

_SCAN_PASS_WRITE_DENY_MSG = "BLOCKED: Direct writes to .scan-pass are not allowed. The scan-pass file is managed by the security scanner. Run scan_diff() to scan your code instead."  # noqa: S105, E501


def check_gate(cmd: str) -> GateResult:
    """Main entry point: evaluate a shell command against the security gate.

    Returns GateResult with decision="allow" or decision="deny" plus system_message.
    """
    if _is_scan_pass_write_bash(cmd):
        return GateResult("deny", _SCAN_PASS_WRITE_DENY_MSG)

    if not _is_shipping_command(cmd):
        return GateResult("allow", "")

    # A commit in the command is checked even when a push/PR follows it
    # (`git add -A && git commit … && git push`): the push branch only checks
    # that a pass exists, which would wave through an unscanned commit.
    if _is_commit(cmd):
        problem = _index_changing_commit(cmd)
        if problem:
            return GateResult("deny", build_index_change_message(problem))
        if not _has_matching_scan_pass():
            return GateResult("deny", build_system_message(cmd))

    if _is_push_or_pr(cmd) and not _has_scan_pass_for_push():
        return GateResult("deny", build_system_message(cmd))

    return GateResult("allow", "")

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A Claude Code **plugin** (not a library) that exposes Armis's AI-powered SAST scanner through three surfaces:

1. **MCP server** (`server.py`) — tools `scan_code`, `scan_file`, `scan_diff`, `approve_findings`, `debug_config` and the `appsec://last-scan` resource.
2. **PreToolUse hooks** (`hooks/`) — a commit gate that blocks `git commit` / `git push` / `gh pr create` until a scan has passed, plus a guard that prevents Write/Edit from forging `.scan-pass`.
3. **Slash command** (`skills/security-scan/SKILL.md`) — on-demand `/security-scan` invocation.

Distribution is via `.claude-plugin/marketplace.json`; the plugin installs under `~/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/<version>/` and is launched by `run.sh` (which bootstraps a per-install `.venv` keyed off `requirements.txt`'s SHA-256).

Requires **Python 3.12+**. Credentials (`ARMIS_CLIENT_ID`, `ARMIS_CLIENT_SECRET`) live in a `.env` in the plugin directory.

## Common commands

```bash
make lint          # ruff check . --fix
make format        # ruff format .
make format-check  # ruff format --check .  (what CI runs)
make typecheck     # mypy . --exclude '.venv|__pycache__|hooks/tests'
make test          # pytest --cov --cov-report=term-missing
make check         # format-check + lint + typecheck + test  (full CI gate locally)

# Run a single test file / test
pytest hooks/tests/test_suppression.py -v
pytest hooks/tests/test_server_helpers.py::test_validate_file_path_blocks_etc -v

# Other useful targets
make install-hooks   # symlink git-hooks/pre-commit into .git/hooks/
make uninstall-hooks # remove the symlink
make setup CLIENT=cursor  # generate MCP config (cursor|vscode|gemini|copilot)

# Run the MCP server directly (stdio transport, reads .env)
./run.sh
# or, if deps already installed:
python server.py
```

`pytest.ini_options` in `pyproject.toml` pins `testpaths = ["hooks/tests"]` — **all tests live under `hooks/tests/`**, even though most of them exercise `server.py`, `scanner_core.py`, `auth.py`, and `suppression.py` (not hooks). That path is historical; don't move tests trying to "fix" it.

## Architecture: the shared core

`scanner_core.py`, `auth.py`, `suppression.py`, and `hash_utils.py` are the load-bearing shared modules. The MCP server and the hooks both import from them — a change in any of these affects **both** the tool-call flow and the commit-gate flow.

- `scanner_core.call_appsec_api()` → POSTs to `{APPSEC_API_URL}/scan/fast` with `{code, mode: "fast"}` and a JWT Bearer. HTTPS is enforced (localhost exempt).
- `scanner_core.parse_findings()` → extracts the JSON block from the LLM response; findings with `cwe in (None, 0)` are filtered out to match the production pipeline.
- `scanner_core.format_findings()` → compact, no-markdown plain text (optimized for LLM token cost, not human readability).
- `auth.JWTAuth` → OAuth2 client-credentials against `/auth/token`. Token cached in memory, re-exchanged when within 5 minutes of `exp`. `_parse_jwt_exp` bounds-checks `exp` (must be future, ≤24h out).
- `suppression` → two mechanisms, both deterministic local matching (no LLM involvement): (1) **`.armisignore`** at git root — `cwe:`, `severity:`, `category:`, `rule:` directives and path patterns (basename, glob, or `dir/` prefix); (2) **inline `armis:ignore`** source comments — `apply_inline_suppressions` (file scans, by source line) and `apply_inline_suppressions_to_diff` (diff scans, by blob line via `build_diff_line_map`). Fail-open on any parse/IO error.
- `hash_utils.compute_staged_hash()` → SHA-256 of `git diff --cached --no-color --no-ext-diff`; used by both server and hook to agree on "same staged diff."

## The `.scan-pass` commit gate (critical invariant)

This is the trickiest cross-file interaction. The commit gate works like a handshake:

1. Agent calls `scan_diff(staged=True, repo_path=...)` (or `ref=...`). On success with **no HIGH/CRITICAL findings**, `server._cache_scan()` writes `SHA-256(staged diff)` to the scan-pass file. The file lives **inside the repo's git dir** as `<git-dir>/armis-scan-pass` — resolved by `hash_utils.resolve_scan_pass_path(repo_path)` via `git rev-parse --absolute-git-dir`. Keeping it in `.git/` means it never appears in the working tree (no `git status` noise, nothing to gitignore) and it resolves correctly inside **git worktrees** (every Conductor workspace), where `.git` is a *file*, not a directory.
2. Agent calls `git commit`. `hooks/pre_commit_scan.py` fires (PreToolUse on Bash), computes the **current** staged hash, and allows the command only if it equals the stored hash. Stale passes (someone staged more code since scanning) are rejected.
3. For `git push` / `gh pr create`, file presence alone is sufficient — the commit already enforced the hash match.
4. If the agent needs to ship despite HIGH/CRITICAL findings, the user must explicitly approve; the agent then calls `approve_findings(reason=...)` which writes `.scan-pass` with the approval hash. **The agent must never call `approve_findings` on its own** — the system message in `_build_system_message` spells this out.

**Forgery protection:**
- `hooks/protect_scan_pass.py` denies any `Write`/`Edit` whose basename is `armis-scan-pass` (or the legacy `.scan-pass`) — see `hook_core.is_scan_pass_file`.
- `hooks/pre_commit_scan.py` denies any Bash command matching `_SCAN_PASS_WRITE_PATTERN` — a *write context* targeting `armis-scan-pass` / `.scan-pass`: a redirect (`>`, `>>`, `>|`, fd-prefixed), a write-capable command naming the file (`tee`/`cp`/`mv`/`dd`/`sed -i`/`install`/`ln`/`truncate`/`sponge`/editors/interpreters like `python`/`perl`/`awk`/`gawk`/`php`), or assigning the path to a shell variable. It deliberately does **not** match mere mentions (commit messages, `grep`/`cat`/`rm`/`pytest`). The verb list is a blocklist (inherently leaky) — the hash match and `protect_scan_pass.py`'s Write/Edit guard are the backstops, and an unforgeable HMAC token is the durable follow-up.
- The scan-pass path is computed by `git` itself (`git rev-parse --absolute-git-dir`), not from an env var, so there is no externally-controlled path to traverse (the old `CLAUDE_PLUGIN_ROOT`-based resolution and its CWE-73 mitigation are gone).

**Reader/writer must agree (the worktree bug, part 1 — *same resolver*):** the gate reader (`hook_core`) and the scanner writer (`server`, `git-hooks`) **both** call `hash_utils.resolve_scan_pass_path()`. They previously used two private `_find_git_root` walkers that disagreed on a worktree's `.git` *file* (`os.path.isdir` vs `os.path.exists`), so the gate denied forever in every Conductor workspace. Never reintroduce a second resolver.

**Reader/writer must agree (the worktree bug, part 2 — *same CWD*):** sharing the resolver is necessary but **not sufficient**. `git rev-parse --absolute-git-dir` returns the *per-worktree* git dir, so its answer depends on the **directory it runs in**. The MCP server is a long-lived process pinned to its launch CWD — in a Conductor setup, usually the **main checkout**, not the worktree being committed. The pre-commit hook is spawned fresh per Bash call and runs in the user's CWD (the worktree). Same resolver, two CWDs → two different git dirs → the server writes the scan-pass into the main repo's `.git/` while the hook looks in the worktree's per-worktree git dir, and they never meet. **The fix has two halves:** (a) `resolve_scan_pass_path()`, `compute_staged_hash()`, and `cleanup_legacy_scan_pass()` all take an optional `repo_path` (`None` → CWD), and `scan_diff` threads its `repo_path` through `_cache_scan`/`do_approve_findings` so the write lands in the *scanned* repo's git dir; (b) the hook — the only actor that reliably knows the commit's CWD — injects `repo_path='<work-tree-root>'` (via `hash_utils.resolve_repo_toplevel()`) into the `scan_diff(...)` call it tells the agent to run (`hook_core._scan_call`). The agent reproduces that call verbatim, pinning the server's scan and scan-pass write to the same git dir the hook reads from. **Always pass `repo_path` from the hook; never let the server fall back to its own CWD for a worktree commit.**

Don't "simplify" any of this without reading `.context/0008-*.md` — the guard rails are deliberate.

## Suppression semantics (`.armisignore`)

`apply_suppressions()` partitions findings into `active` and `suppressed`. Non-obvious rules:

- **Suppressed CRITICAL** findings still block `.scan-pass` — they require `approve_findings`.
- **Suppressed HIGH** does **not** block. A team's presence of `severity:HIGH` in `.armisignore` is treated as an already-made risk decision, so no per-commit approval is needed. See the comment in `server._cache_scan()`.
- `scan_file` also short-circuits *before* the API call if the file path is excluded by `.armisignore` — avoids paying API cost on ignored files.
- Category is derived, not declared: `has_secret: true` → `"secrets"`, else `"sast"`.

### Inline `armis:ignore` comments

A finding can also be suppressed by a comment **in the source itself**, on the finding's own
line or the line directly above it. This works for `scan_file`, `scan_diff`, and the portable
`git-hooks/scan-staged.py` (all three apply it; `scan_code` does not — it has no file/diff to
anchor on). Syntax:

- Marker `armis:ignore` (case-insensitive), inside a comment in any supported language
  (`#`, `//`, `--`, `<!-- -->`, `/* */`, …). Comment detection (`_extract_comment_text`) is
  **string-literal aware**: a marker inside a quoted string (e.g. `q = "... #armis:ignore"`)
  does **not** start a directive, so it can't suppress the finding on that line. This is the
  fail-safe direction — when in doubt the finding stays active.
- Bare `armis:ignore` suppresses **any** finding on that line.
- Optional params narrow the match: `cwe:798`, `severity:HIGH`, `category:secrets`, and a
  free-text `reason: ...`. Logic is **AND across param *types*** (a `cwe:` and a `severity:`
  in the same directive must both hold) but **OR *within* repeated `cwe:` tokens** —
  `cwe:78 cwe:77` suppresses a finding reported as *either* CWE. The OR-over-CWEs accumulates
  into `InlineDirective.cwes` (a tuple), matching `.armisignore`'s `cwes` list and production
  `inline.go`. This matters because the fast-scan model is non-deterministic about which CWE
  it assigns to a sink (command injection rotates 78/77, the path-read family rotates
  22/23/73/770), so a directive must be able to name every CWE the finding may surface as.
  **List CWEs generously.** (Before the PPSC-920 fix, multiple `cwe:` tokens collapsed
  last-wins — `cwe:78 cwe:77` silently became `cwe:77` only — so a CWE-78 finding stayed
  active with no error. Don't reintroduce single-value `cwe` parsing.)
- `rule:` is recognized but a `rule:`-only directive matches **nothing** (the fast-scan model
  has no rule IDs) — it is *not* treated as bare. Combine it with `cwe:`/etc. to take effect.
- **Diff scans match the diff blob, not files on disk** (`apply_inline_suppressions_to_diff`):
  correct for `staged`/`ref` scans where the working tree may differ. The "line above" is the
  same file's previous *source* line, so a directive can never cross a hunk gap or file
  boundary, and a directive on a removed (`-`) line never suppresses.
- Inline-suppressed **CRITICAL** still blocks `.scan-pass` (requires `approve_findings`); inline
  HIGH/other does not — same gate semantics as `.armisignore`.

## Fail-open vs fail-closed

| Component | Policy | Rationale |
|---|---|---|
| `hooks/pre_commit_scan.py` | **Fail open** (catch-all wraps `main()`) | Plugin bugs must never block the developer |
| `hooks/protect_scan_pass.py` | **Fail open** | Same |
| `suppression.load_armisignore` | **Fail open** on IO/parse errors | Never lose findings due to a malformed ignore file |
| `auth.JWTAuth` | **Fail closed** | Can't scan without auth; errors propagate as `RuntimeError` → `ToolError` |
| CI scanner (separate pipeline) | **Fail closed** | Second line of defense |

When you edit either hook, preserve the outer `try: ... except Exception: print({}); sys.exit(0)` — it is load-bearing.

## Path validation and size limits (in `server.py`)

- `_validate_file_path` enforces an **allowlist** ($HOME, `/tmp`, `/private/tmp`, system temp) and a **blocklist** (`/etc/`, `/proc/`, `/sys/`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`). Both apply — allowlist first, then defense-in-depth blocklist.
- `_VALID_GIT_REF` rejects refs with shell-unsafe characters or leading `-`.
- `_MAX_CODE_CHARS = 90_000` — `scan_code`/`scan_file` inputs are **silently** truncated past this (a warning is logged). For `scan_diff` (the shipping path), `run_git_diff` returns `(diff_text, truncated)`; a **truncated** staged/ref diff is **not** shipping-eligible — `scan_diff` writes no scan-pass and surfaces a "too large to gate — split your commit" warning (the scanner only saw the first 90K but the staged hash covers the full diff, so a vuln past the cut would otherwise ship under a clean pass). Keep this in mind when writing tests that assemble large inputs.
- `_MAX_FILE_BYTES = 10 MB`, binary-detection sniffs the first 8 KiB for null bytes.

## Ruff and mypy quirks

`pyproject.toml` has intentional per-file overrides — don't "clean them up":

- `server.py` and `hooks/pre_commit_scan.py` ignore `E402` because they manipulate `sys.path` before importing local modules (needed so the module works regardless of CWD).
- `hooks/tests/*` ignore the `S` (bandit) rules, `E402`, and `B017` — tests legitimately do subprocess calls, `pytest.raises(Exception)`, and path gymnastics.
- `mypy` is set with `check_untyped_defs = false` and excludes `hooks/tests`. Don't try to type the tests.

## When adding a new MCP tool

1. Add a sync helper function (e.g. `do_x(...)`) at module level — this is what tests call.
2. Add a thin `@mcp.tool()` async wrapper that awaits into the helper.
3. If the tool produces shipping-eligible scans, route through `_run_scan(...)` so `.scan-pass` caching, `.armisignore` suppression, and progress reporting are consistent.
4. Update `skills/security-scan/SKILL.md` if it's user-facing via `/security-scan`.

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `ARMIS_CLIENT_ID` | (required) | Read from `.env` in plugin dir |
| `ARMIS_CLIENT_SECRET` | (required) | Read fresh from env on each `exchange()` — not cached in memory |
| `APPSEC_ENV` | `prod` | Selects `moose.armis.com` (prod) or `moose-dev.armis.com` (dev) |
| `APPSEC_API_URL` | auto | Full override; must be HTTPS unless hostname is localhost |
| `APPSEC_DEBUG` | unset | Any truthy value enables debug logging |
| `APPSEC_TRANSPORT` | `stdio` | MCP transport passed to `mcp.run()` |
| `CLAUDE_PLUGIN_ROOT` | auto | Set by Claude Code; must resolve inside a git repo or it's ignored |

## Two hook systems

The repo has two distinct hook systems serving different audiences:

- **`hooks/`** — Claude Code **PreToolUse** hooks (manifest: `hooks/hooks.json`). These fire inside Claude Code's tool execution pipeline and are installed automatically via the plugin. They enforce the scan-pass gate on `Bash` (commit/push/PR commands) and block `Write`/`Edit` to the scan-pass file (anti-forgery).
- **`git-hooks/`** — Portable **git** hooks (`pre-commit` shell script + `scan-staged.py`). These work with any client (Cursor, VS Code, Gemini, Copilot CLI) and are installed via `make install-hooks`. They call the scanner directly (no MCP client needed) and write the scan-pass using the same path and hash format, so they're interchangeable with the MCP `scan_diff` flow.

Both systems share the same core modules and resolve the scan-pass to the same place — `<git-dir>/armis-scan-pass`, holding a SHA-256 of the staged diff (the shell hook uses `git rev-parse --absolute-git-dir`; Python uses `hash_utils.resolve_scan_pass_path()`). Code scanned via `git-hooks/scan-staged.py` will satisfy the Claude Code hook and vice versa.

## Multi-client support

The MCP server works with 5 clients: Claude Code, Cursor, VS Code (GitHub Copilot), Gemini CLI, and GitHub Copilot CLI.

- `config-templates/` — JSON templates for each client's MCP config format, used by `make setup CLIENT=...`.
- `AGENTS.md`, `.github/copilot-instructions.md`, `.cursor/rules/security-scanning.mdc` — instruction files for non-Claude clients. All contain the same "scan before commit" guidance. **Keep these in sync** — if you update one, update the others.

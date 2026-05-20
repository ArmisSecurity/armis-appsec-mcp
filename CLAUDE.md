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
- `suppression` → `.armisignore` at git root. Supports `cwe:`, `severity:`, `category:`, `rule:` directives and path patterns (basename, glob, or `dir/` prefix). Fail-open on any parse/IO error.
- `hash_utils.compute_staged_hash()` → SHA-256 of `git diff --cached --no-color --no-ext-diff`; used by both server and hook to agree on "same staged diff."

## The `.scan-pass` commit gate (critical invariant)

This is the trickiest cross-file interaction. The commit gate works like a handshake:

1. Agent calls `scan_diff(staged=True)` (or `ref=...`). On success with **no HIGH/CRITICAL findings**, `server._cache_scan()` writes `SHA-256(staged diff)` to `{CLAUDE_PLUGIN_ROOT}/.scan-pass`.
2. Agent calls `git commit`. `hooks/pre_commit_scan.py` fires (PreToolUse on Bash), computes the **current** staged hash, and allows the command only if it equals the stored hash. Stale passes (someone staged more code since scanning) are rejected.
3. For `git push` / `gh pr create`, file presence alone is sufficient — the commit already enforced the hash match.
4. If the agent needs to ship despite HIGH/CRITICAL findings, the user must explicitly approve; the agent then calls `approve_findings(reason=...)` which writes `.scan-pass` with the approval hash. **The agent must never call `approve_findings` on its own** — the system message in `_build_system_message` spells this out.

**Forgery protection:**
- `hooks/protect_scan_pass.py` denies any `Write`/`Edit` whose basename is `.scan-pass`.
- `hooks/pre_commit_scan.py` denies any Bash command matching `_SCAN_PASS_WRITE_PATTERN` (redirects, `tee`, `cp`, `mv` targeting `.scan-pass`).
- `CLAUDE_PLUGIN_ROOT` is validated in `_plugin_root()` — it must resolve inside a git repository, mitigating CWE-73 path traversal.

Don't "simplify" any of this without reading `.context/0008-*.md` — the guard rails are deliberate.

## Suppression semantics (`.armisignore`)

`apply_suppressions()` partitions findings into `active` and `suppressed`. Non-obvious rules:

- **Suppressed CRITICAL** findings still block `.scan-pass` — they require `approve_findings`.
- **Suppressed HIGH** does **not** block. A team's presence of `severity:HIGH` in `.armisignore` is treated as an already-made risk decision, so no per-commit approval is needed. See the comment in `server._cache_scan()`.
- `scan_file` also short-circuits *before* the API call if the file path is excluded by `.armisignore` — avoids paying API cost on ignored files.
- Category is derived, not declared: `has_secret: true` → `"secrets"`, else `"sast"`.

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
- `_MAX_CODE_CHARS = 90_000` — code/diff inputs are **silently** truncated past this (a warning is logged). Keep this in mind when writing tests that assemble large inputs.
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

- **`hooks/`** — Claude Code **PreToolUse** hooks (manifest: `hooks/hooks.json`). These fire inside Claude Code's tool execution pipeline and are installed automatically via the plugin. They enforce the `.scan-pass` gate on `Bash` (commit/push/PR commands) and block `Write`/`Edit` to `.scan-pass` (anti-forgery).
- **`git-hooks/`** — Portable **git** hooks (`pre-commit` shell script + `scan-staged.py`). These work with any client (Cursor, VS Code, Gemini, Copilot CLI) and are installed via `make install-hooks`. They call the scanner directly (no MCP client needed) and write `.scan-pass` using the same hash format, so they're interchangeable with the MCP `scan_diff` flow.

Both systems share the same core modules and the same `.scan-pass` file format — a SHA-256 of the staged diff. Code scanned via `git-hooks/scan-staged.py` will satisfy the Claude Code hook and vice versa.

## Multi-client support

The MCP server works with 5 clients: Claude Code, Cursor, VS Code (GitHub Copilot), Gemini CLI, and GitHub Copilot CLI.

- `config-templates/` — JSON templates for each client's MCP config format, used by `make setup CLIENT=...`.
- `AGENTS.md`, `.github/copilot-instructions.md`, `.cursor/rules/security-scanning.mdc` — instruction files for non-Claude clients. All contain the same "scan before commit" guidance. **Keep these in sync** — if you update one, update the others.

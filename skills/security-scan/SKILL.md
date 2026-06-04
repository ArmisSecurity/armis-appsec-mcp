---
name: security-scan
description: "On-demand AI-powered security scanning. Use when the user asks to scan code for vulnerabilities, run a security check, scan code for security issues, scan a file, scan a diff, scan staged changes, check for security issues, check for secrets, find hardcoded credentials, or run an appsec scan. Triggers: /security-scan, scan for vulnerabilities, security scan, check this code, scan my changes, scan this file, scan diff, appsec scan, security check, check for secrets, find credentials."
---

# /security-scan

On-demand security scanning powered by AI SAST. Scans code snippets, files, or git diffs for vulnerabilities and reports findings with CWE IDs, severity, line numbers, and fix suggestions.

## Usage

- `/security-scan` -- scan staged changes (falls back to unstaged if nothing staged)
- `/security-scan path/to/file.py` -- scan a specific file
- `/security-scan ref=main` -- scan diff against a branch or ref
- `/security-scan full` -- include all severities (not just HIGH/CRITICAL)
- User pastes code inline and asks about security -- scan the pasted code

## MCP Tools

The MCP server is named `scanner`. All tools are prefixed `mcp__scanner__`.

| Tool | When to Use |
|------|-------------|
| `mcp__scanner__scan_diff` | Default. Scan git changes (staged, unstaged, or vs a ref) |
| `mcp__scanner__scan_file` | User provides a file path to scan |
| `mcp__scanner__scan_code` | User pastes code inline or asks about a snippet |

### Tool Parameters

**`mcp__scanner__scan_diff`**
- `repo_path` (string, optional): Path to git repo. **Always set this to the absolute work-tree root of the repository you are working in** — the value of `git rev-parse --show-toplevel`, not just your current working directory (which may be a subdirectory and would resolve the hash/scan-pass against the wrong root). The MCP server is a long-lived process whose own working directory may be a *different* checkout than yours — in a git worktree (e.g. a Conductor workspace) it is often the main repo, not your worktree. Passing `repo_path` pins the scan, the staged-diff hash, and the `.scan-pass` write to *your* repo so the commit gate sees them. Omitting it falls back to the server's working directory, which is wrong outside that one checkout.
- `ref` (string, optional): Git ref to diff against (branch name, tag, SHA, `HEAD~3`). If empty, scans unstaged or staged changes.
- `staged` (bool, optional): If true, scan only staged changes (`git diff --cached`). Ignored when `ref` is provided.

**`mcp__scanner__scan_file`**
- `file_path` (string, required): Absolute path to the file to scan.

**`mcp__scanner__scan_code`**
- `code` (string, required): The source code to scan. Truncated at 90,000 characters.
- `filename` (string, optional): Filename for context (e.g. `"auth.py"`). Defaults to `"snippet"`.

Note: `scan_file` and `scan_code` both silently truncate input at 90,000 characters. For very large files, consider using `scan_diff` on specific changes instead.

### Resource

- `appsec://last-scan` -- Returns cached results from the most recent scan. Use when the user asks "what was the last scan?" or "show previous results" without needing to re-scan.

## Decision Tree

Follow this logic to pick the right tool. **For every `scan_diff` call, pass `repo_path` set to the absolute path of the repo you're working in** (see Tool Parameters for why — it is required for the commit gate to work inside git worktrees).

1. **User provided a file path as argument?**
   Yes: Call `mcp__scanner__scan_file` with that path.

2. **User pasted code inline or is asking about a code block in the conversation?**
   Yes: Call `mcp__scanner__scan_code` with the code. Set `filename` if the language or origin is known.

3. **User specified a ref (branch, tag, SHA) to diff against?**
   Yes: Call `mcp__scanner__scan_diff` with `ref` set to that value (and `repo_path`).

4. **Default (no arguments, or just `/security-scan`):**
   - First: Call `mcp__scanner__scan_diff` with `staged=true` and `repo_path`.
   - If result is "No changes to scan.": Call `mcp__scanner__scan_diff` with `staged=false` (unstaged changes).
   - If still no changes: Tell the user there are no changes to scan.

## Suppressing Findings

If a finding is a reviewed false positive, the user can suppress it. Both mechanisms are
deterministic local matching and apply to `scan_file`, `scan_diff`, and the git commit hook:

- **Inline comment** -- `armis:ignore` in a comment on the finding's line or the line directly
  above it. Narrow with `cwe:`, `severity:`, or `category:` (AND logic), plus an optional free-text
  `reason:`. Example: `query = build(sql)  # armis:ignore cwe:89 reason: parameterized below`. A
  bare `armis:ignore` suppresses any finding on that line. (`rule:`-only matches nothing -- combine
  it with `cwe:`/etc.)
- **`.armisignore` file** at the repo root -- `cwe:`, `severity:`, `category:` directives and path
  patterns, applied repo-wide.

Inline-suppressed/`.armisignore`-suppressed **CRITICAL** still blocks the commit and requires
`approve_findings`; HIGH and below do not. Only suggest suppression for genuine false positives,
never to bypass a real vulnerability.

## Output Formatting

Present findings to the user as follows:

**When findings exist:**

1. State the total count: "Found N security issue(s)."
2. Group by severity (CRITICAL first, then HIGH, MEDIUM, LOW, INFO).
3. For each finding, include:
   - File path and line number: The scanner output already contains resolved `file:line` locations (e.g. `server.py:167`). Use these locations **exactly as they appear** in the tool result -- do NOT substitute raw line numbers from the finding data. If the tool output shows `L{number}` (no file prefix), the line could not be resolved to a source file -- show it as-is.
   - Severity, CWE ID, and CWE name (e.g. "CRITICAL -- CWE-89 (SQL Injection)")
   - Explanation of the vulnerability
   - `[SECRET]` tag if the finding involves a hardcoded secret
   - Tainted function references if present
   - Generate a concise, actionable fix suggestion based on the finding type (the scanner does not include fixes -- you provide them using the table below as a starting point)
4. **Default behavior**: Only show CRITICAL and HIGH findings. Summarize lower severities with a count (e.g. "Also found 2 MEDIUM and 1 LOW issue -- run `/security-scan full` for details.").
5. **Full report mode** (user said `full`, `--all`, or asked for all severities): Show all findings regardless of severity.

**When no findings:**

Report "No vulnerabilities found" and confirm what was scanned (staged changes, file name, etc.).

**Common fix suggestions by finding type:**
- Hardcoded secrets: Move to environment variables or a secrets manager.
- SQL injection: Use parameterized queries.
- XSS: Sanitize/escape output, use framework auto-escaping.
- Debug mode enabled: Set `debug=False` for production.
- Path traversal: Validate and canonicalize file paths.
- SSRF: Validate URLs against an allowlist.

## Error Handling

| Error | What to Tell the User |
|-------|----------------------|
| "No auth credentials configured" or "ARMIS_CLIENT_ID is not set" | The scanner is not configured. Set `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` in the plugin's `.env` file. |
| "Authentication failed: invalid client_id/client_secret" | The credentials are wrong. Verify `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` with the AppSec team. |
| "Scan failed: ..." or API timeout | The scanning service is temporarily unavailable. Try again in a moment. |
| "No changes to scan." | No git changes detected. This is handled by the decision tree -- fall back to unstaged, or suggest scanning a specific file. |
| "File not found: ..." | The file path does not exist. Ask the user to verify the path. |
| "File '...' appears to be binary" | Binary files cannot be scanned. Only source code is supported. |
| "File too large (NMB). Max: 10MB." | File exceeds the 10MB limit. Suggest scanning a specific section or using `scan_diff` instead. |
| "Scanning system path '...' is not allowed" | System directories (`/etc/`, `/proc/`, `/sys/`) are blocked for safety. |
| "Scanning '...' is blocked (sensitive directory)" | Sensitive directories (`~/.ssh`, `~/.aws`, `~/.gnupg`) are blocked for safety. |
| "git diff failed: ..." | Git operation failed. Check that the path is a git repository and the ref is valid. |
| "git diff timed out after 30 seconds" | The diff is too large. Suggest a narrower ref (e.g. `HEAD~1` instead of `main`) or scanning specific files. |
| "Invalid git ref: '...'" | The ref contains invalid characters. Ask the user to verify the branch name, tag, or SHA. |
| "File '...' is empty -- nothing to scan." | The file has no content. Nothing to scan. |
| "Permission denied reading ..." | Claude doesn't have read access to the file. Ask the user to check permissions. |
| "Not a directory: ..." | The `repo_path` for `scan_diff` is not a valid directory. |

## Examples

**Scan staged changes (default):**
User: `/security-scan`
Action: Call `mcp__scanner__scan_diff` with `staged=true`. If "No changes to scan.", retry with `staged=false`.

**Scan a specific file:**
User: `/security-scan services/api-controller/src/routes/auth.py`
Action: Call `mcp__scanner__scan_file` with `file_path` set to the absolute path.

**Scan diff against main:**
User: `/security-scan ref=main`
Action: Call `mcp__scanner__scan_diff` with `ref="main"`.

**Scan pasted code:**
User: "Is this code secure?" followed by a code block
Action: Extract the code, call `mcp__scanner__scan_code` with the code and an appropriate filename.

**Full report:**
User: `/security-scan full`
Action: Run the default scan flow but display ALL severity levels in the output.

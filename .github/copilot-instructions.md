# Armis AppSec Scanner — Copilot Instructions

This project uses the Armis AppSec MCP server for AI-powered security scanning.

## Before Committing Code

Before running `git commit`, `git push`, or creating a pull request:

1. Call `scan_diff` with `staged=true` **and `repo_path` set to your repo's absolute path** to scan staged changes. Always pass `repo_path`: the MCP server is a long-lived process whose own working directory may be a different checkout than yours (in a git worktree it is often the main repo), so without `repo_path` the scan and its `.scan-pass` land in the wrong git dir and the commit gate never sees them.
2. If HIGH or CRITICAL findings are reported:
   - Attempt to fix them (move secrets to env vars, use parameterized queries, etc.)
   - Re-stage fixes and re-scan
   - If findings cannot be fixed, present them to the user and ask for explicit approval
   - Only call `approve_findings` after the user acknowledges the risk
3. If scan is clean (no HIGH/CRITICAL), proceed with the commit

## On-Demand Scanning

When the user asks to "scan", "security check", or "check for vulnerabilities":

| Scenario | Tool | Parameters |
|----------|------|------------|
| Staged/unstaged changes | `scan_diff` | `staged=true` or `ref=main`, plus `repo_path=/absolute/repo/path` |
| A specific file | `scan_file` | `file_path=/absolute/path` |
| Pasted code snippet | `scan_code` | `code="..."`, optional `filename` |
| Check scanner config | `debug_config` | (none) |

## Suppressing False Positives

Two ways to suppress a finding the team has reviewed and accepted. Both are deterministic
(no AI judgment) and apply to `scan_diff`, `scan_file`, and the git commit hook:

1. **Inline comment** — add `armis:ignore` in a comment on the finding's line (or the line
   above). Narrow it with `cwe:`, `severity:`, or `category:` (combined with AND logic), e.g.
   `password = os.environ["PW"]  # armis:ignore cwe:798 reason: loaded from env`. A bare
   `armis:ignore` suppresses any finding on that line.
2. **`.armisignore` file** at the repo root — `cwe:`, `severity:`, `category:` directives and
   path patterns, applied repo-wide.

Suppressed **CRITICAL** findings still block the commit and require `approve_findings`; suppressed
HIGH and below do not. Suggest suppression only for genuine false positives — never to bypass a
real vulnerability.

## Important Rules

- NEVER call `approve_findings` without explicit user consent
- Always scan BEFORE committing, not after
- If a scan fails (API error, timeout), inform the user but do not block their work

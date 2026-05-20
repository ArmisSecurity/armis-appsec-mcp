# Armis AppSec Scanner — Copilot Instructions

This project uses the Armis AppSec MCP server for AI-powered security scanning.

## Before Committing Code

Before running `git commit`, `git push`, or creating a pull request:

1. Call `scan_diff` with `staged=true` to scan staged changes
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
| Staged/unstaged changes | `scan_diff` | `staged=true` or `ref=main` |
| A specific file | `scan_file` | `file_path=/absolute/path` |
| Pasted code snippet | `scan_code` | `code="..."`, optional `filename` |
| Check scanner config | `debug_config` | (none) |

## Important Rules

- NEVER call `approve_findings` without explicit user consent
- Always scan BEFORE committing, not after
- If a scan fails (API error, timeout), inform the user but do not block their work

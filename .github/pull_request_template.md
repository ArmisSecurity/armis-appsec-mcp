## Related Issue

<!-- Link to Jira ticket or GitHub issue. Delete the one you don't use. -->

* [PPSC-XXXX](https://your-jira.atlassian.net/browse/PPSC-XXXX)
* Fixes #XXX

## Type of Change

* [ ] Bug fix (non-breaking change which fixes an issue)
* [ ] New feature (non-breaking change which adds functionality)
* [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
* [ ] Documentation update
* [ ] Refactoring (no functional changes)
* [ ] Performance improvement

## Problem

<!-- What problem does this PR solve? Why is this change needed? -->

## Solution

<!-- How does this PR solve the problem? What approach did you take? -->

## Testing

### Automated Tests

* [ ] Unit tests added/updated
* [ ] `make check` passes locally (format-check, lint, typecheck, test)

### Manual Testing

<!-- How did you verify this works? Steps to reproduce -->

## Areas Touched

<!-- Check all that apply. These are shared or load-bearing; see CLAUDE.md before changing them. -->

* [ ] Shared core (`scanner_core.py`, `auth.py`, `suppression.py`, `hash_utils.py`): affects both the MCP server and the hooks
* [ ] `.scan-pass` commit gate (`hooks/`, `hook_core.py`, `git-hooks/`)
* [ ] MCP tools or `skills/security-scan/SKILL.md`
* [ ] Auth, networking, or logging (`net_config`, `server_log`, `token_cache`)
* [ ] None of the above

## Reviewer Notes

<!-- Anything specific reviewers should focus on? -->
<!-- Any trade-offs, technical debt, or follow-up work? -->

## Checklist

* [ ] Code follows project style guidelines
* [ ] Pre-commit hooks pass
* [ ] Self-review performed
* [ ] Documentation updated (if needed)
* [ ] `CLAUDE.md` updated if architecture or invariants changed
* [ ] `AGENTS.md`, `.github/copilot-instructions.md`, and `.cursor/rules/security-scanning.mdc` kept in sync (if scan guidance changed)
* [ ] Breaking changes documented (if applicable)
* [ ] No new warnings generated
* [ ] No secrets, credentials, or customer data in code, logs, or test fixtures

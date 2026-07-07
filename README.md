# Armis AppSec MCP Plugin

AI-powered security scanning for [Claude Code](https://claude.ai/code), [Cursor](https://cursor.com), [VS Code](https://code.visualstudio.com) (GitHub Copilot), [Gemini CLI](https://github.com/google-gemini/gemini-cli), [GitHub Copilot CLI](https://docs.github.com/en/copilot), [Codex CLI](https://github.com/openai/codex), and [Cline](https://github.com/cline/cline). Scans code, files, and git diffs for vulnerabilities in real-time using the Armis scanning API.

## Features

- **`scan_code`** — Scan a code snippet for vulnerabilities
- **`scan_file`** — Scan a file on disk
- **`scan_diff`** — Scan git changes (staged, unstaged, or diff against a branch)
- **`approve_findings`** — Approve findings after user consent (for shipping with known risks)
- **`debug_config`** — Check scanner configuration status
- **Commit gate** — Git pre-commit hook that blocks commits until code is scanned
- **`/security-scan`** — Claude Code slash command for on-demand scanning

## Quick Setup (any client)

```bash
# 1. Clone the repository
git clone https://github.com/ArmisSecurity/armis-appsec-mcp.git
cd armis-appsec-mcp

# 2. Create credentials
cat > .env << 'EOF'
ARMIS_CLIENT_ID=<your-client-id>
ARMIS_CLIENT_SECRET=<your-client-secret>
EOF
chmod 600 .env

# 3. Generate config for your client
make setup CLIENT=cursor    # or: vscode, gemini, copilot
```

Contact the Armis AppSec team if you don't have credentials.

## Client Setup

### Cursor

Run `make setup CLIENT=cursor` and copy the output to `~/.cursor/mcp.json` (user-level) or `.cursor/mcp.json` (workspace-level).

Or manually add to your config:

```json
{
  "mcpServers": {
    "armis-scanner": {
      "command": "/path/to/armis-appsec-mcp/run.sh",
      "args": []
    }
  }
}
```

### VS Code (GitHub Copilot)

Run `make setup CLIENT=vscode` and copy the output to `.vscode/mcp.json` in your project.

Or manually add:

```json
{
  "servers": {
    "armis-scanner": {
      "type": "stdio",
      "command": "/path/to/armis-appsec-mcp/run.sh",
      "args": []
    }
  }
}
```

Enable MCP in VS Code settings if not already: `github.copilot.chat.mcp.enabled: true`.

### Gemini CLI

Run `make setup CLIENT=gemini` and copy the output to `~/.gemini/settings.json` (user-level) or `.gemini/settings.json` (project-level).

Or manually add the `mcpServers` block to your `settings.json`:

```json
{
  "mcpServers": {
    "armis-scanner": {
      "command": "/path/to/armis-appsec-mcp/run.sh",
      "args": []
    }
  }
}
```

### GitHub Copilot CLI

Run `make setup CLIENT=copilot` and copy the output to `.mcp.json` (workspace) or `~/.copilot/mcp-config.json` (user-level).

Copilot CLI requires both `command` and `args` fields. A config without `args` will be ignored.

### Codex CLI

Add the MCP server to your Codex CLI config per its documentation. Then wire in the commit gate hook:

```bash
make setup CLIENT=codex   # prints the hook config JSON
```

Merge the printed `hooks` block into your Codex CLI hooks config file (path varies by installation), replacing `/absolute/path/to/armis-appsec-mcp` with the actual clone path.

### Cline

Add the MCP server via Cline's MCP settings panel. Then wire in the commit gate hook:

```bash
make setup CLIENT=cline   # prints the hook config JSON
```

Merge the printed `hooks` block into your Cline `settings.json`, replacing `/absolute/path/to/armis-appsec-mcp` with the actual clone path.

### Claude Code (full integration)

Install via the plugin marketplace for the complete experience (hooks + slash command):

```
/plugin marketplace add ArmisSecurity/armis-appsec-mcp
/plugin install armis-appsec@armis-appsec-mcp
```

Then set credentials:

```bash
PLUGIN_DIR="$(ls -dt ~/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/*/ | head -1)"
cat > "$PLUGIN_DIR/.env" << 'EOF'
ARMIS_CLIENT_ID=<your-client-id>
ARMIS_CLIENT_SECRET=<your-client-secret>
EOF
chmod 600 "$PLUGIN_DIR/.env"
```

## Feature Comparison

| Feature | Claude Code | Cursor | VS Code | Gemini | Copilot CLI | Codex CLI | Cline |
|---------|------------|--------|---------|--------|-------------|-----------|-------|
| MCP tools (all 5) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Commit gate (hard) | Native hook | Native hook | Git hook | Native hook | Native hook | Native hook | Native hook |
| Commit gate (soft) | Native hook | .cursor/rules | instructions | AGENTS.md | — | AGENTS.md | — |
| /security-scan | Yes | — | — | — | — | — | — |

"Native hook" = PreToolUse hook wired into the client's tool pipeline (blocks the command before it runs, injects a scan instruction). "Git hook" = portable `pre-commit` script (installed via `make install-hooks`). VS Code is the only client without a native hook template.

## Optional: Git Pre-Commit Hook

For a client-agnostic commit gate that works regardless of which AI tool you use:

```bash
make install-hooks
```

This installs a git pre-commit hook that verifies the scan-pass (stored inside `.git/`, so it never clutters your working tree) before allowing commits. It fails **open** by default (plugin bugs never block developers). Set `APPSEC_HOOK_STRICT=1` for fail-closed behavior.

To remove: `make uninstall-hooks`

## Local Development

To test uncommitted changes from a clone end-to-end in Claude Code (or any client that loads the installed plugin), point the installed plugin at your working tree:

```bash
make dev-install     # backs up the installed plugin, symlinks it -> this repo
# ...restart Claude Code, then test...
make dev-uninstall   # restores the backed-up plugin exactly
make dev-status      # show whether dev mode is active
```

`dev-install` backs up the real plugin to `latest.bak`, symlinks `latest` to this repo, and copies the installed `.env` (credentials) over so the launcher's preflight still passes. **Restart Claude Code after each install/uninstall** — MCP servers launch at session start. Override the cache location with `PLUGIN_CACHE=...` if your plugins live elsewhere.

## Usage

### Scan staged changes (default)

```
/security-scan
```

Or ask your AI assistant: "scan staged changes for security issues"

### Scan a specific file

```
/security-scan path/to/file.py
```

### Scan diff against a branch

```
/security-scan ref=main
```

### Scan pasted code

Paste code into the conversation and ask:

```
Is this code secure?
```

### Commit gate behavior

When the git pre-commit hook is installed, or when using Claude Code's native hooks:

1. Blocks the command until code is scanned
2. The AI assistant scans the changes automatically
3. Allows the command after a clean scan (no HIGH/CRITICAL findings)

If HIGH/CRITICAL findings are found, the assistant will attempt to fix them. If findings remain after remediation, it asks for your approval before proceeding.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ARMIS_CLIENT_ID` | (required) | Client ID for authentication |
| `ARMIS_CLIENT_SECRET` | (required) | Client secret for authentication |
| `APPSEC_ENV` | `prod` | `dev` or `prod` — selects API endpoint |
| `APPSEC_API_URL` | (auto) | Override the API base URL |
| `APPSEC_DEBUG` | (unset) | Set to any value to enable debug logging |
| `APPSEC_TRANSPORT` | `stdio` | MCP transport (`stdio`, `sse`) |
| `APPSEC_HOOK_STRICT` | (unset) | Set to `1` for fail-closed git hook |

### SSE Transport (shared server)

For teams that want a single shared scanner instance:

```bash
APPSEC_TRANSPORT=sse ./run.sh
```

Then configure clients to connect via HTTP instead of launching a local process.

## Platform Support

Requires macOS or Linux. On Windows, use WSL2.

## Running Tests

```bash
make check          # full CI gate (format + lint + typecheck + test)
make test           # pytest only
pytest hooks/tests/test_pre_commit_scan.py -v  # specific test file
```

## Architecture

```
              +---------------------+
              |  Armis Cloud        |
              |  POST /scan/fast    |
              +--------+------------+
                       ^
                       | HTTPS (JWT Bearer)
              +--------+------------+
              |   Scanner Core       |
              |  scanner_core.py     |
              +--------+------------+
                 +-----+------+
                 |            |
           +-----v-----+ +---v---------+
           | MCP Server | | Git Hook    |
           | server.py  | | git-hooks/  |
           +------------+ +-------------+
                 |
    +------------+-------------+
    |            |             |
  Claude     Cursor      VS Code/
  Code       Gemini      Copilot
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

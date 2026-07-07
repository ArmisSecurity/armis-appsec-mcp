.PHONY: lint format format-check typecheck test check clean install-hooks uninstall-hooks setup dev-install dev-uninstall dev-status

# Where Claude Code installs this plugin. Override if your cache lives elsewhere.
PLUGIN_CACHE ?= $(HOME)/.claude/plugins/cache/armis-appsec-mcp/armis-appsec

lint:
	ruff check . --fix

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy . --exclude '.venv|__pycache__|hooks/tests'

test:
	pytest --cov --cov-report=term-missing

check: format-check lint typecheck test

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

install-hooks:
	@test -d .git || { echo "ERROR: not a git repository. Run from the repo root." >&2; exit 1; }
	@mkdir -p .git/hooks
	@ln -sf ../../git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x git-hooks/pre-commit
	@echo "Pre-commit hook installed (fail-open). Set APPSEC_HOOK_STRICT=1 for strict mode."

uninstall-hooks:
	@rm -f .git/hooks/pre-commit
	@echo "Pre-commit hook removed."

# ---------------------------------------------------------------------------
# Local dev: point the installed plugin at THIS working tree so you can test
# uncommitted changes end-to-end in Claude Code (and any other client).
#
# `dev-install` backs up the real installed plugin to `latest.bak`, symlinks
# `latest` -> this repo, and copies the existing .env (credentials) in so
# run.sh's preflight still passes. `dev-uninstall` reverses it exactly.
#
# A Claude Code RESTART is required after each of these (MCP servers launch at
# session start), so the swapped code is only picked up on the next session.
# ---------------------------------------------------------------------------
dev-install:
	@test -f .claude-plugin/plugin.json || test -d .claude-plugin || { echo "ERROR: run from the plugin repo root (no .claude-plugin here)." >&2; exit 1; }
	@test -e "$(PLUGIN_CACHE)" || { echo "ERROR: plugin cache not found at $(PLUGIN_CACHE). Install the plugin first (/plugin install armis-appsec@armis-appsec-mcp), or set PLUGIN_CACHE=..." >&2; exit 1; }
	@REPO="$$(pwd)"; \
	if [ -L "$(PLUGIN_CACHE)/latest" ]; then \
		echo "ERROR: $(PLUGIN_CACHE)/latest is already a symlink -> $$(readlink "$(PLUGIN_CACHE)/latest"). Run 'make dev-uninstall' first." >&2; exit 1; \
	fi; \
	if [ -e "$(PLUGIN_CACHE)/latest.bak" ]; then \
		echo "ERROR: $(PLUGIN_CACHE)/latest.bak already exists — a previous dev-install wasn't reverted. Run 'make dev-uninstall' first." >&2; exit 1; \
	fi; \
	mv "$(PLUGIN_CACHE)/latest" "$(PLUGIN_CACHE)/latest.bak" || { echo "ERROR: could not back up the installed plugin." >&2; exit 1; }; \
	if [ -f "$(PLUGIN_CACHE)/latest.bak/.env" ] && [ ! -f "$$REPO/.env" ]; then \
		cp "$(PLUGIN_CACHE)/latest.bak/.env" "$$REPO/.env" && chmod 600 "$$REPO/.env" && echo "Copied .env (credentials) from the installed plugin."; \
	fi; \
	ln -s "$$REPO" "$(PLUGIN_CACHE)/latest" || { echo "ERROR: symlink failed; restoring backup." >&2; mv "$(PLUGIN_CACHE)/latest.bak" "$(PLUGIN_CACHE)/latest"; exit 1; }; \
	echo "Dev plugin linked: $(PLUGIN_CACHE)/latest -> $$REPO"; \
	echo "RESTART Claude Code to load it. Revert with 'make dev-uninstall'."

dev-uninstall:
	@if [ ! -L "$(PLUGIN_CACHE)/latest" ]; then \
		echo "Nothing to revert: $(PLUGIN_CACHE)/latest is not a dev symlink."; \
		[ -e "$(PLUGIN_CACHE)/latest.bak" ] && echo "NOTE: a stray $(PLUGIN_CACHE)/latest.bak exists — inspect it manually." || true; \
	elif [ ! -e "$(PLUGIN_CACHE)/latest.bak" ]; then \
		echo "ERROR: $(PLUGIN_CACHE)/latest is a symlink but no latest.bak to restore. Remove the symlink and reinstall the plugin." >&2; exit 1; \
	else \
		rm "$(PLUGIN_CACHE)/latest" && \
		mv "$(PLUGIN_CACHE)/latest.bak" "$(PLUGIN_CACHE)/latest" && \
		echo "Reverted: $(PLUGIN_CACHE)/latest restored from backup. RESTART Claude Code."; \
	fi

dev-status:
	@if [ -L "$(PLUGIN_CACHE)/latest" ]; then \
		echo "DEV MODE: $(PLUGIN_CACHE)/latest -> $$(readlink "$(PLUGIN_CACHE)/latest")"; \
		test -e "$(PLUGIN_CACHE)/latest.bak" && echo "Backup present: $(PLUGIN_CACHE)/latest.bak" || echo "WARNING: no latest.bak backup found."; \
	elif [ -e "$(PLUGIN_CACHE)/latest" ]; then \
		echo "NORMAL: $(PLUGIN_CACHE)/latest is the installed plugin (not a dev symlink)."; \
	else \
		echo "Plugin not installed at $(PLUGIN_CACHE)/latest."; \
	fi

setup:
	@test -n "$(CLIENT)" || { echo "Usage: make setup CLIENT=cursor|vscode|gemini|copilot|codex|cline"; exit 1; }
	@case "$(CLIENT)" in cursor|vscode|gemini|copilot|codex|cline) ;; *) echo "ERROR: Unknown CLIENT '$(CLIENT)'. Valid: cursor, vscode, gemini, copilot, codex, cline" >&2; exit 1;; esac
	@PLUGIN_DIR=$$(pwd) && \
	TEMPLATE="config-templates/$(CLIENT).mcp.json" && \
	[ ! -f "$$TEMPLATE" ] && TEMPLATE="config-templates/$(CLIENT)-cli.mcp.json"; \
	echo "=== MCP Server Config ===" && \
	sed "s|/absolute/path/to/armis-appsec-mcp|$$PLUGIN_DIR|g" "$$TEMPLATE" && \
	HOOKS_TEMPLATE="config-templates/$(CLIENT).hooks.json" && \
	if [ -f "$$HOOKS_TEMPLATE" ]; then \
		echo "" && echo "=== Hook Config (commit gate) ===" && \
		sed "s|/absolute/path/to/armis-appsec-mcp|$$PLUGIN_DIR|g" "$$HOOKS_TEMPLATE"; \
	fi
	@echo ""
	@echo "Copy the above JSON to your client config files."

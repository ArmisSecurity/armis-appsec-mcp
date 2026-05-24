.PHONY: lint format format-check typecheck test check clean install-hooks uninstall-hooks setup

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

setup:
	@test -n "$(CLIENT)" || { echo "Usage: make setup CLIENT=cursor|vscode|gemini|copilot"; exit 1; }
	@case "$(CLIENT)" in cursor|vscode|gemini|copilot) ;; *) echo "ERROR: Unknown CLIENT '$(CLIENT)'. Valid: cursor, vscode, gemini, copilot" >&2; exit 1;; esac
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

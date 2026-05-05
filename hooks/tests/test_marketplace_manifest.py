"""Tests for marketplace manifest safety and installability."""

import json
from pathlib import Path


def test_relative_plugin_sources_stay_within_marketplace_root():
    """Relative plugin sources must not escape the marketplace root."""
    repo_root = Path(__file__).resolve().parents[2]
    marketplace_path = repo_root / ".claude-plugin" / "marketplace.json"
    manifest = json.loads(marketplace_path.read_text())

    metadata = manifest.get("metadata", {})
    source_base = metadata.get("pluginRoot", ".")
    marketplace_root = repo_root.resolve()

    for plugin in manifest["plugins"]:
        source = plugin["source"]
        if not isinstance(source, str) or not source.startswith("./"):
            continue

        # pluginRoot is relative to the manifest directory (.claude-plugin/)
        resolved_source = (marketplace_path.parent / source_base / source).resolve()
        assert resolved_source.is_relative_to(marketplace_root), (
            f"Plugin source escapes marketplace root: {plugin['name']} -> {source_base}/{source}"
        )

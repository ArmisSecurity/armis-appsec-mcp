"""Imported module: properly sanitizes input before rendering."""

import html


def safe_render(user_content):
    escaped = html.escape(user_content)
    return f"<div class='comment'>{escaped}</div>"

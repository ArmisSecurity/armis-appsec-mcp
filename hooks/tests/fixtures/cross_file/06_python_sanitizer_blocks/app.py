"""Negative case: sanitizer properly blocks the taint flow.
This should NOT produce a finding because html.escape sanitizes the input."""

from .sanitize import safe_render


def handle_comment(request):
    comment = request.form["comment"]
    safe_html = safe_render(comment)
    return safe_html

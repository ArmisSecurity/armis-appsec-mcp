"""Shipping rules for the commit gate, shared by server.scan_diff and git-hooks/scan-staged.py.

Both writers of the scan-pass must agree on what earns one, otherwise a diff
that ``scan_diff`` refuses to vouch for can still pass the gate through the
portable git hook. Keep the rules here, not in either caller:

- the diff handed to the scanner (``--diff-filter=d``, 10 context lines),
- the 90K-char cap and what a truncated diff may do (nothing, or approval-only
  mid-merge),
- which findings block a pass, and writing / removing the pass accordingly.
"""

import os
from collections.abc import Callable

from hash_utils import (
    cleanup_legacy_scan_pass,
    compute_staged_hash,
    merge_or_rebase_in_progress,
    resolve_scan_pass_path,
)

MAX_CODE_CHARS = 90_000

# Deleted files are not scanned (nothing to find in removed code), so a
# deletion-only diff is empty here and earns no pass. The staged *hash* still
# covers the full ``git diff --cached``.
DIFF_FILTER_ARGS = ("--diff-filter=d", "--no-ext-diff")
DIFF_CONTEXT_LINES = 10


def clip_diff(diff_text: str, limit: int = MAX_CODE_CHARS) -> tuple[str, bool]:
    """Return ``(diff_text, truncated)``, clipping to ``limit`` chars."""
    if len(diff_text) > limit:
        return diff_text[:limit], True
    return diff_text, False


def shipping_decision(
    ref: str, staged: bool, truncated: bool, scan_repo: str | None
) -> tuple[bool, bool]:
    """Decide ``(is_shipping_scan, require_approval)`` for a diff scan.

    Both staged and ref-based scans are shipping-eligible so they can write the
    scan-pass (fixes push/PR gate loop). BUT a truncated diff means the scanner
    saw less than the scan-pass hash vouches for, so it is NOT shipping-eligible.

    EXCEPTION: a merge/rebase in progress. Its staged diff is mostly
    already-landed, CI-scanned upstream code; blunt refusal would leave no
    in-band escape. A truncated mid-merge diff stays shipping-eligible but
    ``require_approval`` is set, so the scan-pass is never auto-written — only an
    explicit human ``approve_findings`` gets through.
    """
    shipping_kind = bool(ref) or staged
    merge_in_progress = truncated and shipping_kind and merge_or_rebase_in_progress(scan_repo)
    is_shipping_scan = shipping_kind and (not truncated or merge_in_progress)
    return is_shipping_scan, merge_in_progress


def blocks_scan_pass(findings: list[dict], suppressed: list[dict] | None) -> bool:
    """True if these results must not earn a scan-pass.

    Any active HIGH/CRITICAL blocks. Suppressed CRITICAL (``.armisignore`` or
    inline) also blocks — it needs an explicit ``approve_findings``. Suppressed
    HIGH does not: ``.armisignore`` is a deliberate team risk decision.
    """
    if any((f.get("severity") or "").upper() in ("CRITICAL", "HIGH") for f in findings):
        return True
    return any((f.get("severity") or "").upper() == "CRITICAL" for f in (suppressed or []))


def write_or_clear_scan_pass(
    findings: list[dict],
    suppressed: list[dict] | None,
    *,
    scan_hash: str,
    repo_path: str | None,
    require_approval: bool = False,
    pass_path: Callable[[str | None], str] = resolve_scan_pass_path,
    cleanup_legacy: Callable[[str | None], None] = cleanup_legacy_scan_pass,
    hash_fn: Callable[[str | None], str] = compute_staged_hash,
) -> None:
    """Write the scan-pass for a clean shipping scan, remove it otherwise.

    Callers invoke this only for shipping scans. ``require_approval`` never
    auto-writes: the stale pass is removed and a human must approve. The
    resolver arguments exist so server.py can pass its own module-level names
    (which its tests redirect).
    """
    path = pass_path(repo_path)
    cleanup_legacy(repo_path)  # remove any stale working-tree .scan-pass
    try:
        if not require_approval and not blocks_scan_pass(findings, suppressed):
            effective_hash = scan_hash or hash_fn(repo_path)
            if effective_hash:
                with open(path, "w") as f:
                    f.write(effective_hash)
        elif os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass

"""End-to-end smoke test of the installed-plugin path, no credentials needed.

Runs what a Claude Code user on Windows/Git Bash actually runs:

1. ``bash run.sh`` bootstraps the venv and starts the MCP server over stdio.
2. The PreToolUse Bash hook (the exact command from ``hooks/hooks.json``)
   denies ``git commit`` and names the ``scan_diff(...)`` call to make.
3. That call goes through the MCP server to a local stub API (auth + clean
   scan), which writes the scan-pass.
4. The hook now allows the commit, and denies it again once the index changes.
5. The Write guard denies forging the scan-pass.

The server is launched from a different CWD than the repo being committed,
which is the Conductor/worktree layout the ``repo_path`` handshake exists for.

Usage: python .github/scripts/smoke_e2e.py [--plugin-dir DIR]
Stdlib only, so it runs before (and independent of) the plugin's venv.
"""

import argparse
import ast
import base64
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, NoReturn

EXPECTED_TOOLS = {
    "scan_code",
    "scan_file",
    "scan_files",
    "scan_diff",
    "approve_findings",
    "debug_config",
}
LF_ONLY = ["run.sh", "git-hooks/pre-commit"]


def log(msg: str) -> None:
    print(f"[smoke] {msg}", flush=True)


def fail(msg: str) -> NoReturn:
    print(f"[smoke] FAIL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Stub AppSec API
# ---------------------------------------------------------------------------


def _fake_jwt() -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    # armis:ignore cwe:327 cwe:347 reason: unsigned token for the localhost stub API only
    return f"{b64({'alg': 'none'})}.{b64({'exp': int(time.time()) + 3600})}.sig"


class StubAPI(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        StubAPI.hits.append(self.path)
        if self.path.endswith("/auth/token"):
            body = {"token": _fake_jwt()}
        elif self.path.endswith("/scan/fast"):
            body = {"raw_response": "```json\n[]\n```"}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args) -> None:
        pass


# ---------------------------------------------------------------------------
# MCP stdio client
# ---------------------------------------------------------------------------


class MCPClient:
    """Newline-delimited JSON-RPC over the server's stdio.

    Reads on a thread: Windows pipes can't be select()ed, and a hang is
    exactly what this test must report rather than inherit.
    """

    def __init__(self, proc: subprocess.Popen):
        assert proc.stdin and proc.stdout
        self.proc = proc
        self.stdin: IO[str] = proc.stdin
        self.stdout: IO[str] = proc.stdout
        self.next_id = 0
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict, timeout: float) -> dict:
        self.next_id += 1
        rid = self.next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"{method} got no response within {timeout:.0f}s (server hung?)")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                fail(f"server exited (code {self.proc.poll()}) while waiting for {method}")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                fail(f"non-JSON on server stdout (stdout must be the MCP channel): {line!r}")
            if msg.get("id") == rid:
                if "error" in msg:
                    fail(f"{method} returned JSON-RPC error: {msg['error']}")
                return msg["result"]

    def call_tool(self, name: str, args: dict, timeout: float = 120) -> str:
        result = self.request("tools/call", {"name": name, "arguments": args}, timeout)
        text = "".join(c.get("text", "") for c in result.get("content", []))
        if result.get("isError"):
            fail(f"{name} returned a tool error: {text}")
        return text

    def _send(self, msg: dict) -> None:
        self.stdin.write(json.dumps(msg) + "\n")
        self.stdin.flush()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(root: Path) -> Path:
    repo = root / "repo with space"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "ci@example.com")
    git(repo, "config", "user.name", "CI")
    (repo / "README.md").write_text("smoke\n")
    git(repo, "add", "README.md")
    git(repo, "commit", "-q", "-m", "init")
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
    git(repo, "add", "app.py")
    return repo


def hook_command(plugin_dir: Path, matcher: str) -> str:
    manifest = json.loads((plugin_dir / "hooks" / "hooks.json").read_text())
    for entry in manifest["hooks"]["PreToolUse"]:
        if entry["matcher"] == matcher:
            return entry["hooks"][0]["command"]
    fail(f"no {matcher} hook in hooks.json")


def run_hook(bash: str, plugin_dir: Path, matcher: str, payload: dict, cwd: Path):
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(plugin_dir)}
    return subprocess.run(
        # armis:ignore cwe:78 cwe:77 reason: runs this repo's own hooks.json command
        [bash, "-c", hook_command(plugin_dir, matcher)],
        input=json.dumps(payload),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def commit_hook(bash: str, plugin_dir: Path, repo: Path):
    payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -m smoke"}}
    return run_hook(bash, plugin_dir, "Bash", payload, repo)


def scan_diff_args(deny_stderr: str) -> dict:
    """Pull the scan_diff(...) call the hook told the agent to make."""
    match = re.search(r"scan_diff\(([^)]*)\)", deny_stderr)
    if not match:
        fail(f"hook deny message has no scan_diff(...) call: {deny_stderr}")
    call = ast.parse(f"f({match.group(1)})", mode="eval").body
    assert isinstance(call, ast.Call)
    return {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def check_line_endings(plugin_dir: Path) -> None:
    for rel in LF_ONLY:
        if b"\r\n" in (plugin_dir / rel).read_bytes():
            fail(f"{rel} has CRLF line endings; bash will fail on it ('$'\\r': command not found')")
    log(f"line endings OK: {', '.join(LF_ONLY)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-dir", default=Path(__file__).resolve().parents[2], type=Path)
    plugin_dir = parser.parse_args().plugin_dir.resolve()

    bash = shutil.which("bash")
    if not bash:
        fail("bash not on PATH")
    log(f"bash: {bash}")
    log(f"plugin dir: {plugin_dir}")

    check_line_endings(plugin_dir)

    api = ThreadingHTTPServer(("127.0.0.1", 0), StubAPI)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    api_url = f"http://127.0.0.1:{api.server_address[1]}"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = make_repo(root)
        server_cwd = root / "elsewhere"
        server_cwd.mkdir()

        # 1. Gate denies the unscanned commit and names the scan to run.
        denied = commit_hook(bash, plugin_dir, repo)
        if denied.returncode != 2 or '"deny"' not in denied.stderr:
            fail(f"hook did not deny unscanned commit: rc={denied.returncode} {denied.stderr!r}")
        args = scan_diff_args(denied.stderr)
        log(f"hook denied unscanned commit, asked for scan_diff({args})")
        if not args.get("repo_path"):
            fail("hook did not inject repo_path into the scan_diff call")

        # 2. Start the server exactly as the plugin manifest does: bash run.sh.
        env = {
            **os.environ,
            "ARMIS_CLIENT_ID": "ci-smoke",
            # armis:ignore cwe:798 cwe:259 reason: dummy value, only the localhost stub reads it
            "ARMIS_CLIENT_SECRET": "ci-smoke",
            "APPSEC_API_URL": api_url,
            "APPSEC_SCAN_TIMEOUT": "60",
            "CLAUDE_PLUGIN_ROOT": str(plugin_dir),
            "PYTHONUTF8": "1",
        }
        env.pop("ARMIS_DEFAULT_AUTH_METHOD", None)
        proc = subprocess.Popen(
            [bash, str(plugin_dir / "run.sh")],
            cwd=server_cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            encoding="utf-8",
        )
        mcp = MCPClient(proc)
        try:
            t0 = time.monotonic()
            init = mcp.request(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "ci-smoke", "version": "0"},
                },
                timeout=600,  # first run.sh call creates the venv and pip-installs
            )
            mcp.notify("notifications/initialized")
            log(f"initialized {init['serverInfo']} in {time.monotonic() - t0:.1f}s")

            tools = {t["name"] for t in mcp.request("tools/list", {}, timeout=30)["tools"]}
            if missing := EXPECTED_TOOLS - tools:
                fail(f"tools/list missing {sorted(missing)}; got {sorted(tools)}")
            log(f"tools/list OK ({len(tools)} tools)")

            mcp.call_tool("debug_config", {}, timeout=30)
            log("debug_config OK")

            # 3. The scan the hook asked for, via the server, against the stub.
            report = mcp.call_tool("scan_diff", args)
            if "/scan/fast" not in " ".join(StubAPI.hits):
                fail(f"scan_diff never reached the scan API; stub hits={StubAPI.hits}")
            log(f"scan_diff OK: {report.splitlines()[0] if report else '(empty)'}")
        finally:
            mcp.stdin.close()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
            api.shutdown()

        # 4. Gate allows the scanned commit.
        allowed = commit_hook(bash, plugin_dir, repo)
        if allowed.returncode != 0:
            fail(f"hook still denies after a clean scan: rc={allowed.returncode} {allowed.stderr}")
        log("hook allowed scanned commit")

        # 5. Gate denies once the index changes after the scan.
        (repo / "app.py").write_text("import os\nos.system(input())\n")
        git(repo, "add", "app.py")
        stale = commit_hook(bash, plugin_dir, repo)
        if stale.returncode != 2:
            fail(f"hook allowed a commit whose index changed after the scan: {stale.stderr!r}")
        log("hook denied stale scan-pass")

        # 6. Write guard denies forging the scan-pass.
        scan_pass = Path(git(repo, "rev-parse", "--absolute-git-dir")) / "armis-scan-pass"
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(scan_pass)}}
        forged = run_hook(bash, plugin_dir, "Write", payload, repo)
        if forged.returncode != 2:
            fail(f"Write guard allowed writing {scan_pass}: {forged.stderr!r}")
        log("Write guard denied scan-pass forgery")

    log("PASS")


if __name__ == "__main__":
    main()

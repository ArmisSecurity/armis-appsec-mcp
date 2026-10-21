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

The plugin is copied into a temp dir first (as the installed plugin cache is),
so run.sh's venv rebuild and the server log never touch the source checkout,
and its ``.env`` is left behind.

Usage: python .github/scripts/smoke_e2e.py [--plugin-dir DIR] [--log-dir DIR]
Stdlib only, so it runs before (and independent of) the plugin's venv.
"""

import argparse
import ast
import base64
import json
import os
import queue
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
# Not copied into the temp plugin dir: local state that must not leak into the run.
COPY_IGNORE = (".git", ".venv", ".env", "logs", "__pycache__", "*_cache", "*.egg-info")
LOOPBACK = "127.0.0.1,localhost"


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
            if "method" in msg:
                if "id" in msg:
                    self._reply_to_server_request(msg)
                continue
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

    def _reply_to_server_request(self, msg: dict) -> None:
        reply: dict = {"jsonrpc": "2.0", "id": msg["id"]}
        if msg["method"] == "ping":
            reply["result"] = {}
        else:
            reply["error"] = {"code": -32601, "message": "not supported by smoke client"}
        self._send(reply)

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
    # Space and parens, as in "Program Files (x86)": the scan_diff(...) call the
    # hook builds must survive them.
    repo = root / "repo (smoke) with space"
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


def hook_entry(plugin_dir: Path, matcher: str) -> tuple[str, float]:
    """The hook's command and the timeout (seconds) Claude Code enforces on it."""
    manifest = json.loads((plugin_dir / "hooks" / "hooks.json").read_text())
    for entry in manifest["hooks"]["PreToolUse"]:
        if entry["matcher"] == matcher:
            hook = entry["hooks"][0]
            return hook["command"], hook.get("timeout", 60)
    fail(f"no {matcher} hook in hooks.json")


def run_hook(bash: str, plugin_dir: Path, matcher: str, payload: dict, cwd: Path):
    command, timeout = hook_entry(plugin_dir, matcher)
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(plugin_dir)}
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            # armis:ignore cwe:78 cwe:77 reason: runs this repo's own hooks.json command
            [bash, "-c", command],
            input=json.dumps(payload),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # Claude Code treats a timed-out hook as a non-blocking error, so the
        # tool call goes through: a slow gate is an open gate.
        fail(f"{matcher} hook exceeded its {timeout}s hooks.json timeout")
    log(f"{matcher} hook took {time.monotonic() - t0:.1f}s (limit {timeout}s)")
    return result


def commit_hook(bash: str, plugin_dir: Path, repo: Path):
    payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -m smoke"}}
    return run_hook(bash, plugin_dir, "Bash", payload, repo)


def scan_diff_args(deny_stderr: str) -> dict:
    """Pull the scan_diff(...) call the hook told the agent to make.

    Parsed from the decoded systemMessage (the text the agent sees), taking the
    shortest prefix from ``scan_diff(`` that parses, so a ``)`` inside a quoted
    path doesn't end the call early.
    """
    try:
        message = json.loads(deny_stderr)["systemMessage"]
    except (json.JSONDecodeError, KeyError, TypeError):
        fail(f"hook deny output is not JSON with a systemMessage: {deny_stderr!r}")
    start = message.find("scan_diff(")
    end = start
    while start >= 0 and (end := message.find(")", end + 1)) >= 0:
        try:
            call = ast.parse(message[start : end + 1], mode="eval").body
        except SyntaxError:
            continue
        if isinstance(call, ast.Call):
            return {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords}
    fail(f"hook deny message has no parseable scan_diff(...) call: {message}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def check_line_endings(plugin_dir: Path) -> None:
    """Every file .gitattributes pins to eol=lf must be LF in the working tree."""
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--eol", "-z"],
            cwd=plugin_dir,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        log("line endings: skipped (plugin dir is not a git checkout)")
        return
    # Each entry: "i/<eol> w/<eol> attr/<attrs>\t<path>"
    lf_only = [
        path
        for info, _, path in (e.partition("\t") for e in listing.split("\0") if e)
        if "eol=lf" in info
    ]
    if "run.sh" not in lf_only:
        fail(f"run.sh is not pinned to eol=lf by .gitattributes; pinned: {lf_only}")
    for rel in lf_only:
        if b"\r\n" in (plugin_dir / rel).read_bytes():
            fail(f"{rel} has CRLF line endings; bash will fail on it ('$'\\r': command not found)")
    log(f"line endings OK: {', '.join(lf_only)}")


def server_env(plugin_dir: Path, api_url: str) -> dict[str, str]:
    env = {
        **os.environ,
        # armis:ignore cwe:798 cwe:259 reason: dummy value, only the localhost stub reads it
        "ARMIS_CLIENT_ID": "ci-smoke",
        # armis:ignore cwe:798 cwe:259 reason: dummy value, only the localhost stub reads it
        "ARMIS_CLIENT_SECRET": "ci-smoke",
        # Empty rather than unset: load_dotenv(override=False) would fill an
        # unset key from a .env and could switch auth away from the stub.
        "ARMIS_DEFAULT_AUTH_METHOD": "",
        "APPSEC_API_URL": api_url,
        "APPSEC_SCAN_TIMEOUT": "60",
        "CLAUDE_PLUGIN_ROOT": str(plugin_dir),
        "PYTHONUTF8": "1",
    }
    # Keep any proxy for run.sh's pip install, but never for the loopback stub.
    # urllib prefers lowercase no_proxy when both are set, so set both.
    for key in ("NO_PROXY", "no_proxy"):
        current = env.get(key)
        env[key] = f"{current},{LOOPBACK}" if current else LOOPBACK
    return env


def stop_server(proc: subprocess.Popen) -> None:
    try:
        proc.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    if sys.platform == "win32":
        # MSYS bash's exec of a native python.exe spawns a child rather than
        # replacing bash, so killing bash alone orphans the server.
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False
        )
    else:
        proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        log(f"server pid {proc.pid} did not exit after kill")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--plugin-dir",
        default=Path(__file__).resolve().parents[2],
        type=Path,
        help="plugin source to copy and test (default: this checkout)",
    )
    parser.add_argument(
        "--log-dir", type=Path, help="copy the server's logs/ here when done (for CI artifacts)"
    )
    opts = parser.parse_args()
    source_dir = opts.plugin_dir.resolve()

    bash = shutil.which("bash")
    if not bash:
        fail("bash not on PATH")
    log(f"bash: {bash}")
    log(f"plugin source: {source_dir}")

    check_line_endings(source_dir)

    api = ThreadingHTTPServer(("127.0.0.1", 0), StubAPI)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    api_url = f"http://127.0.0.1:{api.server_address[1]}"

    # ignore_cleanup_errors: a server that survived stop_server still holds
    # files open on Windows; don't let the cleanup traceback hide the result.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        plugin_dir = root / "plugin"
        shutil.copytree(source_dir, plugin_dir, ignore=shutil.ignore_patterns(*COPY_IGNORE))
        try:
            run_smoke(bash, plugin_dir, root, api_url)
        finally:
            api.shutdown()
            if opts.log_dir and (plugin_dir / "logs").is_dir():
                shutil.copytree(plugin_dir / "logs", opts.log_dir, dirs_exist_ok=True)

    log("PASS")


def run_smoke(bash: str, plugin_dir: Path, root: Path, api_url: str) -> None:
    repo = make_repo(root)
    server_cwd = root / "elsewhere"
    server_cwd.mkdir()

    # 1. Gate denies the unscanned commit and names the scan to run.
    denied = commit_hook(bash, plugin_dir, repo)
    if denied.returncode != 2 or '"deny"' not in denied.stderr:
        fail(f"hook did not deny unscanned commit: rc={denied.returncode} {denied.stderr!r}")
    args = scan_diff_args(denied.stderr)
    log(f"hook denied unscanned commit, asked for scan_diff({args})")
    repo_path = args.get("repo_path")
    if not repo_path:
        fail("hook did not inject repo_path into the scan_diff call")
    if not os.path.isdir(repo_path) or not os.path.samefile(repo_path, repo):
        fail(f"scan_diff repo_path {repo_path!r} is not the committing repo {str(repo)!r}")

    # 2. Start the server exactly as the plugin manifest does: bash run.sh.
    proc = subprocess.Popen(
        [bash, str(plugin_dir / "run.sh")],
        cwd=server_cwd,
        env=server_env(plugin_dir, api_url),
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
        stop_server(proc)

    # 4. Gate allows the scanned commit. The hook also exits 0 when it fails
    #    open on an internal error, so that has to be ruled out separately.
    allowed = commit_hook(bash, plugin_dir, repo)
    if allowed.returncode != 0:
        fail(f"hook still denies after a clean scan: rc={allowed.returncode} {allowed.stderr}")
    if "fail-open" in allowed.stderr:
        fail(f"hook allowed the commit only by failing open: {allowed.stderr!r}")
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


if __name__ == "__main__":
    main()

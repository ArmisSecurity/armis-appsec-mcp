"""run.sh credential preflight: a pure-SSO user (no client creds, no .env) must start.

The venv is stubbed (a shell script standing in for python) and the deps sentinel
pre-seeded, so run.sh skips the pip install and `exec`s the stub instead of the
real server.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import sys

import pytest

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


@pytest.fixture
def plugin_dir(tmp_path):
    d = tmp_path / "plugin"
    (d / ".venv" / "bin").mkdir(parents=True)
    shutil.copy(os.path.join(_PLUGIN_ROOT, "run.sh"), d / "run.sh")
    reqs = d / "requirements.txt"
    reqs.write_text("httpx==0.28.1\n")
    (d / ".venv" / ".deps-installed").write_text(
        hashlib.sha256(reqs.read_bytes()).hexdigest() + "\n"
    )
    stub = d / ".venv" / "bin" / "python"
    stub.write_text('#!/bin/sh\n[ "$1" = -c ] && exit 0\necho SERVER-STARTED\n')
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return d


def _run(plugin_dir, env_extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ARMIS_", "APPSEC_"))}
    env.update(env_extra or {})
    return subprocess.run(
        ["bash", str(plugin_dir / "run.sh")],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def test_no_credentials_no_env_file_starts(plugin_dir):
    """Pure SSO: neither client credential nor .env."""
    r = _run(plugin_dir)
    assert r.returncode == 0, r.stderr
    assert "SERVER-STARTED" in r.stdout


def test_both_in_env_starts(plugin_dir):
    r = _run(plugin_dir, {"ARMIS_CLIENT_ID": "i", "ARMIS_CLIENT_SECRET": "s"})
    assert r.returncode == 0, r.stderr
    assert "SERVER-STARTED" in r.stdout


def test_both_in_dotenv_starts(plugin_dir):
    (plugin_dir / ".env").write_text("ARMIS_CLIENT_ID=i\nARMIS_CLIENT_SECRET=s\n")
    r = _run(plugin_dir)
    assert r.returncode == 0, r.stderr


def test_dotenv_without_credentials_starts(plugin_dir):
    (plugin_dir / ".env").write_text("ARMIS_TENANT_ID=t\n")
    r = _run(plugin_dir)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize(
    ("env", "dotenv", "missing"),
    [
        ({"ARMIS_CLIENT_ID": "i"}, "", "ARMIS_CLIENT_SECRET"),
        ({"ARMIS_CLIENT_SECRET": "s"}, "", "ARMIS_CLIENT_ID"),
        ({}, "ARMIS_CLIENT_ID=i\n", "ARMIS_CLIENT_SECRET"),
        ({"ARMIS_CLIENT_SECRET": "s"}, "ARMIS_TENANT_ID=t\n", "ARMIS_CLIENT_ID"),
    ],
)
def test_half_configured_credentials_fail(plugin_dir, env, dotenv, missing):
    if dotenv:
        (plugin_dir / ".env").write_text(dotenv)
    r = _run(plugin_dir, env)
    assert r.returncode == 1
    assert missing in r.stderr
    assert "SERVER-STARTED" not in r.stdout


def test_sso_opt_in_skips_preflight_even_when_half_configured(plugin_dir):
    r = _run(plugin_dir, {"ARMIS_CLIENT_ID": "i", "ARMIS_DEFAULT_AUTH_METHOD": "SSO"})
    assert r.returncode == 0, r.stderr


def test_sso_opt_in_from_dotenv(plugin_dir):
    (plugin_dir / ".env").write_text('ARMIS_CLIENT_ID=i\nARMIS_DEFAULT_AUTH_METHOD="sso"\n')
    r = _run(plugin_dir)
    assert r.returncode == 0, r.stderr


def _isolated_path(tmp_path, python_names):
    """A PATH holding only the tools run.sh needs, plus stub interpreters."""
    bin_dir = tmp_path / "isolated-bin"
    bin_dir.mkdir()
    for tool in ("dirname", "cat", "grep", "cut", "tr", "sha256sum", "shasum"):
        found = shutil.which(tool)
        if found:
            (bin_dir / tool).symlink_to(found)
    for name, code in python_names.items():
        stub = bin_dir / name
        stub.write_text(f"#!/bin/sh\nexit {code}\n")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return str(bin_dir)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only stubs")
def test_non_running_interpreter_is_not_chosen(plugin_dir, tmp_path):
    """The Microsoft Store python3 stub is on PATH but exits non-zero."""
    path = _isolated_path(tmp_path, {"python3": 49})
    r = subprocess.run(
        [shutil.which("bash"), str(plugin_dir / "run.sh")],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": path},
    )
    assert r.returncode == 1
    assert "no working python3/python/py" in r.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only stubs")
def test_working_interpreter_after_broken_one_is_chosen(plugin_dir, tmp_path):
    path = _isolated_path(tmp_path, {"python3": 49, "python": 0})
    r = subprocess.run(
        [shutil.which("bash"), str(plugin_dir / "run.sh")],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": path},
    )
    assert r.returncode == 0, r.stderr
    assert "SERVER-STARTED" in r.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only stubs")
def test_extensionless_run_entry_point_starts_server(plugin_dir):
    """.mcp.json launches `run`; it must hand over to run.sh from any CWD."""
    shutil.copy(os.path.join(_PLUGIN_ROOT, "run"), plugin_dir / "run")
    (plugin_dir / "run").chmod(0o755)
    r = subprocess.run(
        [str(plugin_dir / "run")],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(plugin_dir.parent),
        env={k: v for k, v in os.environ.items() if not k.startswith(("ARMIS_", "APPSEC_"))},
    )
    assert r.returncode == 0, r.stderr
    assert "SERVER-STARTED" in r.stdout

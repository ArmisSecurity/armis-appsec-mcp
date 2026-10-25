"""run_hook in hooks/find-python.sh: every bash-form hook command goes through it."""

import os
import shutil
import stat
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = [
    pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh"),
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only stubs"),
]

_ECHO_HOOK = "import sys; print(repr(sys.stdin.read()), sys.argv[1:])\n"


@pytest.fixture
def hooks_dir(tmp_path):
    d = tmp_path / "plugin" / "hooks"
    d.mkdir(parents=True)
    shutil.copy(os.path.join(_ROOT, "hooks", "find-python.sh"), d)
    (d / "echo_hook.py").write_text(_ECHO_HOOK)
    return d


def _path_dir(tmp_path, name, pythons):
    d = tmp_path / name
    d.mkdir()
    for py_name, target in pythons.items():
        stub = d / py_name
        if isinstance(target, int):
            stub.write_text(f"#!/bin/sh\nexit {target}\n")
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        else:
            stub.symlink_to(target)
    return str(d)


def _run(hooks_dir, path, cwd=None):
    """The manifest's command shape, with a PATH holding no tools at all."""
    cmd = f'. "{hooks_dir}/find-python.sh" && run_hook "{hooks_dir}/echo_hook.py" --stdout-json'
    return subprocess.run(
        [shutil.which("sh"), "-c", cmd],
        input='{"tool_name": "Bash"}',
        capture_output=True,
        text=True,
        timeout=30,
        cwd=cwd,
        env={"PATH": os.pathsep.join(path)},
    )


def test_skips_an_earlier_stub_and_passes_stdin_and_args(hooks_dir, tmp_path):
    stub_dir = _path_dir(tmp_path, "windowsapps", {"python3": 49, "python": 49})
    real_dir = _path_dir(tmp_path, "real", {"python3": sys.executable})
    r = _run(hooks_dir, [stub_dir, real_dir])
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "'{\"tool_name\": \"Bash\"}' ['--stdout-json']"


def test_no_working_python_reports_the_gate_is_off(hooks_dir, tmp_path):
    stub_dir = _path_dir(tmp_path, "windowsapps", {"python3": 49, "python": 49})
    r = _run(hooks_dir, [stub_dir])
    assert r.returncode == 1
    assert "commit gate is OFF" in r.stderr


def test_relative_path_entries_are_not_searched(hooks_dir, tmp_path):
    """A python3 planted in the repo the hook runs in must never execute."""
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "planted-ran"
    planted = repo / "python3"
    planted.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
    planted.chmod(planted.stat().st_mode | stat.S_IXUSR)
    real_dir = _path_dir(tmp_path, "real", {"python3": sys.executable})
    r = _run(hooks_dir, ["", ".", real_dir], cwd=str(repo))
    assert r.returncode == 0, r.stderr
    assert not marker.exists()

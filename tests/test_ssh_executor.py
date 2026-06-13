"""SSHExecutor and VM-side evidence registration tests (M4).

The live SIFT VM is not reachable from CI, so these tests inject a fake SSH
connection at the connector seam and a fake executor for remote hashing. They
pin the contract that matters for the engine: run() ALWAYS returns an ExecResult
(timeouts become status='timeout', any transport error becomes status='error')
and never raises, so the investigation loop can keep going.
"""

from __future__ import annotations

import asyncio

import pytest

from find_evil.engine.schemas import ExecResult
from find_evil.evidence.register import EvidenceError, register_remote
from find_evil.tools.executor import SSHExecutor


class _FakeResult:
    def __init__(self, exit_status: int | None, stdout: str = "", stderr: str = ""):
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


class _FakeConn:
    """A real stand-in for an asyncssh connection."""

    def __init__(
        self, result=None, raises: Exception | None = None, delay: float = 0.0
    ):
        self._result = result
        self._raises = raises
        self._delay = delay
        self.closed = False

    async def run(self, command: str, check: bool = False):
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._raises is not None:
            raise self._raises
        return self._result

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _executor_with_conn(conn) -> SSHExecutor:
    async def connector():
        return conn

    return SSHExecutor(
        host="10.0.0.1",
        port=22,
        user="sansforensics",
        key_path=None,
        known_hosts=None,
        strict=False,
        connector=connector,
    )


async def test_ssh_run_ok_returns_stdout():
    conn = _FakeConn(result=_FakeResult(exit_status=0, stdout="partition table\n"))
    ex = _executor_with_conn(conn)
    res = await ex.run("mmls", "mmls /mnt/evidence/x.E01", 30)
    assert isinstance(res, ExecResult)
    assert res.status == "ok"
    assert res.exit_code == 0
    assert res.stdout == "partition table\n"
    assert res.tool == "mmls"


async def test_ssh_run_nonzero_exit_is_error():
    conn = _FakeConn(result=_FakeResult(exit_status=1, stdout="", stderr="boom"))
    ex = _executor_with_conn(conn)
    res = await ex.run("fsstat", "fsstat -o 2048 /mnt/evidence/x.E01", 30)
    assert res.status == "error"
    assert res.exit_code == 1


async def test_ssh_run_timeout_becomes_status_timeout():
    conn = _FakeConn(result=_FakeResult(0, "late"), delay=5.0)
    ex = _executor_with_conn(conn)
    res = await ex.run("fls", "fls -r -o 2048 /mnt/evidence/x.E01", 0.01)
    assert res.status == "timeout"
    assert res.exit_code == 124


async def test_ssh_connect_failure_is_error_not_raise():
    async def bad_connector():
        raise OSError("connection refused")

    ex = SSHExecutor(
        host="10.0.0.1",
        port=22,
        user="x",
        key_path=None,
        known_hosts=None,
        strict=False,
        connector=bad_connector,
    )
    res = await ex.run("mmls", "mmls /mnt/evidence/x.E01", 30)
    assert res.status == "error"
    assert res.exit_code != 0


async def test_ssh_run_transport_error_is_error_not_raise():
    conn = _FakeConn(raises=ConnectionResetError("dropped"))
    ex = _executor_with_conn(conn)
    res = await ex.run("mmls", "mmls /mnt/evidence/x.E01", 30)
    assert res.status == "error"


def test_connect_kwargs_password_and_hostkey_wiring():
    # Strict on with default known_hosts -> () (load ~/.ssh/known_hosts), password included.
    strict = SSHExecutor(
        host="h",
        port=2222,
        user="sansforensics",
        key_path=None,
        known_hosts=None,
        strict=True,
        password="forensics",
    )
    kw = strict._connect_kwargs()
    assert kw["username"] == "sansforensics"
    assert kw["port"] == 2222
    assert kw["known_hosts"] == ()
    assert kw["password"] == "forensics"
    assert "client_keys" not in kw

    # Strict off -> host-key verification disabled (None). Key path included.
    loose = SSHExecutor(
        host="h",
        port=22,
        user="u",
        key_path="/home/u/.ssh/id_ed25519",
        known_hosts=None,
        strict=False,
    )
    kw2 = loose._connect_kwargs()
    assert kw2["known_hosts"] is None
    assert kw2["client_keys"] == ["/home/u/.ssh/id_ed25519"]
    assert "password" not in kw2


# ---- VM-side evidence registration ------------------------------------------
class _FakeExecutor:
    """Returns scripted ExecResults based on the command's leading token."""

    def __init__(self, by_tool: dict[str, ExecResult]):
        self._by_tool = by_tool

    async def run(self, tool: str, command: str, timeout_s: int) -> ExecResult:
        return self._by_tool[tool]


def _ok(tool: str, stdout: str) -> ExecResult:
    return ExecResult(
        execution_id="x",
        tool=tool,
        command="c",
        exit_code=0,
        stdout=stdout,
        stdout_sha256="s",
        duration_s=0.0,
        status="ok",
    )


async def test_register_remote_hashes_on_vm():
    sha = "a" * 64
    ex = _FakeExecutor(
        {
            "sha256sum": _ok("sha256sum", f"{sha}  /mnt/evidence/win10.E01\n"),
            "stat": _ok("stat", "104857600\n"),
        }
    )
    ev = await register_remote(ex, "/mnt/evidence/win10.E01", ["/mnt/evidence/"], 60)
    assert ev.sha256 == sha
    assert ev.size_bytes == 104857600
    assert ev.type == "disk_image"
    assert ev.path == "/mnt/evidence/win10.E01"


async def test_register_remote_rejects_path_outside_allowlist():
    ex = _FakeExecutor({})
    with pytest.raises(EvidenceError):
        await register_remote(ex, "/etc/shadow", ["/mnt/evidence/"], 60)


async def test_register_remote_errors_when_hash_command_fails():
    failed = ExecResult(
        execution_id="x",
        tool="sha256sum",
        command="c",
        exit_code=1,
        stdout="sha256sum: cannot open",
        stdout_sha256="s",
        duration_s=0.0,
        status="error",
    )
    ex = _FakeExecutor({"sha256sum": failed})
    with pytest.raises(EvidenceError):
        await register_remote(ex, "/mnt/evidence/missing.E01", ["/mnt/evidence/"], 60)

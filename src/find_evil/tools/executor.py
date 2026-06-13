"""Execution backends behind one protocol.

Build and test the entire loop against MockExecutor with captured fixtures.
Swap to SSHExecutor for the live SIFT VM. The engine depends on this protocol,
never on a transport.
"""

from __future__ import annotations
import asyncio
import hashlib
import time
import uuid
from pathlib import Path
from typing import Awaitable, Callable, Protocol

import structlog

from find_evil.engine.schemas import ExecResult

log = structlog.get_logger()


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


class Executor(Protocol):
    async def run(self, tool: str, command: str, timeout_s: int) -> ExecResult: ...


class MockExecutor:
    """Replays canned tool output from fixtures/sample_case.

    Fixture lookup: by tool name -> fixtures_dir/<tool>.txt. This lets Day 1-3
    proceed with zero SIFT access and doubles as the regression corpus.
    """

    def __init__(self, fixtures_dir: str):
        self.dir = Path(fixtures_dir)

    async def run(self, tool: str, command: str, timeout_s: int) -> ExecResult:
        fixture = self.dir / f"{tool}.txt"
        if fixture.exists():
            out, code, status = fixture.read_text(), 0, "ok"
        else:
            out, code, status = f"[mock] no fixture for tool {tool!r}\n", 1, "error"
        return ExecResult(
            execution_id=str(uuid.uuid4()),
            tool=tool,
            command=command,
            exit_code=code,
            stdout=out,
            stdout_sha256=_sha(out),
            duration_s=0.01,
            status=status,
        )


class SSHExecutor:
    """Runs commands on the SIFT Workstation over SSH (asyncssh).

    Host-key verification comes from settings. The timeout is enforced with
    asyncio.wait_for. run() ALWAYS returns an ExecResult: a timeout becomes
    status='timeout' (exit_code 124), and any transport error becomes
    status='error'. It never raises, so the engine loop never aborts on a tool
    failure. The connection is opened lazily and reused; it is reset after any
    failure so the next call reconnects.

    `connector` is an optional injection seam for tests: an async callable that
    returns a connection object exposing `run(command, check=False)` (returning
    an object with `.exit_status` and `.stdout`), `close()`, and `wait_closed()`.
    """

    def __init__(
        self,
        host,
        port,
        user,
        key_path,
        known_hosts,
        strict,
        password: str | None = None,
        connector: Callable[[], Awaitable] | None = None,
    ):
        self.host, self.port, self.user = host, port, user
        self.key_path, self.known_hosts, self.strict = key_path, known_hosts, strict
        self.password = password
        self._connector = connector
        self._conn = None

    def _known_hosts_arg(self):
        """Translate settings into asyncssh's known_hosts argument.

        None disables host-key verification (only when strict checking is off).
        () is asyncssh's default: load ~/.ssh/known_hosts. An explicit path uses
        that file.
        """
        if not self.strict:
            return None
        if self.known_hosts:
            return self.known_hosts
        return ()

    def _connect_kwargs(self) -> dict:
        """Build the keyword arguments for asyncssh.connect.

        Key auth is preferred; a password is included only when set. Kept
        separate so the auth and host-key wiring can be tested without a server.
        """
        kwargs: dict = {
            "port": self.port,
            "username": self.user,
            "known_hosts": self._known_hosts_arg(),
        }
        if self.key_path:
            kwargs["client_keys"] = [self.key_path]
        if self.password:
            kwargs["password"] = self.password
        return kwargs

    async def _connect(self):
        if self._conn is not None:
            return self._conn
        if self._connector is not None:
            self._conn = await self._connector()
            return self._conn
        import asyncssh

        self._conn = await asyncssh.connect(self.host, **self._connect_kwargs())
        return self._conn

    async def _reset(self) -> None:
        """Close and forget the connection so the next call reconnects."""
        conn = self._conn
        self._conn = None
        if conn is None:
            return
        try:
            conn.close()
            await conn.wait_closed()
        except Exception:  # noqa: BLE001 - cleanup must never raise
            pass

    async def run(self, tool: str, command: str, timeout_s: int) -> ExecResult:
        start = time.monotonic()
        execution_id = str(uuid.uuid4())
        try:
            conn = await self._connect()
            result = await asyncio.wait_for(
                conn.run(command, check=False), timeout=timeout_s
            )
            out = result.stdout or ""
            code = result.exit_status if result.exit_status is not None else -1
            status = "ok" if code == 0 else "error"
            return ExecResult(
                execution_id=execution_id,
                tool=tool,
                command=command,
                exit_code=code,
                stdout=out,
                stdout_sha256=_sha(out),
                duration_s=time.monotonic() - start,
                status=status,
            )
        except asyncio.TimeoutError:
            log.warning("ssh_timeout", tool=tool, timeout_s=timeout_s)
            await self._reset()
            return ExecResult(
                execution_id=execution_id,
                tool=tool,
                command=command,
                exit_code=124,
                stdout="",
                stdout_sha256=_sha(""),
                duration_s=time.monotonic() - start,
                status="timeout",
            )
        except Exception as e:  # noqa: BLE001 - transport errors become a result
            log.warning("ssh_error", tool=tool, error=str(e))
            await self._reset()
            msg = f"[ssh error] {e}"
            return ExecResult(
                execution_id=execution_id,
                tool=tool,
                command=command,
                exit_code=-1,
                stdout=msg,
                stdout_sha256=_sha(msg),
                duration_s=time.monotonic() - start,
                status="error",
            )

    async def close(self) -> None:
        await self._reset()


def build_executor(settings) -> Executor:
    if settings.executor == "mock":
        return MockExecutor(settings.fixtures_dir)
    if settings.executor == "ssh":
        return SSHExecutor(
            settings.sift_host,
            settings.sift_port,
            settings.sift_user,
            settings.sift_ssh_key_path,
            settings.sift_known_hosts_path,
            settings.sift_strict_host_key,
            password=settings.sift_password,
        )
    raise ValueError(f"unknown executor {settings.executor!r}")

"""Evidence registration. Step zero. The agent never invents a path.

For MOCK runs, hashing the real artifact on the analyst host is fine. For LIVE
runs the artifact lives on the SIFT VM; compute the hash there via the executor
(sha256sum) rather than locally. See CLAUDE.md Day 4 note.
"""

from __future__ import annotations
import hashlib
import shlex
import uuid
from pathlib import Path

from find_evil.engine.schemas import Evidence


class EvidenceError(Exception):
    pass


def _classify(path: str) -> str:
    p = path.lower()
    if p.endswith((".e01", ".dd", ".raw", ".img")):
        return "disk_image"
    if p.endswith((".mem", ".vmem", ".dmp", ".lime")):
        return "memory_dump"
    if p.endswith((".zip", ".tar", ".gz")):
        return "triage_collection"
    return "file"


def register_local(path: str, allowlist: list[str]) -> Evidence:
    """Register an artifact that exists on THIS host (mock/local mode)."""
    if not any(path.startswith(p) for p in allowlist):
        # In mock mode the fixtures dir is the allowed location; callers pass it in.
        raise EvidenceError(f"path not in allowlist {allowlist}: {path}")
    fp = Path(path)
    if not fp.exists():
        raise EvidenceError(f"evidence not found: {path}")
    h = hashlib.sha256()
    with fp.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return Evidence(
        evidence_id=str(uuid.uuid4()),
        path=path,
        type=_classify(path),
        sha256=h.hexdigest(),
        size_bytes=fp.stat().st_size,
    )


async def register_remote(
    executor, path: str, allowlist: list[str], timeout_s: int = 60
) -> Evidence:
    """Register an artifact that lives on the SIFT VM (ssh mode).

    The hash and size are computed ON THE VM via the executor (sha256sum and
    stat), never by reading the file locally, because the analyst host does not
    have the evidence. The path is checked against the allowlist before any
    command runs. A failed command becomes an EvidenceError so the engine can
    degrade honestly rather than register a bogus artifact.
    """
    if not any(path.startswith(p) for p in allowlist):
        raise EvidenceError(f"path not in allowlist {allowlist}: {path}")

    quoted = shlex.quote(path)

    h = await executor.run("sha256sum", f"sha256sum -- {quoted}", timeout_s)
    if h.status != "ok" or h.exit_code != 0:
        raise EvidenceError(f"could not hash evidence on VM ({h.status}): {path}")
    tokens = h.stdout.split()
    sha256 = tokens[0] if tokens else ""
    if len(sha256) != 64:
        raise EvidenceError(f"unexpected sha256sum output for {path}: {h.stdout!r}")

    s = await executor.run("stat", f"stat -c %s -- {quoted}", timeout_s)
    if s.status != "ok" or s.exit_code != 0:
        raise EvidenceError(f"could not stat evidence on VM ({s.status}): {path}")
    try:
        size_bytes = int(s.stdout.strip().split()[0])
    except (ValueError, IndexError):
        raise EvidenceError(f"unexpected stat output for {path}: {s.stdout!r}")

    return Evidence(
        evidence_id=str(uuid.uuid4()),
        path=path,
        type=_classify(path),
        sha256=sha256,
        size_bytes=size_bytes,
    )

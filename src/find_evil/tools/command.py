"""Deterministic command assembly. The LLM never writes a command string.

It returns typed ToolParams; code assembles the final command from the tool
template and validated slots. This eliminates the narration-leak failure where
model prose was passed to the shell and blocked by the validator.

Rail: do not add a code path that accepts a free-text command from the model.
"""

from __future__ import annotations
import re
import shlex
import yaml
from pathlib import Path

from find_evil.engine.schemas import ToolParams, Evidence

# Shell metacharacters that must never appear in an assembled command.
_FORBIDDEN = re.compile(r"[;&|`$><\n\r]|\$\(|\.\.")


class CommandBuildError(Exception):
    pass


class CommandValidator:
    """Defense-in-depth backstop. With template assembly this should rarely
    trip; slot validation and the allowlist run first."""

    def validate(self, command: str) -> None:
        if _FORBIDDEN.search(command):
            raise CommandBuildError(f"forbidden shell pattern in command: {command!r}")


def load_metadata(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())


def _tool_meta(metadata: dict, name: str) -> dict:
    for t in metadata.get("tools", []):
        if t["name"] == name:
            return t
    raise CommandBuildError(f"unknown tool {name!r}")


def assemble_command(
    metadata: dict,
    params: ToolParams,
    evidence: dict[str, Evidence],
    allowlist: list[str],
) -> str:
    """Build a safe command from a template + validated slots.

    evidence: maps evidence_id -> Evidence (paths AS SEEN ON THE EXECUTION TARGET).
    allowlist: permitted path prefixes for evidence_path slots.
    """
    meta = _tool_meta(metadata, params.tool)
    values: dict[str, str] = {}
    for slot, spec in meta.get("slots", {}).items():
        raw = params.params.get(slot, "")
        required = spec.get("required", False)
        if not raw and required:
            raise CommandBuildError(
                f"missing required slot {slot!r} for {params.tool!r}"
            )
        if not raw:
            values[slot] = spec.get("default", "")
            continue

        stype = spec["type"]
        if stype == "evidence_path":
            ev = evidence.get(raw)
            if ev is None:
                raise CommandBuildError(
                    f"unknown evidence_id {raw!r} for slot {slot!r}"
                )
            if not any(ev.path.startswith(p) for p in allowlist):
                raise CommandBuildError(f"evidence path not in allowlist: {ev.path}")
            values[slot] = shlex.quote(ev.path)
        elif stype == "workspace_path":
            if ".." in raw or raw.startswith("/etc") or raw.startswith("~"):
                raise CommandBuildError(f"unsafe workspace path: {raw}")
            values[slot] = shlex.quote(raw)
        elif stype == "enum":
            choices = spec.get("choices", [])
            if raw not in choices:
                raise CommandBuildError(f"slot {slot!r} value {raw!r} not in {choices}")
            values[slot] = raw
        elif stype == "scalar":
            if not re.fullmatch(r"[A-Za-z0-9._:\-/]+", raw):
                raise CommandBuildError(
                    f"slot {slot!r} scalar has illegal chars: {raw!r}"
                )
            values[slot] = raw
        else:
            raise CommandBuildError(f"unknown slot type {stype!r}")

    command = meta["template"].format(**values)
    CommandValidator().validate(command)
    return command

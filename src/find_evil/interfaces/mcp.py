"""MCP interface. A thin adapter over interfaces.core.investigate.

It exposes one tool, `investigate`, that runs the engine and returns the same
markdown report the CLI produces. The mcp SDK is imported lazily so importing
this module never requires it; build_server() raises a clear error if the SDK is
absent. The investigate_tool handler is plain and testable without the SDK.
"""

from __future__ import annotations

from find_evil.config.settings import Settings, get_settings
from find_evil.interfaces import core

_DEFAULT_GOAL = "Reconstruct the attack chain and identify IOCs."


async def investigate_tool(
    incident: str,
    evidence: list[str],
    goal: str = _DEFAULT_GOAL,
    supervised: bool = False,
    *,
    settings: Settings | None = None,
    llm=None,
    executor=None,
) -> str:
    """Run an investigation and return the rendered markdown report.

    This is the MCP tool handler. The settings/llm/executor keyword arguments are
    injection seams for tests and embedding; an MCP client supplies only the
    domain arguments.
    """
    settings = settings or get_settings()
    _, report = await core.investigate(
        settings,
        incident,
        goal,
        list(evidence),
        supervised,
        llm=llm,
        executor=executor,
    )
    return report


def build_server():
    """Construct the MCP server exposing the investigate tool.

    Imports the mcp SDK lazily. Raises a clear ImportError if it is not
    installed, so the dependency is only required when actually serving.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - exercised only without the SDK
        raise ImportError(
            "The 'mcp' package is required to run the MCP interface. "
            "Install it with: pip install mcp"
        ) from e

    server = FastMCP("find-evil")

    @server.tool()
    async def investigate(
        incident: str,
        evidence: list[str],
        goal: str = _DEFAULT_GOAL,
        supervised: bool = False,
    ) -> str:
        """Autonomously investigate an incident on the SIFT Workstation and
        return a provenance-grounded markdown report."""
        return await investigate_tool(incident, evidence, goal, supervised)

    return server


def main() -> None:  # pragma: no cover - process entrypoint
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()

"""Base Parser - Abstract base class for all tool output parsers.

All parsers inherit from BaseParser and implement the parse() method
to convert raw tool output into structured data.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()

T = TypeVar("T")


@dataclass
class ParserResult(Generic[T]):
    """Result from parsing tool output.

    Attributes:
        success: True if parsing succeeded
        data: Parsed structured data (type varies by parser)
        raw_output: Original raw text output
        tool_name: Name of the tool that produced the output
        parse_errors: List of parsing errors/warnings
        metadata: Additional parser-specific metadata
    """

    success: bool
    data: T | None
    raw_output: str
    tool_name: str
    parse_errors: list[str] | None = None
    metadata: dict[str, Any] | None = None


class BaseParser(ABC):
    """Abstract base class for tool output parsers.

    All parsers must implement:
    - parse(): Convert raw output to structured data
    - supports_tool(): Check if parser handles a given tool

    Subclasses should:
    - Define their own data models (dataclasses/Pydantic)
    - Handle multiple output formats where applicable
    - Provide graceful degradation on parse errors
    - Log parsing issues for debugging
    """

    def __init__(self, tool_name: str | None = None):
        """Initialize parser.

        Args:
            tool_name: Optional tool name for validation
        """
        self.tool_name = tool_name
        self.logger = logger.bind(parser=self.__class__.__name__)

    @abstractmethod
    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse raw tool output into structured data.

        Args:
            raw_output: Raw text output from tool
            **kwargs: Parser-specific options (e.g., plugin name, format)

        Returns:
            ParserResult with structured data or errors

        Example:
            >>> parser = VolatilityParser()
            >>> result = parser.parse(output, plugin="pslist")
            >>> if result.success:
            ...     processes = result.data.processes
        """
        pass

    @abstractmethod
    def supports_tool(self, tool_name: str) -> bool:
        """Check if this parser supports the given tool.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if parser can handle this tool

        Example:
            >>> parser = VolatilityParser()
            >>> parser.supports_tool("volatility")
            True
            >>> parser.supports_tool("grep")
            False
        """
        pass

    def _log_parse_error(self, error: str, context: dict[str, Any] | None = None):
        """Log parsing error with context.

        Args:
            error: Error message
            context: Additional context for debugging
        """
        self.logger.warning(
            "parse_error", error=error, tool=self.tool_name, **(context or {})
        )

    def _create_error_result(
        self, raw_output: str, error: str, tool_name: str | None = None
    ) -> ParserResult:
        """Create a failed ParserResult.

        Args:
            raw_output: Original raw output
            error: Error message
            tool_name: Tool name (uses self.tool_name if not provided)

        Returns:
            ParserResult with success=False
        """
        return ParserResult(
            success=False,
            data=None,
            raw_output=raw_output,
            tool_name=tool_name or self.tool_name or "unknown",
            parse_errors=[error],
        )

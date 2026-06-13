"""Parser Factory - Automatically select and apply appropriate parser for tools.

This factory determines which parser to use based on the tool name
and applies it to the raw output.
"""

import structlog

from .base import BaseParser, ParserResult
from .volatility import VolatilityParser
from .timeline import TimelineParser
from .tsk import TSKParser
from .strings import StringsParser
from .grep import GrepParser

logger = structlog.get_logger()


class ParserFactory:
    """Factory for creating and applying appropriate parsers.

    Automatically selects the correct parser based on tool name
    and applies it to raw output.

    Example:
        >>> factory = ParserFactory()
        >>> result = factory.parse("volatility", raw_output, plugin="pslist")
        >>> if result.success:
        ...     processes = result.data.processes
    """

    def __init__(self):
        """Initialize parser factory with all available parsers."""
        self.parsers: list[BaseParser] = [
            VolatilityParser(),
            TimelineParser(),
            TSKParser(),
            StringsParser(),
            GrepParser(),
        ]

        logger.info("parser_factory_initialized", parser_count=len(self.parsers))

    def get_parser(self, tool_name: str) -> BaseParser | None:
        """Get appropriate parser for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Parser instance or None if no parser supports this tool
        """
        tool_lower = tool_name.lower()

        for parser in self.parsers:
            if parser.supports_tool(tool_lower):
                logger.debug(
                    "parser_found", tool=tool_name, parser=parser.__class__.__name__
                )
                return parser

        logger.debug(
            "no_parser_found",
            tool=tool_name,
            available_parsers=[p.__class__.__name__ for p in self.parsers],
        )
        return None

    def parse(self, tool_name: str, raw_output: str, **kwargs) -> ParserResult | None:
        """Parse tool output using appropriate parser.

        Args:
            tool_name: Name of the tool
            raw_output: Raw text output
            **kwargs: Parser-specific options

        Returns:
            ParserResult if parser found and parsing succeeds, None otherwise
        """
        parser = self.get_parser(tool_name)

        if not parser:
            logger.debug(
                "parsing_skipped", tool=tool_name, reason="no_parser_available"
            )
            return None

        try:
            result = parser.parse(raw_output, **kwargs)

            logger.info(
                "parsing_complete",
                tool=tool_name,
                parser=parser.__class__.__name__,
                success=result.success,
                errors=len(result.parse_errors or []),
            )

            return result

        except Exception as e:
            logger.error(
                "parsing_failed",
                tool=tool_name,
                parser=parser.__class__.__name__,
                error=str(e),
            )
            return None

    def supports_tool(self, tool_name: str) -> bool:
        """Check if any parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if a parser is available for this tool
        """
        return self.get_parser(tool_name) is not None


# Global parser factory instance
_parser_factory: ParserFactory | None = None


def get_parser_factory() -> ParserFactory:
    """Get global parser factory instance.

    Returns:
        Singleton ParserFactory instance
    """
    global _parser_factory

    if _parser_factory is None:
        _parser_factory = ParserFactory()

    return _parser_factory

"""Timeline Parser - Parse log2timeline/psort output.

Supports formats:
- CSV: psort CSV output format
- JSON: psort JSON output format
- L2T: log2timeline native format
"""

import csv
import json
from io import StringIO
from dataclasses import dataclass
from typing import List
from .base import BaseParser, ParserResult


@dataclass
class TimelineEvent:
    """Timeline event entry."""

    timestamp: str
    timestamp_desc: str
    source: str
    source_long: str
    message: str
    parser: str
    display_name: str
    tag: str | None = None


@dataclass
class TimelineData:
    """Structured timeline data."""

    events: List[TimelineEvent]
    total_events: int
    format: str


class TimelineParser(BaseParser):
    """Parser for log2timeline/psort timeline output.

    Handles multiple formats:
    - CSV (most common)
    - JSON
    - L2T (native plaso format - limited support)

    Example:
        >>> parser = TimelineParser()
        >>> result = parser.parse(csv_output, format="csv")
        >>> for event in result.data.events:
        ...     print(f"{event.timestamp}: {event.message}")
    """

    def __init__(self):
        """Initialize Timeline parser."""
        super().__init__(tool_name="psort")

    def supports_tool(self, tool_name: str) -> bool:
        """Check if parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is log2timeline or psort
        """
        return tool_name.lower() in [
            "log2timeline",
            "psort",
            "log2timeline.py",
            "psort.py",
        ]

    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse timeline output into structured data.

        Args:
            raw_output: Raw text output from psort/log2timeline
            **kwargs: Must include 'format' ("csv", "json", "l2t")

        Returns:
            ParserResult with TimelineData
        """
        output_format = kwargs.get("format", "csv").lower()

        if not raw_output or not raw_output.strip():
            return self._create_error_result(raw_output, "Empty timeline output")

        try:
            if output_format == "csv":
                data = self._parse_csv(raw_output)
            elif output_format == "json":
                data = self._parse_json(raw_output)
            else:
                return self._create_error_result(
                    raw_output,
                    f"Unsupported format: {output_format} (use 'csv' or 'json')",
                )

            return ParserResult(
                success=True,
                data=data,
                raw_output=raw_output,
                tool_name="psort",
                metadata={"format": output_format, "event_count": len(data.events)},
            )

        except Exception as e:
            self._log_parse_error(
                f"Failed to parse timeline output: {e}", {"format": output_format}
            )
            return self._create_error_result(raw_output, f"Parse error: {e}")

    def _parse_csv(self, output: str) -> TimelineData:
        """Parse CSV timeline output.

        Format:
        datetime,timestamp_desc,source,source_long,message,parser,display_name,tag
        2026-04-01T12:00:00.000000Z,File Modified,FILE,File Modification Time,/home/user/malware.exe,filestat,/home/user/malware.exe,
        """
        events = []
        csv_file = StringIO(output)
        reader = csv.DictReader(csv_file)

        for row in reader:
            try:
                event = TimelineEvent(
                    timestamp=row.get("datetime", ""),
                    timestamp_desc=row.get("timestamp_desc", ""),
                    source=row.get("source", ""),
                    source_long=row.get("source_long", ""),
                    message=row.get("message", ""),
                    parser=row.get("parser", ""),
                    display_name=row.get("display_name", ""),
                    tag=row.get("tag") if row.get("tag") else None,
                )
                events.append(event)

            except Exception as e:
                self.logger.debug("skipping_csv_row", error=str(e))
                continue

        return TimelineData(events=events, total_events=len(events), format="csv")

    def _parse_json(self, output: str) -> TimelineData:
        """Parse JSON timeline output.

        Format:
        [
          {
            "timestamp": "2026-04-01T12:00:00.000000Z",
            "timestamp_desc": "File Modified",
            "source": "FILE",
            ...
          }
        ]
        """
        events = []
        data = json.loads(output)

        # Handle both array and single object
        if isinstance(data, dict):
            data = [data]

        for item in data:
            try:
                event = TimelineEvent(
                    timestamp=item.get("timestamp", item.get("datetime", "")),
                    timestamp_desc=item.get("timestamp_desc", ""),
                    source=item.get("source", ""),
                    source_long=item.get("source_long", ""),
                    message=item.get("message", ""),
                    parser=item.get("parser", ""),
                    display_name=item.get("display_name", ""),
                    tag=item.get("tag"),
                )
                events.append(event)

            except Exception as e:
                self.logger.debug("skipping_json_item", error=str(e))
                continue

        return TimelineData(events=events, total_events=len(events), format="json")

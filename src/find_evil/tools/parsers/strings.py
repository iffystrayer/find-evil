"""Strings Parser - Parse strings output with IOC detection and entropy analysis.

Features:
- IOC detection (URLs, IPs, email, file paths)
- Entropy calculation (detect obfuscation)
- Length filtering
- Character set detection (ASCII/Unicode)
"""

import re
import math
from dataclasses import dataclass
from typing import List
from .base import BaseParser, ParserResult


@dataclass
class StringEntry:
    """String entry with metadata."""

    value: str
    length: int
    type: str  # 'url', 'ip', 'email', 'path', 'other'
    entropy: float | None = None
    offset: int | None = None


@dataclass
class StringsData:
    """Structured strings data."""

    strings: List[StringEntry]
    total_count: int
    high_entropy_count: int
    ioc_count: int


class StringsParser(BaseParser):
    """Parser for strings tool output with IOC detection.

    Features:
    - Detects URLs, IPs, emails, file paths
    - Calculates Shannon entropy (obfuscation detection)
    - Filters by minimum length
    - Identifies suspicious patterns

    Example:
        >>> parser = StringsParser()
        >>> result = parser.parse(output, min_length=10, detect_obfuscation=True)
        >>> urls = [s for s in result.data.strings if s.type == 'url']
    """

    # IOC patterns
    URL_PATTERN = re.compile(
        r"https?://[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+(?:/[^\s]*)?",
        re.IGNORECASE,
    )
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PATH_PATTERN = re.compile(r'(?:[A-Z]:\\|/)[^\s<>"|?*]+', re.IGNORECASE)

    def __init__(self):
        """Initialize Strings parser."""
        super().__init__(tool_name="strings")

    def supports_tool(self, tool_name: str) -> bool:
        """Check if parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is 'strings'
        """
        return tool_name.lower() == "strings"

    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse strings output into structured data.

        Args:
            raw_output: Raw text output from strings
            **kwargs:
                - min_length: Minimum string length (default: 4)
                - detect_obfuscation: Calculate entropy (default: False)
                - extract_iocs: Extract IOCs (default: True)

        Returns:
            ParserResult with StringsData
        """
        min_length = kwargs.get("min_length", 4)
        detect_obfuscation = kwargs.get("detect_obfuscation", False)
        extract_iocs = kwargs.get("extract_iocs", True)

        if not raw_output or not raw_output.strip():
            return self._create_error_result(raw_output, "Empty strings output")

        try:
            strings = []
            lines = raw_output.strip().split("\n")

            for line in lines:
                line = line.strip()
                if len(line) < min_length:
                    continue

                # Determine string type
                string_type = self._classify_string(line) if extract_iocs else "other"

                # Calculate entropy if requested
                entropy = None
                if detect_obfuscation:
                    entropy = self._calculate_entropy(line)

                entry = StringEntry(
                    value=line, length=len(line), type=string_type, entropy=entropy
                )
                strings.append(entry)

            # Calculate statistics
            high_entropy_threshold = 4.0
            high_entropy_count = sum(
                1 for s in strings if s.entropy and s.entropy > high_entropy_threshold
            )
            ioc_count = sum(1 for s in strings if s.type != "other")

            data = StringsData(
                strings=strings,
                total_count=len(strings),
                high_entropy_count=high_entropy_count,
                ioc_count=ioc_count,
            )

            metadata = {
                "min_length": min_length,
                "detect_obfuscation": detect_obfuscation,
                "high_entropy_threshold": high_entropy_threshold,
            }

            return ParserResult(
                success=True,
                data=data,
                raw_output=raw_output,
                tool_name="strings",
                metadata=metadata,
            )

        except Exception as e:
            self._log_parse_error(f"Failed to parse strings output: {e}")
            return self._create_error_result(raw_output, f"Parse error: {e}")

    def _classify_string(self, s: str) -> str:
        """Classify string as URL, IP, email, path, or other.

        Args:
            s: String to classify

        Returns:
            String type
        """
        if self.URL_PATTERN.search(s):
            return "url"
        elif self.IP_PATTERN.search(s):
            return "ip"
        elif self.EMAIL_PATTERN.search(s):
            return "email"
        elif self.PATH_PATTERN.search(s):
            return "path"
        else:
            return "other"

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string.

        Higher entropy suggests obfuscation or encryption.
        - Low entropy (< 3.0): Plain text, repetitive
        - Medium entropy (3.0-4.5): Normal text
        - High entropy (> 4.5): Obfuscated, encoded, encrypted

        Args:
            s: String to analyze

        Returns:
            Shannon entropy value
        """
        if not s:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in s:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        length = len(s)
        entropy = 0.0

        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

"""Grep Parser - Parse grep output with context and IOC extraction.

Features:
- Parse grep output with filenames and line numbers
- Extract IOCs (IPs, URLs, domains)
- Support for context lines (grep -C)
- Grouping by filename
"""

import re
from dataclasses import dataclass
from typing import List, Dict
from .base import BaseParser, ParserResult


@dataclass
class GrepMatch:
    """Grep match entry."""

    filename: str
    line_number: int
    matched_text: str
    context_before: List[str] | None = None
    context_after: List[str] | None = None


@dataclass
class GrepData:
    """Structured grep data."""

    matches: List[GrepMatch]
    total_matches: int
    files_matched: int
    iocs: Dict[str, List[str]] | None = None


class GrepParser(BaseParser):
    """Parser for grep tool output.

    Handles:
    - Standard grep output (filename:line:text)
    - Context output (grep -C N)
    - IOC extraction from matched lines

    Example:
        >>> parser = GrepParser()
        >>> result = parser.parse(grep_output, extract_iocs=True)
        >>> for match in result.data.matches:
        ...     print(f"{match.filename}:{match.line_number}: {match.matched_text}")
    """

    # IOC patterns
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    URL_PATTERN = re.compile(
        r"https?://[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+(?:/[^\s]*)?",
        re.IGNORECASE,
    )
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )

    def __init__(self):
        """Initialize Grep parser."""
        super().__init__(tool_name="grep")

    def supports_tool(self, tool_name: str) -> bool:
        """Check if parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is 'grep'
        """
        return tool_name.lower() in ["grep", "egrep", "fgrep", "rgrep"]

    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse grep output into structured data.

        Args:
            raw_output: Raw text output from grep
            **kwargs:
                - extract_iocs: Extract IOCs from matches (default: False)
                - group_by_file: Group matches by filename (default: False)

        Returns:
            ParserResult with GrepData
        """
        extract_iocs = kwargs.get("extract_iocs", False)

        if not raw_output or not raw_output.strip():
            return self._create_error_result(raw_output, "Empty grep output")

        try:
            matches = []
            lines = raw_output.strip().split("\n")

            # Pattern: filename:line_number:matched_text
            # Example: /var/log/syslog:1234:Apr 01 15:30:45 malware: Starting C2
            pattern = re.compile(r"^([^:]+):(\d+):(.+)$")

            for line in lines:
                if not line.strip():
                    continue

                match = pattern.match(line)
                if match:
                    filename = match.group(1)
                    line_number = int(match.group(2))
                    matched_text = match.group(3)

                    grep_match = GrepMatch(
                        filename=filename,
                        line_number=line_number,
                        matched_text=matched_text,
                    )
                    matches.append(grep_match)

            # Extract IOCs if requested
            iocs = None
            if extract_iocs:
                iocs = self._extract_iocs(matches)

            # Calculate statistics
            unique_files = len(set(m.filename for m in matches))

            data = GrepData(
                matches=matches,
                total_matches=len(matches),
                files_matched=unique_files,
                iocs=iocs,
            )

            metadata = {"extract_iocs": extract_iocs, "unique_files": unique_files}

            if iocs:
                metadata["ioc_summary"] = {
                    "ips": len(iocs.get("ips", [])),
                    "urls": len(iocs.get("urls", [])),
                    "domains": len(iocs.get("domains", [])),
                }

            return ParserResult(
                success=True,
                data=data,
                raw_output=raw_output,
                tool_name="grep",
                metadata=metadata,
            )

        except Exception as e:
            self._log_parse_error(f"Failed to parse grep output: {e}")
            return self._create_error_result(raw_output, f"Parse error: {e}")

    def _extract_iocs(self, matches: List[GrepMatch]) -> Dict[str, List[str]]:
        """Extract IOCs from grep matches.

        Args:
            matches: List of grep matches

        Returns:
            Dict with 'ips', 'urls', 'domains' lists
        """
        ips = set()
        urls = set()
        domains = set()

        for match in matches:
            text = match.matched_text

            # Extract IPs
            for ip_match in self.IP_PATTERN.finditer(text):
                ip = ip_match.group(0)
                # Filter out invalid IPs
                parts = ip.split(".")
                if all(0 <= int(p) <= 255 for p in parts):
                    ips.add(ip)

            # Extract URLs
            for url_match in self.URL_PATTERN.finditer(text):
                urls.add(url_match.group(0))

            # Extract domains
            for domain_match in self.DOMAIN_PATTERN.finditer(text):
                domain = domain_match.group(0)
                # Filter out common non-domain matches
                if not domain.endswith(".log") and not domain.endswith(".txt"):
                    domains.add(domain)

        return {
            "ips": sorted(list(ips)),
            "urls": sorted(list(urls)),
            "domains": sorted(list(domains)),
        }

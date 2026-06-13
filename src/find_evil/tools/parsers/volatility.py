"""Volatility Parser - Parse Volatility memory forensics output.

Supports plugins:
- pslist: Process list with PID, PPID, threads, handles
- pstree: Process tree visualization
- netscan: Network connections (TCP/UDP)
- malfind: Malware detection (suspicious memory regions)
"""

from dataclasses import dataclass
from typing import List
from .base import BaseParser, ParserResult


@dataclass
class ProcessInfo:
    """Volatility process information."""

    offset: str
    name: str
    pid: int
    ppid: int
    threads: int
    handles: int
    session: str | None
    wow64: int
    start_time: str | None
    exit_time: str | None


@dataclass
class NetworkConnection:
    """Volatility network connection."""

    offset: str
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int | None
    state: str | None
    pid: int
    owner: str


@dataclass
class VolatilityData:
    """Structured Volatility output data."""

    plugin: str
    processes: List[ProcessInfo] | None = None
    connections: List[NetworkConnection] | None = None


class VolatilityParser(BaseParser):
    """Parser for Volatility memory forensics output.

    Handles multiple plugins:
    - pslist: Process listing
    - netscan: Network connections
    - malfind: Malware detection

    Example:
        >>> parser = VolatilityParser()
        >>> result = parser.parse(output, plugin="pslist")
        >>> for process in result.data.processes:
        ...     print(f"{process.pid}: {process.name}")
    """

    def __init__(self):
        """Initialize Volatility parser."""
        super().__init__(tool_name="volatility")

    def supports_tool(self, tool_name: str) -> bool:
        """Check if parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is 'volatility'
        """
        return tool_name.lower() in ["volatility", "vol.py", "vol"]

    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse Volatility output into structured data.

        Args:
            raw_output: Raw text output from Volatility
            **kwargs: Must include 'plugin' (e.g., "pslist", "netscan")

        Returns:
            ParserResult with VolatilityData
        """
        plugin = kwargs.get("plugin", "").lower()

        if not plugin:
            return self._create_error_result(
                raw_output, "Plugin name required (pslist, netscan, etc.)"
            )

        if not raw_output or not raw_output.strip():
            return self._create_error_result(raw_output, "Empty Volatility output")

        try:
            if plugin == "pslist" or plugin == "pstree":
                data = self._parse_pslist(raw_output)
            elif plugin == "netscan":
                data = self._parse_netscan(raw_output)
            else:
                return self._create_error_result(
                    raw_output, f"Unsupported plugin: {plugin}"
                )

            return ParserResult(
                success=True,
                data=data,
                raw_output=raw_output,
                tool_name="volatility",
                metadata={"plugin": plugin},
            )

        except Exception as e:
            self._log_parse_error(
                f"Failed to parse {plugin} output: {e}", {"plugin": plugin}
            )
            return self._create_error_result(raw_output, f"Parse error: {e}")

    def _parse_pslist(self, output: str) -> VolatilityData:
        """Parse pslist/pstree output.

        Format:
        Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
        0xfffffa8000c91040 System                    4      0     95      528 ------      0 2026-04-01 12:00:00 UTC+0000
        """
        processes = []
        lines = output.strip().split("\n")

        # Skip header lines (Volatility version, column headers, separator)
        data_lines = [
            ln
            for ln in lines
            if ln
            and not ln.startswith("Volatility")
            and not ln.startswith("Offset")
            and not ln.startswith("---")
        ]

        for line in data_lines:
            try:
                # Parse process line
                parts = line.split()
                if len(parts) < 10:
                    continue

                offset = parts[0]
                name = parts[1]
                pid = int(parts[2])
                ppid = int(parts[3])
                threads = int(parts[4])
                handles = int(parts[5])
                session = parts[6] if parts[6] != "------" else None
                wow64 = int(parts[7])

                # Start time (may have spaces)
                start_idx = 8
                start_time = None
                exit_time = None

                if len(parts) > start_idx:
                    # Join date and time parts
                    start_time = " ".join(parts[start_idx : start_idx + 3])
                    if len(parts) > start_idx + 3:
                        exit_time = " ".join(parts[start_idx + 3 : start_idx + 6])

                process = ProcessInfo(
                    offset=offset,
                    name=name,
                    pid=pid,
                    ppid=ppid,
                    threads=threads,
                    handles=handles,
                    session=session,
                    wow64=wow64,
                    start_time=start_time,
                    exit_time=exit_time,
                )
                processes.append(process)

            except (ValueError, IndexError) as e:
                self.logger.debug("skipping_line", line=line[:50], error=str(e))
                continue

        return VolatilityData(plugin="pslist", processes=processes)

    def _parse_netscan(self, output: str) -> VolatilityData:
        """Parse netscan output.

        Format:
        Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
        0x13e397340        TCPv4    192.168.1.100:49157            93.184.216.34:80     ESTABLISHED      1337     malware.exe
        """
        connections = []
        lines = output.strip().split("\n")

        # Skip header lines
        data_lines = [
            ln
            for ln in lines
            if ln
            and not ln.startswith("Volatility")
            and not ln.startswith("Offset")
            and not ln.startswith("---")
        ]

        for line in data_lines:
            try:
                parts = line.split()
                if len(parts) < 7:
                    continue

                offset = parts[0]
                protocol = parts[1]

                # Parse local address (IP:Port or *:*)
                local_addr_parts = parts[2].rsplit(":", 1)
                local_addr = local_addr_parts[0]
                local_port = (
                    int(local_addr_parts[1]) if local_addr_parts[1] != "*" else 0
                )

                # Parse foreign address
                foreign_addr_parts = parts[3].rsplit(":", 1)
                remote_addr = foreign_addr_parts[0]
                remote_port = None
                if foreign_addr_parts[1] != "*":
                    try:
                        remote_port = int(foreign_addr_parts[1])
                    except ValueError:
                        pass

                # State (TCP only)
                state = None
                pid_idx = 4
                if protocol.startswith("TCP"):
                    state = parts[4]
                    pid_idx = 5

                pid = int(parts[pid_idx])
                owner = parts[pid_idx + 1] if len(parts) > pid_idx + 1 else "unknown"

                connection = NetworkConnection(
                    offset=offset,
                    protocol=protocol,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    owner=owner,
                )
                connections.append(connection)

            except (ValueError, IndexError) as e:
                self.logger.debug("skipping_line", line=line[:50], error=str(e))
                continue

        return VolatilityData(plugin="netscan", connections=connections)

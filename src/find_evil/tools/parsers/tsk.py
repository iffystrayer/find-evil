"""TSK Parser - Parse Sleuth Kit (TSK) tool output.

Supports tools:
- fls: File listing (including deleted files)
- mmls: Partition layout
- fsstat: Filesystem statistics
- icat: File extraction (binary, not parsed)
"""

import re
from dataclasses import dataclass
from typing import List
from .base import BaseParser, ParserResult


@dataclass
class FileEntry:
    """File entry from fls output."""

    type: str  # 'r' (regular), 'd' (directory), etc.
    deleted: bool
    inode: int
    name: str


@dataclass
class Partition:
    """Partition from mmls output."""

    slot: str
    start_sector: int
    end_sector: int
    length: int
    description: str


@dataclass
class FilesystemInfo:
    """Filesystem information from fsstat."""

    fs_type: str
    block_size: int | None = None
    total_blocks: int | None = None
    free_blocks: int | None = None
    metadata: dict | None = None


@dataclass
class TSKData:
    """Structured TSK tool output data."""

    tool: str
    files: List[FileEntry] | None = None
    partitions: List[Partition] | None = None
    filesystem: FilesystemInfo | None = None


class TSKParser(BaseParser):
    """Parser for Sleuth Kit (TSK) tool output.

    Handles multiple TSK tools:
    - fls: File and directory listing
    - mmls: Partition layout
    - fsstat: Filesystem details

    Example:
        >>> parser = TSKParser()
        >>> result = parser.parse(fls_output, tool="fls")
        >>> for file in result.data.files:
        ...     if file.deleted:
        ...         print(f"Deleted: {file.name}")
    """

    def __init__(self):
        """Initialize TSK parser."""
        super().__init__(tool_name="tsk")

    def supports_tool(self, tool_name: str) -> bool:
        """Check if parser supports the given tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is a supported TSK tool
        """
        return tool_name.lower() in ["fls", "mmls", "fsstat", "icat", "tsk"]

    def parse(self, raw_output: str, **kwargs) -> ParserResult:
        """Parse TSK tool output into structured data.

        Args:
            raw_output: Raw text output from TSK tool
            **kwargs: Must include 'tool' ("fls", "mmls", "fsstat")

        Returns:
            ParserResult with TSKData
        """
        tool = kwargs.get("tool", "").lower()

        if not tool:
            return self._create_error_result(
                raw_output, "Tool name required (fls, mmls, fsstat)"
            )

        if not raw_output or not raw_output.strip():
            return self._create_error_result(raw_output, f"Empty {tool} output")

        try:
            if tool == "fls":
                data = self._parse_fls(raw_output)
            elif tool == "mmls":
                data = self._parse_mmls(raw_output)
            elif tool == "fsstat":
                data = self._parse_fsstat(raw_output)
            else:
                return self._create_error_result(
                    raw_output, f"Unsupported TSK tool: {tool}"
                )

            return ParserResult(
                success=True,
                data=data,
                raw_output=raw_output,
                tool_name=tool,
                metadata={"tool": tool},
            )

        except Exception as e:
            self._log_parse_error(f"Failed to parse {tool} output: {e}", {"tool": tool})
            return self._create_error_result(raw_output, f"Parse error: {e}")

    def _parse_fls(self, output: str) -> TSKData:
        """Parse fls (file listing) output.

        Format:
        r/r 12345:	malware.exe
        r/r * 12346:	deleted_file.txt
        d/d 12347:	suspicious_folder
        """
        files = []
        lines = output.strip().split("\n")

        # Pattern: <type>/<meta> [*] <inode>:\t<name>
        # Example: r/r * 12346:	deleted_file.txt
        pattern = re.compile(r"([a-z])/([a-z])\s+(\*\s+)?(\d+):\s+(.+)")

        for line in lines:
            if not line.strip():
                continue

            match = pattern.match(line)
            if match:
                file_type = match.group(1)
                deleted = match.group(3) is not None  # '*' indicates deleted
                inode = int(match.group(4))
                name = match.group(5).strip()

                file_entry = FileEntry(
                    type=file_type, deleted=deleted, inode=inode, name=name
                )
                files.append(file_entry)

        return TSKData(tool="fls", files=files)

    def _parse_mmls(self, output: str) -> TSKData:
        """Parse mmls (partition layout) output.

        Format:
        DOS Partition Table
        Offset Sector: 0
        Units are in 512-byte sectors

              Slot      Start        End          Length       Description
        000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
        001:  -------   0000000000   0000002047   0000002048   Unallocated
        002:  000:000   0000002048   0002099199   0002097152   NTFS / exFAT (0x07)
        """
        partitions = []
        lines = output.strip().split("\n")

        # Find the partition table data (after headers)
        in_table = False
        for line in lines:
            if "Slot" in line and "Start" in line:
                in_table = True
                continue

            if in_table and line.strip():
                # Parse partition line
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        slot = parts[0]
                        start = int(parts[2])
                        end = int(parts[3])
                        length = int(parts[4])
                        description = " ".join(parts[5:]) if len(parts) > 5 else ""

                        partition = Partition(
                            slot=slot,
                            start_sector=start,
                            end_sector=end,
                            length=length,
                            description=description,
                        )
                        partitions.append(partition)

                    except (ValueError, IndexError):
                        continue

        return TSKData(tool="mmls", partitions=partitions)

    def _parse_fsstat(self, output: str) -> TSKData:
        """Parse fsstat (filesystem info) output.

        Format varies by filesystem type, extract key details.
        """
        lines = output.strip().split("\n")

        # Extract filesystem type
        fs_type = "unknown"
        block_size = None
        total_blocks = None
        free_blocks = None
        metadata = {}

        for line in lines:
            line_lower = line.lower()

            # Filesystem type
            if "file system type" in line_lower or "filesystem type" in line_lower:
                fs_type = line.split(":")[-1].strip()

            # Block size
            elif "block size" in line_lower:
                match = re.search(r"(\d+)", line)
                if match:
                    block_size = int(match.group(1))

            # Total blocks
            elif "block count" in line_lower or "total blocks" in line_lower:
                match = re.search(r"(\d+)", line)
                if match:
                    total_blocks = int(match.group(1))

            # Free blocks
            elif "free blocks" in line_lower:
                match = re.search(r"(\d+)", line)
                if match:
                    free_blocks = int(match.group(1))

            # Add other metadata
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip()

        filesystem = FilesystemInfo(
            fs_type=fs_type,
            block_size=block_size,
            total_blocks=total_blocks,
            free_blocks=free_blocks,
            metadata=metadata,
        )

        return TSKData(tool="fsstat", filesystem=filesystem)

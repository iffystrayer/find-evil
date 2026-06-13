"""Smoke tests for the ported SIFT tool output parsers.

These parsers were salvaged from the previous build and ported without
behavioral change. The tests confirm the structured extraction still works on
representative tool output.
"""

from __future__ import annotations

from find_evil.tools.parsers import (
    GrepParser,
    StringsParser,
    TSKParser,
    TimelineParser,
    VolatilityParser,
)
from find_evil.tools.parsers.factory import get_parser_factory


def test_volatility_pslist_parses_processes():
    output = (
        "Volatility 3 Framework\n"
        "Offset(V)          Name   PID   PPID   Thds   Hnds   Sess   Wow64   Start   Exit\n"
        "0xfffffa80 System 4 0 95 528 ------ 0 2026-04-01 12:00:00 UTC\n"
        "0xfffffa81 ransom.exe 1337 4 3 40 1 0 2026-04-01 12:05:00 UTC\n"
    )
    result = VolatilityParser().parse(output, plugin="pslist")
    assert result.success
    names = [p.name for p in result.data.processes]
    assert "ransom.exe" in names


def test_tsk_mmls_parses_partitions():
    output = (
        "DOS Partition Table\n"
        "Units are in 512-byte sectors\n"
        "      Slot      Start        End          Length       Description\n"
        "002:  000:000   0000002048   0002099199   0002097152   NTFS / exFAT (0x07)\n"
    )
    result = TSKParser().parse(output, tool="mmls")
    assert result.success
    assert result.data.partitions[0].description.startswith("NTFS")


def test_grep_extracts_iocs():
    output = "/var/log/syslog:1234:beacon to 93.184.216.34 via http://evil.example/c2\n"
    result = GrepParser().parse(output, extract_iocs=True)
    assert result.success
    assert "93.184.216.34" in result.data.iocs["ips"]
    assert any("evil.example" in u for u in result.data.iocs["urls"])


def test_strings_classifies_url():
    output = "harmless\nhttp://malware.example/payload\n"
    result = StringsParser().parse(output, extract_iocs=True)
    assert result.success
    assert any(s.type == "url" for s in result.data.strings)


def test_timeline_csv_parses_events():
    output = (
        "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
        "2026-04-01T12:00:00.000000Z,File Modified,FILE,File Modification Time,"
        "/home/user/ransom.exe,filestat,/home/user/ransom.exe,\n"
    )
    result = TimelineParser().parse(output, format="csv")
    assert result.success
    assert result.data.total_events == 1
    assert "ransom.exe" in result.data.events[0].message


def test_factory_routes_by_tool_name():
    factory = get_parser_factory()
    assert factory.supports_tool("volatility")
    assert factory.supports_tool("mmls")
    assert not factory.supports_tool("nonexistent-tool")

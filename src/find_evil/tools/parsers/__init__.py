"""Tool output parsers. Structured extraction from SIFT forensic tool output.

Ported without behavioral change from the previous build. Each parser converts
raw tool stdout into structured Python objects that the analyzer grounds its
findings against.

Available parsers:
- VolatilityParser: memory forensics (pslist, pstree, netscan)
- TimelineParser: timeline analysis (log2timeline, psort; CSV and JSON)
- TSKParser: Sleuth Kit tools (fls, mmls, fsstat)
- StringsParser: string extraction with IOC and entropy detection
- GrepParser: pattern matching with IOC extraction
"""

from .base import BaseParser, ParserResult
from .volatility import VolatilityParser
from .timeline import TimelineParser
from .tsk import TSKParser
from .strings import StringsParser
from .grep import GrepParser
from .factory import ParserFactory, get_parser_factory

__all__ = [
    "BaseParser",
    "ParserResult",
    "VolatilityParser",
    "TimelineParser",
    "TSKParser",
    "StringsParser",
    "GrepParser",
    "ParserFactory",
    "get_parser_factory",
]

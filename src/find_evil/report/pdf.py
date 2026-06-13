"""Dependency-free PDF export of the markdown report.

This is a deliberately minimal PDF writer: a monospace (Courier) dump of the
report text, wrapped and paginated, with no external dependencies (no reportlab,
weasyprint, or system libraries). It produces a valid PDF that any viewer can
open. The markdown is rendered as plain text, which keeps the export honest and
dependency-light. Provenance and structure remain readable.
"""

from __future__ import annotations

import textwrap

_PAGE_W, _PAGE_H = 612, 792  # US Letter, points
_MARGIN = 50
_FONT_SIZE = 10
_LEADING = 12
_WRAP_COLS = 92
_LINES_PER_PAGE = (_PAGE_H - 2 * _MARGIN) // _LEADING


def _wrap(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw:
            lines.append("")
            continue
        wrapped = textwrap.wrap(
            raw, width=_WRAP_COLS, replace_whitespace=False, drop_whitespace=False
        )
        lines.extend(wrapped or [""])
    return lines


def _paginate(lines: list[str]) -> list[list[str]]:
    pages = [
        lines[i : i + _LINES_PER_PAGE] for i in range(0, len(lines), _LINES_PER_PAGE)
    ]
    return pages or [[""]]


def _escape(s: str) -> str:
    out = s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    # PDF base fonts are byte-oriented; drop anything outside printable ASCII.
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in out)


def _content_stream(page_lines: list[str]) -> bytes:
    top = _PAGE_H - _MARGIN
    parts = ["BT", f"/F1 {_FONT_SIZE} Tf", f"{_LEADING} TL", f"{_MARGIN} {top} Td"]
    for i, line in enumerate(page_lines):
        if i:
            parts.append("T*")
        parts.append(f"({_escape(line)}) Tj")
    parts.append("ET")
    return ("\n".join(parts)).encode("latin-1", "replace")


def write_pdf(report_markdown: str, out_path: str) -> None:
    """Write the report text to a valid PDF at out_path."""
    pages = _paginate(_wrap(report_markdown))

    # Object layout: 1 catalog, 2 pages, 3 font, then per page a Page object and
    # a content stream object.
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)  # 1-based object number

    catalog_num = add(b"")  # placeholder, filled after we know pages num
    pages_num = add(b"")
    font_num = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    page_nums: list[int] = []
    for page_lines in pages:
        content = _content_stream(page_lines)
        content_obj = (
            b"<< /Length "
            + str(len(content)).encode()
            + b" >>\nstream\n"
            + content
            + b"\nendstream"
        )
        content_num = add(content_obj)
        page_obj = (
            b"<< /Type /Page /Parent " + str(pages_num).encode() + b" 0 R "
            b"/MediaBox [0 0 " + f"{_PAGE_W} {_PAGE_H}".encode() + b"] "
            b"/Resources << /Font << /F1 " + str(font_num).encode() + b" 0 R >> >> "
            b"/Contents " + str(content_num).encode() + b" 0 R >>"
        )
        page_nums.append(add(page_obj))

    kids = b" ".join(str(n).encode() + b" 0 R" for n in page_nums)
    objects[pages_num - 1] = (
        b"<< /Type /Pages /Kids ["
        + kids
        + b"] /Count "
        + str(len(page_nums)).encode()
        + b" >>"
    )
    objects[catalog_num - 1] = (
        b"<< /Type /Catalog /Pages " + str(pages_num).encode() + b" 0 R >>"
    )

    # Serialize with a cross-reference table.
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(i).encode() + b" 0 obj\n" + obj + b"\nendobj\n"

    xref_pos = len(out)
    n = len(objects) + 1
    out += b"xref\n0 " + str(n).encode() + b"\n"
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        b"trailer\n<< /Size "
        + str(n).encode()
        + b" /Root "
        + str(catalog_num).encode()
        + b" 0 R >>\nstartxref\n"
        + str(xref_pos).encode()
        + b"\n%%EOF\n"
    )

    with open(out_path, "wb") as f:
        f.write(out)

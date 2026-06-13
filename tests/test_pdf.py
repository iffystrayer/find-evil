"""PDF export tests (M6).

The PDF writer is dependency-free: it emits a valid PDF embedding the report
text. The tests confirm it produces a well-formed file with content, including
across a page break.
"""

from __future__ import annotations

from find_evil.report.pdf import write_pdf


def test_write_pdf_produces_valid_file(tmp_path):
    out = tmp_path / "report.pdf"
    write_pdf(
        "# Incident Report\n\nFinding: ransom.exe via `vol -f mem windows.pslist`.",
        str(out),
    )
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert b"%%EOF" in data
    assert out.stat().st_size > 200


def test_write_pdf_paginates_long_report(tmp_path):
    out = tmp_path / "long.pdf"
    long_report = "\n".join(
        f"line {i}: some forensic detail about the host" for i in range(400)
    )
    write_pdf(long_report, str(out))
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    # More than one page object for a 400-line report.
    assert data.count(b"/Type /Page\n") >= 2 or data.count(b"/Type /Page ") >= 2

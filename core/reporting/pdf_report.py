"""PDF export for KernelSpy Scanner (KernelSpy 1.4.4).

Writes a real, dependency-free PDF (Helvetica, multi-page) so the report can
be archived / printed without a browser.  The layout mirrors the HTML report
header (title, date, severity summary) followed by one row per finding.
"""

import os
import time
from typing import List

from ..models import Finding

# ── Minimal PDF primitives ──────────────────────────────────────────────────

_PAGE_W, _PAGE_H = 792, 612          # US Letter, landscape (fits wide tables)
_MARGIN = 40
_FONT_REG = "F1"
_FONT_BOLD = "F2"
_LINE_H = 14
_ROW_PAD = 4

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# column layout (x positions and widths), total <= _PAGE_W - 2*_MARGIN
_COLS = [
    ("SEV",   60),
    ("FILE", 200),
    ("LINE", 44),
    ("TYPE", 190),
    ("CATEGORY", 90),
]


def _esc(text: str) -> str:
    """Escape a string for a PDF literal string (\\ and parentheses)."""
    return (str(text)
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("\r", " ")
            .replace("\n", " "))


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _fmt_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class _PdfWriter:
    """Assembles a multi-page PDF with two embedded Helvetica fonts."""

    def __init__(self):
        self.pages: List[List[str]] = []   # each page = list of content-stream ops
        self._new_page()

    def _new_page(self):
        self.pages.append([])
        self._y = _PAGE_H - _MARGIN

    @property
    def _ops(self) -> List[str]:
        return self.pages[-1]

    def _ensure_space(self, needed: int = _LINE_H):
        if self._y - needed < _MARGIN:
            self._new_page()

    # ── drawing helpers ──────────────────────────────────────────────────
    def text(self, x: float, y: float, string: str, size: int = 10,
             font: str = _FONT_REG, gray: float = 0.0):
        self._ops.append(
            f"BT /{font} {size} Tf {gray:.2f} g "
            f"{x:.1f} {y:.1f} Td ({_esc(string)}) Tj ET"
        )

    def line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5):
        self._ops.append(f"{width:.2f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def rect(self, x: float, y: float, w: float, h: float, gray: float = 0.92):
        self._ops.append(f"{gray:.2f} g {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f 0 g")

    # ── high-level blocks ────────────────────────────────────────────────
    def heading(self, string: str, size: int = 18):
        self._ensure_space(size + 8)
        self.text(_MARGIN, self._y, string, size=size, font=_FONT_BOLD)
        self._y -= size + 6

    def body(self, string: str, size: int = 10, gray: float = 0.0,
             indent: int = 0):
        self._ensure_space(_LINE_H)
        self.text(_MARGIN + indent, self._y, string, size=size, gray=gray)
        self._y -= _LINE_H

    def gap(self, amount: int = 8):
        self._y -= amount

    def table_header(self):
        self._ensure_space(_LINE_H + 4)
        x = _MARGIN
        self.rect(_MARGIN, self._y - 4, _PAGE_W - 2 * _MARGIN, _LINE_H + 2,
                  gray=0.88)
        for label, w in _COLS:
            self.text(x + 2, self._y, label, size=9, font=_FONT_BOLD)
            x += w
        self._y -= _LINE_H + 4

    def table_row(self, cells: List[str], sev: str = ""):
        # estimate wrapped height conservatively by longest cell
        max_chars = max((len(c) // (w // 6) for c, (_, w) in zip(cells, _COLS)),
                        default=1)
        rows = max(1, min(max_chars, 3))
        self._ensure_space(_LINE_H * rows + _ROW_PAD)
        x = _MARGIN
        y0 = self._y
        for cell, (label, w) in zip(cells, _COLS):
            clipped = _truncate(cell, w // 5 + 4)
            self.text(x + 2, y0, clipped, size=8)
            x += w
        self._y -= _LINE_H * rows + _ROW_PAD
        self.line(_MARGIN, self._y + 2, _PAGE_W - _MARGIN, self._y + 2,
                  width=0.3)

    # ── serialisation ────────────────────────────────────────────────────
    def render(self) -> bytes:
        objects: List[bytes] = []

        def add(obj) -> int:
            if isinstance(obj, str):
                objects.append(obj.encode("latin-1"))
            else:
                objects.append(obj)
            return len(objects)          # 1-based object number

        # Fonts (objects 1 & 2)
        add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{_FONT_REG} "
            f"/Encoding /WinAnsiEncoding >>")
        add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{_FONT_BOLD} "
            f"/Encoding /WinAnsiEncoding >>")

        # Content streams (one per page)
        content_ids = []
        for ops in self.pages:
            stream = "\n".join(ops).encode("latin-1", "replace")
            header = f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            cid = add(header + stream + b"\nendstream")
            content_ids.append(cid)

        # Page objects reference the Pages tree; we know its id in advance
        # because it is the next object added after all page objects.
        pages_id = len(objects) + len(content_ids) + 1
        page_ids = []
        for cid in content_ids:
            pid = add(
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
                f"/Resources << /Font << /{_FONT_REG} 1 0 R "
                f"/{_FONT_BOLD} 2 0 R >> >> "
                f"/Contents {cid} 0 R >>"
            )
            page_ids.append(pid)

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        actual_pages_id = add(
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>"
        )
        assert actual_pages_id == pages_id, "pages id forward-ref mismatch"
        catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        # xref table
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]                       # object 0 is the free head
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode("latin-1") + obj + b"\nendobj\n"
        xref_pos = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode("latin-1")
        out += (f"trailer\n<< /Size {len(objects) + 1} "
                f"/Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_pos}\n%%EOF\n").encode("latin-1")
        return bytes(out)


def export_pdf(path: str, results: List[Finding]) -> bool:
    """Write the findings as a real PDF report.

    Args:
        path: Output file path (should end with ``.pdf``).
        results: Findings to include.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    try:
        writer = _PdfWriter()
        total = len(results)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in results:
            sev = str(getattr(f, "severity", "INFO") or "INFO").upper()
            if sev in counts:
                counts[sev] += 1

        writer.heading("KernelSpy Scanner - Security Report")
        writer.body(f"Generated: {_fmt_ts()}", size=9, gray=0.35)
        writer.body(f"Total findings: {total}    "
                    f"CRITICAL {counts['CRITICAL']}   "
                    f"HIGH {counts['HIGH']}   "
                    f"MEDIUM {counts['MEDIUM']}   "
                    f"LOW {counts['LOW']}   INFO {counts['INFO']}",
                    size=9, gray=0.2)
        writer.gap(6)
        writer.line(_MARGIN, writer._y, _PAGE_W - _MARGIN, writer._y,
                    width=1.0)
        writer.gap(10)

        if not results:
            writer.body("No findings to report.", size=11, gray=0.4)
        else:
            writer.table_header()
            for f in results:
                sev = str(getattr(f, "severity", "") or "").upper()
                writer.table_row([
                    sev,
                    str(getattr(f, "file", "")),
                    str(getattr(f, "line", "")),
                    str(getattr(f, "type", "")),
                    str(getattr(f, "category", "")),
                ], sev=sev)

        data = writer.render()
        # ensure parent dir exists
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return True
    except Exception:
        return False

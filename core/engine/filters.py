"""Report filters for KernelSpy 1.5.0.

Two capabilities run once per scan, over the combined finding list, before
deduplication:

1. Inline Suppression (SAST comments) - feature 5
   A developer who reviewed a line can silence it permanently::

       # kernelspy-ignore                       (everything on the line)
       # kernelspy-ignore: all
       // kernelspy-ignore: B404, strcpy
       /* kernelspy-ignore: Mass Assignment (Rails) */
       eval(x)   # kernelspy-ignore: eval        (trailing comment)

   The tag is honoured when it sits on the finding's own line (trailing
   comment) or on the line directly above it (next-line style).

2. Scope-Aware Pattern Matching - feature 3
   Framework rules only fire when the project really is that framework::

       Mass Assignment (Rails)  ->  needs a Rails marker (Gemfile, config.ru,
                                    config/application.rb, ...) in the scanned
                                    tree AND a database write call that is
                                    actually fed from ``params``.

   Without the scope gate a bare ``params[`` match (PHP, JS, plain Ruby ...)
   is reported as a Rails mass-assignment bug - a false positive.
"""

import os
import re
from typing import Dict, List, Optional, Set

from ..models import Finding


class SourceLoader:
    """Reads (and caches) the source files of a scan root.

    Every post-processor works on relative finding paths; the loader resolves
    them against the scan root and never raises - a missing/unreadable file
    simply yields no lines, which makes the callers skip their check.
    """

    def __init__(self, root=None):
        self.root = str(root) if root else ""
        self._cache: Dict[str, List[str]] = {}

    def lines(self, relpath: str) -> List[str]:
        key = str(relpath or "")
        if key in self._cache:
            return self._cache[key]
        data: List[str] = []
        if self.root and key:
            try:
                with open(os.path.join(self.root, key), "r",
                          encoding="utf-8", errors="ignore") as fh:
                    data = fh.read().split("\n")
            except Exception:
                data = []
        if len(self._cache) < 4096:
            self._cache[key] = data
        return data

    def line(self, relpath: str, line_no: int) -> str:
        lines = self.lines(relpath)
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    def statement(self, relpath: str, line_no: int, span: int = 3) -> str:
        """The call site plus the next few lines (multiline calls)."""
        lines = self.lines(relpath)
        if not lines or line_no <= 0:
            return ""
        chunk = lines[max(0, line_no - 1): max(0, line_no - 1) + span]
        return " ".join(s.strip() for s in chunk if s.strip())[:600]


# ════════════════════════════════════════════════════════════════════
#  Feature 5 - inline suppression
# ════════════════════════════════════════════════════════════════════
_TAG_RE = re.compile(r"kernelspy-ignore(?:\s*:\s*([^*\n\r]+))?", re.IGNORECASE)

# Markers that must appear before the tag on the same line, so a plain
# string literal containing the words never suppresses anything.
_COMMENT_MARKERS = ("//", "#", ";", "--", "/*", "*", "%")

_SUPPRESS_ALL = {"", "all", "*", "any", "true"}


def _ignore_spec(line_text: str) -> Optional[str]:
    """Return the rule list of a ``kernelspy-ignore`` tag, else None."""
    if not line_text:
        return None
    m = _TAG_RE.search(line_text)
    if not m:
        return None
    prefix = line_text[:m.start()]
    if not any(marker in prefix for marker in _COMMENT_MARKERS):
        return None                      # not inside a comment -> ignore tag
    return (m.group(1) or "").strip()    # "" = bare tag, suppress everything


def _finding_matches_spec(finding: Finding, spec: Optional[str]) -> bool:
    spec = (spec or "").strip().lower()
    if spec in _SUPPRESS_ALL:
        return True

    blob_parts = [
        str(getattr(finding, "type", "")),
        str(getattr(finding, "category", "")),
        str(getattr(finding, "analyzer", "")),
    ]
    try:
        blob_parts.extend(str(a) for a in finding.analyzer_list)
    except Exception:
        pass
    blob = " ".join(blob_parts).lower()

    for token in re.split(r"[,\s]+", spec):
        token = token.strip()
        if token and token in blob:
            return True
    return spec in blob                    # multi-word rule name in the tag


def _is_suppressed(finding: Finding, loader: Optional[SourceLoader]) -> bool:
    line_no = int(getattr(finding, "line", 0) or 0)
    if line_no <= 0 or loader is None:
        return False
    for candidate in (loader.line(finding.file, line_no),
                      loader.line(finding.file, line_no - 1)):
        spec = _ignore_spec(candidate)
        if spec is not None and _finding_matches_spec(finding, spec):
            return True
    return False


def apply_inline_suppressions(findings: List[Finding],
                              loader: Optional[SourceLoader]) -> List[Finding]:
    """Drop findings a developer marked with ``kernelspy-ignore``."""
    if not findings or loader is None:
        return findings
    kept: List[Finding] = []
    for f in findings:
        if not _is_suppressed(f, loader):
            kept.append(f)
    return kept


# ════════════════════════════════════════════════════════════════════
#  Feature 3 - scope aware pattern matching
# ════════════════════════════════════════════════════════════════════
_RAILS_MARKERS = {
    "Gemfile", "Gemfile.lock", "config.ru", "Rakefile", "Procfile",
}

_rails_cache: Dict[str, bool] = {}


def is_rails_project(root) -> bool:
    """True when the scanned tree looks like a Ruby on Rails application.

    The check is a shallow directory scan (a handful of stat calls) and is
    performed once per scan, only when a Rails-scoped rule actually fired.
    """
    if not root:
        return False

    found = False
    try:
        for entry in os.scandir(str(root)):
            if entry.is_file() and entry.name in _RAILS_MARKERS:
                found = True
                break
            if entry.is_dir() and entry.name in ("config", "bin", "app"):
                try:
                    sub = set(os.listdir(entry.path))
                except OSError:
                    continue
                if entry.name == "config" and "application.rb" in sub:
                    found = True
                    break
                if entry.name == "bin" and "rails" in sub:
                    found = True
                    break
                if entry.name == "app" and "models" in sub:
                    found = True
                    break
    except Exception:
        found = False
    return found


# params flowing into a database write -> real mass assignment risk
_RAILS_WRITE = re.compile(
    r"(?:attr_accessible|permit!"
    r"|\.(?:new|create|create!|update|update!|update_attributes!?"
    r"|assign_attributes|attributes\s*=|save)\s*\(?\s*params"
    r"|\bparams\s*\[[^\]]*\]\s*\.permit!?"
    r"|\bparams\.require\b)",
    re.IGNORECASE,
)

_SCOPE_GATES = {
    "Mass Assignment (Rails)": lambda text, loader: bool(_RAILS_WRITE.search(text)),
}


def _scope_ok(finding: Finding, loader: Optional[SourceLoader],
              is_rails: bool) -> bool:
    gate = _SCOPE_GATES.get(str(finding.type or ""))
    if gate is None:
        return True                       # not a framework scoped rule
    if not is_rails:
        return False                      # not a Rails project at all

    line_no = int(getattr(finding, "line", 0) or 0)
    text = loader.statement(finding.file, line_no) if loader else ""
    text = text or finding.snippet
    return gate(text, loader)


def apply_scope_gates(findings: List[Finding],
                      loader: Optional[SourceLoader]) -> List[Finding]:
    """Drop framework findings whose scope conditions are not satisfied."""
    if not findings:
        return findings
    needs_scope = [f for f in findings if str(f.type or "") in _SCOPE_GATES]
    if not needs_scope:
        return findings

    is_rails = is_rails_project(getattr(loader, "root", None))
    return [f for f in findings if _scope_ok(f, loader, is_rails)]

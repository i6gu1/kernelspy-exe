from typing import List

from ..models import Finding
from ..engine.context import strip_comments_and_strings
from ..engine.patterns import ContentContext, scan_content_for_rules
from ..engine.taint_tracker import SOURCES, SINKS, TaintTracker


class GenericAnalyzer:
    def __init__(self):
        self._taint = TaintTracker()

    def analyze(self, filepath: str, content: str, compiled_rules: List) -> List[Finding]:
        ext = '.' + filepath.rsplit('.', 1)[-1] if '.' in filepath else ''
        findings: List[Finding] = []
        clean = strip_comments_and_strings(content, ext)
        if compiled_rules:
            findings.extend(scan_content_for_rules(
                filepath, compiled_rules, ContentContext(clean)))
        if ext in SOURCES and ext in SINKS:
            # Taint tables cover Go/C#/Ruby/Kotlin/Lua/Perl/C-C++ sources
            # and sinks; Python/PHP/JS/Java run taint in their own analyzers.
            findings.extend(self._taint.analyze(filepath, content, ext))
        return findings
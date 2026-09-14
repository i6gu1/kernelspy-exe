from typing import List

from ..models import Finding
from ..engine.context import strip_comments_and_strings
from ..engine.patterns import ContentContext, scan_content_for_rules
from ..engine.taint_tracker import SOURCES, SINKS, TaintTracker
from ..engine.lexer_analyzer import LexerAnalyzer


class GenericAnalyzer:
    def __init__(self):
        self._taint = TaintTracker()
        self._lexer = LexerAnalyzer()

    def analyze(self, filepath: str, content: str, compiled_rules: List) -> List[Finding]:
        ext = '.' + filepath.rsplit('.', 1)[-1] if '.' in filepath else ''
        findings: List[Finding] = []
        clean = strip_comments_and_strings(content, ext)
        
        # Lexer-based detection for all languages
        findings.extend(self._lexer.analyze(filepath, content, ext))
        
        # Pattern rules
        if compiled_rules:
            findings.extend(scan_content_for_rules(
                filepath, compiled_rules, ContentContext(clean)))
        
        # Taint tracking for languages with defined sources/sinks
        if ext in SOURCES and ext in SINKS:
            findings.extend(self._taint.analyze(filepath, content, ext))
        
        return findings
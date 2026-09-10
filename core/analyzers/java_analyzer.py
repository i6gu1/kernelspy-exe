from typing import List

from ..models import Finding
from ..engine.lexer_analyzer import LexerAnalyzer
from ..engine.taint_tracker import TaintTracker
from ..engine.context import strip_comments_and_strings
from ..engine.patterns import ContentContext, scan_content_for_rules


class JavaAnalyzer:
    def __init__(self):
        self.lexer_analyzer = LexerAnalyzer()
        self.taint_tracker = TaintTracker()

    def analyze(self, filepath: str, content: str, compiled_rules: List) -> List[Finding]:
        findings = []
        clean = strip_comments_and_strings(content, '.java')
        findings.extend(self.lexer_analyzer.analyze(filepath, content, '.java'))
        if compiled_rules:
            findings.extend(scan_content_for_rules(
                filepath, compiled_rules, ContentContext(clean)))
        findings.extend(self.taint_tracker.analyze(filepath, content, '.java'))
        return findings
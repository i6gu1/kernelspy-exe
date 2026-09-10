from typing import List

from ..models import Finding
from ..engine.ast_analyzer import PythonASTAnalyzer
from ..engine.taint_tracker import TaintTracker
from ..engine.context import strip_comments_and_strings
from ..engine.patterns import ContentContext, scan_content_for_rules


class PythonAnalyzer:
    def __init__(self):
        self.ast_analyzer = PythonASTAnalyzer()
        self.taint_tracker = TaintTracker()

    def analyze(self, filepath: str, content: str, compiled_rules: List) -> List[Finding]:
        findings = []
        clean = strip_comments_and_strings(content, '.py')
        findings.extend(self.ast_analyzer.analyze(filepath, content))
        if compiled_rules:
            findings.extend(scan_content_for_rules(
                filepath, compiled_rules, ContentContext(clean)))
        findings.extend(self.taint_tracker.analyze(filepath, content, '.py'))
        return findings
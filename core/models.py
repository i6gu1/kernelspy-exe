from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.order < other.order
        return NotImplemented


class AnalyzerType(Enum):
    PATTERN = "pattern"
    AST = "ast"
    LEXER = "lexer"
    TAINT = "taint"
    BANDIT = "bandit"
    DEPENDENCY = "dependency"
    FILE = "file"
    TREE_SITTER = "tree_sitter"
    CPG = "cpg"
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    SONAR = "sonar"
    AI = "ai"


class Category(Enum):
    INJECTION = "INJECTION"
    XSS = "XSS"
    TRAVERSAL = "TRAVERSAL"
    DESERIALIZATION = "DESERIALIZATION"
    CRYPTO = "CRYPTO"
    SSRF = "SSRF"
    CONFIG = "CONFIG"
    NETWORK = "NETWORK"
    AUTH = "AUTH"
    SESSION = "SESSION"
    UPLOAD = "UPLOAD"
    INFO = "INFO"
    LOGIC = "LOGIC"
    REDIRECT = "REDIRECT"
    SECRET = "SECRET"
    CLOUD = "CLOUD"
    PAYMENT = "PAYMENT"
    VCS = "VCS"
    CHAT = "CHAT"
    COMM = "COMM"
    SOCIAL = "SOCIAL"
    PACKAGE = "PACKAGE"
    EMAIL = "EMAIL"
    DATABASE = "DATABASE"
    AI = "AI"
    DEPENDENCY = "DEPENDENCY"
    BANDIT = "BANDIT"
    PYTHON = "PYTHON"
    JAVASCRIPT = "JAVASCRIPT"
    PHP = "PHP"
    JAVA = "JAVA"
    CSHARP = "C#"
    GO = "GO"
    RUBY = "RUBY"
    RUST = "RUST"
    LUA = "LUA"
    PERL = "PERL"
    KOTLIN = "KOTLIN"
    SWIFT = "SWIFT"


@dataclass
class Finding:
    file: str
    line: int
    type: str
    severity: str
    snippet: str
    description: str
    category: str = "SECRET"
    analyzer: str = "pattern"

    @property
    def severity_enum(self) -> Severity:
        try:
            return Severity(self.severity)
        except ValueError:
            return Severity.INFO

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "severity": self.severity,
            "snippet": self.snippet,
            "description": self.description,
            "category": self.category,
            "analyzer": self.analyzer,
        }


@dataclass
class TaintPath:
    source_line: int
    source_var: str
    sink_line: int
    sink_func: str
    path_vars: List[str] = field(default_factory=list)

    def to_finding(self, file: str, severity: str = "CRITICAL") -> Finding:
        desc = (
            f"Taint flow: variable '{self.source_var}' (line {self.source_line}) "
            f"flows into dangerous sink '{self.sink_func}' (line {self.sink_line}). "
            f"Path: {' -> '.join(self.path_vars)}"
        )
        return Finding(
            file=file,
            line=self.sink_line,
            type=f"Taint: {self.source_var} -> {self.sink_func}",
            severity=severity,
            snippet=f"{self.source_var} -> {self.sink_func}",
            description=desc,
            category="INJECTION",
            analyzer="taint",
        )


@dataclass
class FileContext:
    filepath: str
    extension: str
    language: str
    content: str
    lines: List[str] = field(default_factory=list)
    non_comment_indices: List[int] = field(default_factory=list)
    non_string_indices: List[int] = field(default_factory=list)
    clean_content: str = ""

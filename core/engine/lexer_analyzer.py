import re
from typing import List, Set

from ..models import Finding


class LexerToken:
    __slots__ = ('type', 'value', 'line', 'col')

    def __init__(self, type_: str, value: str, line: int, col: int):
        self.type = type_
        self.value = value
        self.line = line
        self.col = col


class Lexer:
    TOKEN_SPEC = [
        ('COMMENT_SINGLE', r'//.*'),
        ('COMMENT_MULTI', r'/\*[\s\S]*?\*/'),
        ('COMMENT_HASH', r'#[^\n]*'),
        ('STRING_SINGLE', r"'(?:\\.|[^'\\])*'"),
        ('STRING_DOUBLE', r'"(?:\\.|[^"\\])*"'),
        ('VARIABLE', r'\$\w+'),
        ('FUNCTION_CALL', r'\b\w+(?=\s*\()'),
        ('NUMBER', r'\b\d+(?:\.\d+)?\b'),
        ('OPERATOR', r'[+\-*/%=<>!&|^~?:]+'),
        ('PUNCTUATION', r'[(){}\[\];,.]'),
        ('IDENT', r'\b[a-zA-Z_]\w*\b'),
        ('NEWLINE', r'\n'),
        ('SKIP', r'[ \t]+'),
    ]

    def __init__(self):
        self._tok_regex = '|'.join(
            f'(?P<{name}>{pattern})' for name, pattern in self.TOKEN_SPEC
        )
        self._re = re.compile(self._tok_regex)

    def tokenize(self, code: str) -> List[LexerToken]:
        tokens = []
        line_num = 1
        line_start = 0

        for m in self._re.finditer(code):
            kind = m.lastgroup
            value = m.group()
            col = m.start() - line_start

            if kind == 'NEWLINE':
                line_num += 1
                line_start = m.end()
                continue
            if kind == 'SKIP':
                continue
            if kind.startswith('COMMENT'):
                continue
            if kind.startswith('STRING'):
                continue

            tokens.append(LexerToken(kind, value, line_num, col))

        return tokens


DANGEROUS_FUNCS = {
    '.php': {
        'eval': ('CRITICAL', 'INJECTION'), 'exec': ('CRITICAL', 'INJECTION'),
        'system': ('CRITICAL', 'INJECTION'), 'passthru': ('CRITICAL', 'INJECTION'),
        'shell_exec': ('CRITICAL', 'INJECTION'), 'popen': ('HIGH', 'INJECTION'),
        'proc_open': ('HIGH', 'INJECTION'), 'pcntl_exec': ('HIGH', 'INJECTION'),
        'assert': ('HIGH', 'INJECTION'), 'create_function': ('CRITICAL', 'INJECTION'),
        'unserialize': ('CRITICAL', 'DESERIALIZATION'),
        'preg_replace': ('CRITICAL', 'INJECTION'),
    },
    '.js': {
        'eval': ('HIGH', 'INJECTION'), 'exec': ('HIGH', 'INJECTION'),
    },
    '.ts': {
        'eval': ('HIGH', 'INJECTION'),
    },
    '.java': {
        'exec': ('CRITICAL', 'INJECTION'),
    },
}

XSS_IDS = {
    'innerHTML', 'outerHTML', 'document', 'insertAdjacentHTML',
}


class LexerAnalyzer:
    """Token-based analyzer that only examines code tokens, never comments or
    string literals."""

    def __init__(self):
        self.lexer = Lexer()

    def analyze(self, filepath: str, content: str, extension: str) -> List[Finding]:
        findings: List[Finding] = []
        tokens = self.lexer.tokenize(content)
        lines = content.split('\n')

        for token in tokens:
            if token.type == 'FUNCTION_CALL' and token.value in DANGEROUS_FUNCS.get(extension, {}):
                sev, cat = DANGEROUS_FUNCS[extension][token.value]
                line_text = lines[token.line - 1].strip() if token.line <= len(lines) else ''
                findings.append(Finding(
                    file=filepath,
                    line=token.line,
                    type=f"Lexer: {token.value}()",
                    severity=sev,
                    snippet=line_text[:120],
                    description=f"Lexer detected dangerous function '{token.value}()'.",
                    category=cat,
                    analyzer="lexer",
                ))

        if extension in ('.js', '.ts', '.jsx', '.tsx'):
            for i, token in enumerate(tokens):
                if token.type == 'IDENT' and token.value in XSS_IDS:
                    if i + 1 < len(tokens) and tokens[i + 1].value in ('=', '('):
                        line_text = lines[token.line - 1].strip() if token.line <= len(lines) else ''
                        findings.append(Finding(
                            file=filepath,
                            line=token.line,
                            type=f"Lexer: XSS sink '{token.value}'",
                            severity='HIGH',
                            snippet=line_text[:120],
                            description=f"Lexer detected XSS sink '{token.value}'.",
                            category='XSS',
                            analyzer="lexer",
                        ))

        return findings
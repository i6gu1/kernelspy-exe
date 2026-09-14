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
        'array_map': ('HIGH', 'INJECTION'), 'call_user_func': ('HIGH', 'INJECTION'),
        'include': ('CRITICAL', 'TRAVERSAL'), 'require': ('CRITICAL', 'TRAVERSAL'),
        'extract': ('HIGH', 'INJECTION'), 'parse_str': ('HIGH', 'INJECTION'),
    },
    '.js': {
        'eval': ('HIGH', 'INJECTION'), 'exec': ('HIGH', 'INJECTION'),
        'Function': ('HIGH', 'INJECTION'),
        'setTimeout': ('MEDIUM', 'INJECTION'), 'setInterval': ('MEDIUM', 'INJECTION'),
    },
    '.ts': {
        'eval': ('HIGH', 'INJECTION'),
        'Function': ('HIGH', 'INJECTION'),
    },
    '.jsx': {
        'eval': ('HIGH', 'INJECTION'),
        'Function': ('HIGH', 'INJECTION'),
    },
    '.tsx': {
        'eval': ('HIGH', 'INJECTION'),
        'Function': ('HIGH', 'INJECTION'),
    },
    '.java': {
        'exec': ('CRITICAL', 'INJECTION'),
        'Runtime': ('CRITICAL', 'INJECTION'),
        'ProcessBuilder': ('HIGH', 'INJECTION'),
        'XMLDecoder': ('CRITICAL', 'DESERIALIZATION'),
        'ObjectInputStream': ('CRITICAL', 'DESERIALIZATION'),
        'XStream': ('CRITICAL', 'DESERIALIZATION'),
    },
    '.go': {
        'exec.Command': ('HIGH', 'INJECTION'),
        'os.Execute': ('CRITICAL', 'INJECTION'),
        'os.Open': ('MEDIUM', 'TRAVERSAL'),
        'http.Get': ('MEDIUM', 'SSRF'),
        'http.Post': ('MEDIUM', 'SSRF'),
        'http.ListenAndServe': ('MEDIUM', 'CONFIG'),
    },
    '.rb': {
        'eval': ('HIGH', 'INJECTION'),
        'exec': ('HIGH', 'INJECTION'),
        'system': ('HIGH', 'INJECTION'),
        'load': ('HIGH', 'DESERIALIZATION'),
        'send': ('HIGH', 'INJECTION'),
    },
    '.cs': {
        'SqlCommand': ('CRITICAL', 'INJECTION'),
        'Process': ('MEDIUM', 'INJECTION'),
        'BinaryFormatter': ('CRITICAL', 'DESERIALIZATION'),
        'XmlSerializer': ('MEDIUM', 'XSS'),
        'DirectorySearcher': ('HIGH', 'INJECTION'),
    },
    '.c': {
        'system': ('HIGH', 'INJECTION'),
        'popen': ('HIGH', 'INJECTION'),
        'exec': ('CRITICAL', 'INJECTION'),
        'strcpy': ('HIGH', 'INJECTION'),
        'strcat': ('HIGH', 'INJECTION'),
        'sprintf': ('HIGH', 'INJECTION'),
        'gets': ('CRITICAL', 'INJECTION'),
        'scanf': ('HIGH', 'INJECTION'),
        'malloc': ('MEDIUM', 'CONFIG'),
    },
    '.cpp': {
        'system': ('HIGH', 'INJECTION'),
        '_popen': ('HIGH', 'INJECTION'),
        'exec': ('CRITICAL', 'INJECTION'),
        'strcpy': ('HIGH', 'INJECTION'),
        'strcat': ('HIGH', 'INJECTION'),
        'sprintf': ('HIGH', 'INJECTION'),
        'gets': ('CRITICAL', 'INJECTION'),
        'scanf': ('HIGH', 'INJECTION'),
    },
    '.h': {
        'system': ('HIGH', 'INJECTION'),
        'strcpy': ('HIGH', 'INJECTION'),
        'strcat': ('HIGH', 'INJECTION'),
        'sprintf': ('HIGH', 'INJECTION'),
        'gets': ('CRITICAL', 'INJECTION'),
    },
    '.hpp': {
        'system': ('HIGH', 'INJECTION'),
        'strcpy': ('HIGH', 'INJECTION'),
        'strcat': ('HIGH', 'INJECTION'),
        'sprintf': ('HIGH', 'INJECTION'),
        'gets': ('CRITICAL', 'INJECTION'),
    },
    '.kt': {
        'exec': ('CRITICAL', 'INJECTION'),
        'Runtime': ('CRITICAL', 'INJECTION'),
        'ProcessBuilder': ('HIGH', 'INJECTION'),
        'rawQuery': ('HIGH', 'INJECTION'),
        'execSQL': ('CRITICAL', 'INJECTION'),
        'loadUrl': ('MEDIUM', 'XSS'),
    },
    '.swift': {
        'Process': ('HIGH', 'INJECTION'),
        'executeQuery': ('CRITICAL', 'INJECTION'),
        'NSAppleScript': ('HIGH', 'INJECTION'),
        'evaluateJavaScript': ('MEDIUM', 'XSS'),
    },
    '.scala': {
        'exec': ('CRITICAL', 'INJECTION'),
        'Runtime': ('CRITICAL', 'INJECTION'),
        'execute': ('CRITICAL', 'INJECTION'),
        'process': ('HIGH', 'INJECTION'),
    },
    '.dart': {
        'Process': ('HIGH', 'INJECTION'),
        'execute': ('CRITICAL', 'INJECTION'),
        'rawQuery': ('HIGH', 'INJECTION'),
        'eval': ('HIGH', 'INJECTION'),
    },
    '.pl': {
        'system': ('HIGH', 'INJECTION'),
        'exec': ('HIGH', 'INJECTION'),
        'eval': ('HIGH', 'INJECTION'),
        'open': ('HIGH', 'INJECTION'),
    },
    '.pm': {
        'system': ('HIGH', 'INJECTION'),
        'exec': ('HIGH', 'INJECTION'),
        'eval': ('HIGH', 'INJECTION'),
    },
    '.lua': {
        'loadstring': ('HIGH', 'INJECTION'),
        'load': ('HIGH', 'INJECTION'),
        'dofile': ('HIGH', 'INJECTION'),
        'os.execute': ('HIGH', 'INJECTION'),
        'io.popen': ('HIGH', 'INJECTION'),
    },
    '.rs': {
        'Command': ('HIGH', 'INJECTION'),
        'exec': ('CRITICAL', 'INJECTION'),
        'system': ('HIGH', 'INJECTION'),
    },
}

XSS_IDS = {
    'innerHTML', 'outerHTML', 'document', 'insertAdjacentHTML',
    'dangerouslySetInnerHTML', 'v-html',
}

SQL_KEYWORDS = {
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
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

        # XSS detection for JS/TS/JSX/TSX
        if extension in ('.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte'):
            for i, token in enumerate(tokens):
                if token.type == 'IDENT' and token.value in XSS_IDS:
                    if i + 1 < len(tokens) and tokens[i + 1].value in ('=', '(', '[', '{'):
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

        # SQL injection detection for all languages
        if extension in ('.js', '.ts', '.jsx', '.tsx', '.php', '.java', '.cs',
                         '.go', '.rb', '.py', '.kt', '.scala', '.dart'):
            for i, token in enumerate(tokens):
                if token.type == 'IDENT' and token.value.lower() in ('query', 'execute', 'raw',
                    'executescript', 'executescalar', 'executenonquery', 'rawquery',
                    'execsql', 'find_by_sql', 'findbysql', 'sql', 'select', 'insert'):
                    # Check if followed by parenthesis (function call)
                    if i + 1 < len(tokens) and tokens[i + 1].value == '(':
                        # Check if the argument contains string concatenation
                        if i + 2 < len(tokens) and tokens[i + 2].value in ('"', "'", '+'):
                            line_text = lines[token.line - 1].strip() if token.line <= len(lines) else ''
                            findings.append(Finding(
                                file=filepath,
                                line=token.line,
                                type=f"Lexer: SQL injection via {token.value}()",
                                severity='CRITICAL',
                                snippet=line_text[:120],
                                description=f"Potential SQL injection in {token.value}() - string concatenation detected.",
                                category='INJECTION',
                                analyzer="lexer",
                            ))

        return findings
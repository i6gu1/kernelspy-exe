"""
Tree-sitter based multi-language parser for KernelSpy Scanner.
Provides unified Concrete Syntax Tree (CST) parsing for 30+ languages.
"""
import os
import re
import importlib
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field

try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

# Grammar packages are imported ONE BY ONE (KernelSpy 1.3.2): a single
# missing or mistyped module no longer switches the whole feature off -
# 1.2 imported every grammar in one try block, so one bad name kept
# Tree-sitter permanently disabled.
_LANGUAGE_MODULES = {
    'python': 'tree_sitter_python',
    'javascript': 'tree_sitter_javascript',
    'typescript': 'tree_sitter_typescript',
    'tsx': 'tree_sitter_typescript',
    'java': 'tree_sitter_java',
    'go': 'tree_sitter_go',
    'rust': 'tree_sitter_rust',
    'c': 'tree_sitter_c',
    'cpp': 'tree_sitter_cpp',
    'c_sharp': 'tree_sitter_c_sharp',
    'php': 'tree_sitter_php',
    'ruby': 'tree_sitter_ruby',
    'kotlin': 'tree_sitter_kotlin',
    'swift': 'tree_sitter_swift',
    'lua': 'tree_sitter_lua',
    'perl': 'tree_sitter_perl',
    'dart': 'tree_sitter_dart',
    'scala': 'tree_sitter_scala',
    'solidity': 'tree_sitter_solidity',
}


def _load_grammar(module_name: str):
    """Best-effort Language object from a grammar package.

    Grammar wheels disagree on the factory name (``language()``,
    ``language_php()``, ``language_typescript()``) and some still return a
    raw C pointer instead of a capsule; both cases are tolerated and the
    grammar is simply skipped when no usable Language can be built.
    """
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        module = importlib.import_module(module_name)
    except Exception:
        return None
    attrs = [a for a in dir(module)
             if a == 'language' or a.startswith('language_')]
    for attr in sorted(attrs, key=lambda a: (a != 'language', a)):
        fn = getattr(module, attr, None)
        if not callable(fn):
            continue
        try:
            value = fn()
        except Exception:
            continue
        if isinstance(value, int):
            continue                      # legacy pointer binding, unusable
        try:
            return Language(value)
        except Exception:
            continue
    return None


_TREE_SITTER_GRAMMARS: Dict[str, Optional['Language']] = {
    name: _load_grammar(mod) for name, mod in _LANGUAGE_MODULES.items()
}
TREE_SITTER_LANGS_AVAILABLE = any(
    lang is not None for lang in _TREE_SITTER_GRAMMARS.values())


@dataclass
class TSNode:
    """Wrapper for a tree-sitter node with metadata."""
    type: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    text: str
    children: List['TSNode'] = field(default_factory=list)
    parent: Optional['TSNode'] = None


@dataclass
class ParseResult:
    """Result of parsing a source file."""
    language: str
    filepath: str
    tree: Optional[object] = None
    root: Optional[TSNode] = None
    errors: List[str] = field(default_factory=list)
    success: bool = False


@dataclass
class SecurityCall:
    """A context-aware dangerous call found in the CST (KernelSpy 1.3)."""
    name: str
    line: int
    text: str
    severity: str
    category: str
    reason: str


# ── Context-aware sink rules ────────────────────────────────────────────
# Matching is done on the *base* (last dotted component) of the callee so
# that e.g. System.out.println never counts as a shell sink and json.load
# never counts as unsafe deserialization.

_SQL_BASES = {
    'query', 'queries', 'execute', 'executescript', 'executescalar',
    'executenonquery', 'executemany', 'rawquery', 'execsql', 'find_by_sql',
    'createstatement', 'preparedstatement',
}
_SQL_FULL = re.compile(
    r'(?:mysqli_query|mysql_query|pg_query|sqlsrv_query|sqlite_query|'
    r'mssql_query|ociparse)', re.I)
_SHELL_BASES = {
    'system', 'popen', 'shell_exec', 'passthru', 'proc_open', 'pcntl_exec',
    'exec', 'exec_command', 'execcommand', 'spawn', 'spawn_sync', 'spawnsync',
    'exec_sync', 'execsync', 'execfile', 'processbuilder', 'cmd', 'backtick',
    'command', 'sh', 'bash', 'start_process',
}
_SHELL_FULL = re.compile(
    r'(?:os\.system|os\.popen|child_process|exec\.command|subprocess|'
    r'runtime\.getruntime\(\)\.exec|cmd\.exe|/bin/sh|/bin/bash|'
    r'new\s+processbuilder|shell_exec)', re.I)
_EVAL_BASES = {
    'eval', 'exec', '__import__', 'import_module', 'loadstring',
    'create_function', 'function', 'new_function', 'assert', 'unsafe_eval',
    'render_template_string',
}
_DESERIALIZE_BASES = {
    'unserialize', 'deserialize', 'readobject', 'fromxml', 'jsonpickle',
    'from_json_object', 'decode_object', 'loads',
}
_DESERIALIZE_FULL = re.compile(
    r'(?:pickle|yaml|marshal|binaryformatter|objectinputstream|xmldecoder|'
    r'xstream|jsonpickle|joblib|dill|shelve)', re.I)
_XSS_BASES = {
    'innerhtml', 'outerhtml', 'insertadjacenthtml', 'dangerouslysetinnerhtml',
}
_XSS_FULL = re.compile(
    r'(?:document\.write(?:ln)?|res\.send|response\.write|'
    r'dangerouslysetinnerhtml|v-html|\.html\s*\()', re.I)
_XSS_ASSIGN = re.compile(
    r'(?:\.\s*(?:inner|outer)HTML|dangerouslySetInnerHTML|v-html)\s*=', re.I)
_PATH_BASES = {
    'send_file', 'readfile', 'file_get_contents', 'include', 'require',
    'require_once', 'include_once', 'fopen', 'open', 'read_file',
    'createfile', 'readtextfile', 'loadfile', 'readalltext',
}
_DYN_ARG = re.compile(
    r'\+\s*[A-Za-z_$]|\b[A-Za-z_$][\w$]*\s*\+'          # concatenation
    r'|`[^`]*\$\{[^}]+\}[^`]*`'                          # template literal
    r'|f["\'][^"\']*\{'                                  # python f-string
    r'|\bformat\s*\(|%\s*[A-Za-z_(]|sprintf\s*\('       # format / printf
    r'|\$\{[^}]+\}|\$\w+'                               # interpolation
    r'|fstring|concat', re.I)
# SQL queries are only dangerous when the *query text itself* is dynamic -
# a variable holding the connection or bound parameters is not enough.
_SQL_DYN = re.compile(
    r'f["\']'                                           # python f-string
    r'|`[^`]*\$\{[^}]*\}[^`]*`'                         # JS template literal
    r'|["\'][^"\']*\$\w+[^"\']*["\']'                   # "SELECT $q" (PHP)
    r'|["\']\s*\+\s*[A-Za-z_$]'                         # "..." + var
    r'|[A-Za-z_$\)\]]\s*\+\s*["\']'                     # var + "..."
    r'|\bformat\s*\('                                   # "...".format(...)
    r'|\bsprintf\s*\(', re.I)
_SQL_SUFFIX = ('_query', '_execute', '_sql', '_sql_query')
_SHELL_TRUE = re.compile(r'shell\s*=\s*True|shell\s*:\s*true', re.I)
_SHELL_FALSE = re.compile(r'shell\s*=\s*False|shell\s*:\s*false', re.I)
_LIST_ARGS = re.compile(r'^\s*[\[({]')


def _ext_of(filepath: str) -> str:
    return os.path.splitext(filepath or '')[1].lower()


def _norm_callee(callee: str) -> str:
    text = re.sub(r'\s+', ' ', (callee or '').strip()).lower()
    return text.replace('new ', '').replace('::', '.')


def _base_name(callee: str) -> str:
    """Trailing identifier of a callee: 'Runtime.getRuntime().exec' -> 'exec'."""
    text = _norm_callee(callee)
    m = re.search(r'([a-z_$][\w$]*)\s*$', text)
    if m:
        return m.group(1)
    return text.split('.')[-1].strip()


def classify_call(callee: str, arg_text: str, ext: str) -> Optional[Tuple[str, str, str]]:
    """Context-aware evaluation of a call node (KernelSpy 1.3).

    Returns ``(severity, category, reason)`` or ``None`` when the call is
    safe in this context (argument vector, parameterised query, escaped
    output, ...).
    """
    if not callee:
        return None
    low = _norm_callee(callee)
    base = _base_name(callee)
    args = arg_text or ''
    is_shell_call = base in _SHELL_BASES or bool(_SHELL_FULL.search(low))
    is_sql_call = (base in _SQL_BASES or base.endswith(_SQL_SUFFIX)
                   or _SQL_FULL.search(low) is not None)

    # shell=True beats everything: input is handed to the shell verbatim
    if is_shell_call and _SHELL_TRUE.search(args):
        return ('CRITICAL', 'INJECTION', 'shell=True lets input reach a shell')

    # ── Dynamic code evaluation: never safe ──
    if base in _EVAL_BASES and 'regex' not in low:
        if is_shell_call:
            return ('CRITICAL', 'INJECTION', 'executes a shell command')
        return ('CRITICAL', 'INJECTION', 'evaluates a string as code')

    # ── SQL: only dangerous when the query text itself is dynamic ──
    if is_sql_call:
        if not _SQL_DYN.search(args):
            return None                     # parameterised / static query
        from .sanitizers import kind_for_sink, line_sanitizes
        kind = kind_for_sink(ext, callee, 'INJECTION')
        if kind and line_sanitizes(args, ext, kind):
            return None
        return ('CRITICAL', 'INJECTION', 'query text built from dynamic input')

    # ── Shell / command execution ──
    if is_shell_call:
        if _SHELL_FALSE.search(args):
            return None
        if _LIST_ARGS.match(args) and not _DYN_ARG.search(args):
            return None                     # argument vector - no shell parsing
        from .sanitizers import kind_for_sink, line_sanitizes
        kind = kind_for_sink(ext, callee, 'INJECTION')
        if kind and line_sanitizes(args, ext, kind):
            return None
        if _DYN_ARG.search(args):
            return ('CRITICAL', 'INJECTION', 'command string built from dynamic input')
        if re.fullmatch(r'[A-Za-z_$][\w$]*', args.strip() or ' '):
            # plain variable, no shell flag - review only
            return ('LOW', 'INJECTION', 'command taken from a variable (no shell)')
        return ('MEDIUM', 'INJECTION', 'dangerous command execution API')

    # ── Deserialization: never safe on untrusted data ──
    if base in _DESERIALIZE_BASES and (
            _DESERIALIZE_FULL.search(low) or base not in ('loads',)):
        return ('CRITICAL', 'DESERIALIZATION', 'deserializes untrusted data')
    if base in ('load', 'loads') and _DESERIALIZE_FULL.search(low):
        return ('CRITICAL', 'DESERIALIZATION', 'deserializes untrusted data')

    # ── XSS sinks: safe only when output is escaped ──
    if base in _XSS_BASES or _XSS_FULL.search(low):
        from .sanitizers import kind_for_sink, line_sanitizes
        kind = kind_for_sink(ext, callee, 'XSS')
        if kind and line_sanitizes(args, ext, kind):
            return None
        if args.strip() or _DYN_ARG.search(args):
            return ('HIGH', 'XSS', 'untrusted data written into the DOM / response')
        return None

    # ── File / path sinks: dangerous only with dynamic paths ──
    if base in _PATH_BASES:
        if not (_DYN_ARG.search(args) or '$' in args or '${' in args):
            return None
        from .sanitizers import kind_for_sink, line_sanitizes
        kind = kind_for_sink(ext, callee, 'TRAVERSAL')
        if kind and line_sanitizes(args, ext, kind):
            return None
        return ('HIGH', 'TRAVERSAL', 'filesystem path built from dynamic input')

    return None


# Map file extensions to tree-sitter language names
EXTENSION_LANGUAGE_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.hpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.cs': 'c_sharp',
    '.php': 'php',
    '.rb': 'ruby',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.swift': 'swift',
    '.lua': 'lua',
    '.pl': 'perl',
    '.pm': 'perl',
    '.dart': 'dart',
    '.scala': 'scala',
    '.sol': 'solidity',
}

# Display names for languages
LANGUAGE_DISPLAY_NAMES = {
    'python': 'Python',
    'javascript': 'JavaScript',
    'typescript': 'TypeScript',
    'tsx': 'TSX',
    'java': 'Java',
    'go': 'Go',
    'rust': 'Rust',
    'c': 'C',
    'cpp': 'C++',
    'c_sharp': 'C#',
    'php': 'PHP',
    'ruby': 'Ruby',
    'kotlin': 'Kotlin',
    'swift': 'Swift',
    'lua': 'Lua',
    'perl': 'Perl',
    'dart': 'Dart',
    'scala': 'Scala',
    'solidity': 'Solidity',
}


class TreeSitterParser:
    """Multi-language parser using Tree-sitter for unified CST parsing."""

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        self._available = TREE_SITTER_AVAILABLE and TREE_SITTER_LANGS_AVAILABLE
        if self._available:
            self._init_languages()

    def _init_languages(self):
        """Initialize tree-sitter language objects."""
        for lang_name, lang_obj in _TREE_SITTER_GRAMMARS.items():
            if lang_obj is None:
                continue
            try:
                parser = Parser(lang_obj)
            except Exception:
                continue
            self._languages[lang_name] = lang_obj
            self._parsers[lang_name] = parser

    @property
    def available(self) -> bool:
        return self._available

    @property
    def supported_languages(self) -> List[str]:
        return list(self._parsers.keys())

    def get_language(self, filepath: str) -> Optional[str]:
        """Get the tree-sitter language name for a file extension."""
        ext = os.path.splitext(filepath)[1].lower()
        return EXTENSION_LANGUAGE_MAP.get(ext)

    def can_parse(self, filepath: str) -> bool:
        """Check if we can parse this file."""
        lang = self.get_language(filepath)
        return lang is not None and lang in self._parsers

    def parse_file(self, filepath: str, content: Optional[str] = None) -> ParseResult:
        """Parse a source file and return a ParseResult with CST."""
        lang_name = self.get_language(filepath)
        if not lang_name or lang_name not in self._parsers:
            return ParseResult(
                language=lang_name or 'unknown',
                filepath=filepath,
                errors=[f"No parser available for language: {lang_name}"]
            )

        if content is None:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (OSError, PermissionError) as e:
                return ParseResult(
                    language=lang_name,
                    filepath=filepath,
                    errors=[str(e)]
                )

        if not content:
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                errors=["Empty file"]
            )

        try:
            parser = self._parsers[lang_name]
            tree = parser.parse(content.encode('utf-8'))
            root = self._convert_node(tree.root_node, content)
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                tree=tree,
                root=root,
                success=True
            )
        except Exception as e:
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                errors=[str(e)]
            )

    def parse_source(self, source: str, language: str) -> ParseResult:
        """Parse source code string directly."""
        if language not in self._parsers:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=[f"No parser for: {language}"]
            )

        if not source:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=["Empty source"]
            )

        try:
            parser = self._parsers[language]
            tree = parser.parse(source.encode('utf-8'))
            root = self._convert_node(tree.root_node, source)
            return ParseResult(
                language=language,
                filepath="<string>",
                tree=tree,
                root=root,
                success=True
            )
        except Exception as e:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=[str(e)]
            )

    def _convert_node(self, node, source: str) -> TSNode:
        """Recursively convert a tree-sitter node to our TSNode wrapper."""
        text = ""
        try:
            text = source[node.start_byte:node.end_byte]
        except Exception:
            pass

        ts_node = TSNode(
            type=node.type,
            start_line=node.start_point[0],
            end_line=node.end_point[0],
            start_col=node.start_point[1],
            end_col=node.end_point[1],
            text=text,
        )

        children = []
        for child in node.children:
            child_ts = self._convert_node(child, source)
            child_ts.parent = ts_node
            children.append(child_ts)
        ts_node.children = children

        return ts_node

    def find_nodes_by_type(self, root: TSNode, node_type: str) -> List[TSNode]:
        """Find all nodes of a given type in the CST."""
        results = []
        if root.type == node_type:
            results.append(root)
        for child in root.children:
            results.extend(self.find_nodes_by_type(child, node_type))
        return results

    def find_function_definitions(self, root: TSNode) -> List[TSNode]:
        """Find all function/method definitions."""
        func_types = {
            'function_definition', 'function_declaration',
            'method_definition', 'method_declaration',
            'arrow_function', 'function',
            'constructor_declaration',
            'generator_function_declaration',
            'func_literal',  # Go
            'function_item',  # Rust
            'method_declaration',
        }
        results = []
        for child in root.children:
            if child.type in func_types:
                results.append(child)
            results.extend(self.find_function_definitions(child))
        return results

    def find_class_definitions(self, root: TSNode) -> List[TSNode]:
        """Find all class/type definitions."""
        class_types = {
            'class_definition', 'class_declaration',
            'interface_declaration', 'type_declaration',
            'struct_declaration', 'enum_declaration',
            'trait_declaration', 'impl_item',
        }
        results = []
        for child in root.children:
            if child.type in class_types:
                results.append(child)
            results.extend(self.find_class_definitions(child))
        return results

    def find_string_concatenation(self, root: TSNode) -> List[TSNode]:
        """Find string concatenation nodes (potential injection points)."""
        concat_types = {
            'concatenated_string', 'binary_operator',
            'template_string', 'f_string',
            'interpolated_string',
        }
        results = []
        for child in root.children:
            if child.type in concat_types:
                if any(op in child.text for op in ['+', '%', 'f"', 'f\'']):
                    results.append(child)
            results.extend(self.find_string_concatenation(child))
        return results

    def get_security_analysis(self, root: TSNode) -> Dict:
        """Extract security-relevant information from CST."""
        return {
            'functions': len(self.find_function_definitions(root)),
            'classes': len(self.find_class_definitions(root)),
            'string_concats': len(self.find_string_concatenation(root)),
            'dangerous_calls': self._find_dangerous_calls(root),
        }

    def _find_dangerous_calls(self, root: TSNode) -> List[TSNode]:
        """Find potentially dangerous function calls."""
        dangerous_names = {
            'eval', 'exec', 'system', 'popen', 'subprocess',
            'os.system', 'os.popen', 'shell_exec', 'passthru',
            'Runtime.exec', 'ProcessBuilder', 'child_process',
            'dangerouslySetInnerHTML', 'innerHTML', 'document.write',
            'pickle.load', 'yaml.load', 'marshal.load',
            'deserializ', 'unserialize', 'marshal.loads',
            'format', 'printf', 'sprintf',
        }
        results = []
        for child in root.children:
            if child.type == 'call':
                func_name = child.children[0].text if child.children else ''
                if any(d in func_name for d in dangerous_names):
                    results.append(child)
            results.extend(self._find_dangerous_calls(child))
        return results

    # ── KernelSpy 1.3: context-aware AST scanning ──────────────────────

    def find_security_calls(self, root: TSNode, filepath: str = "") -> List[SecurityCall]:
        """Walk the CST and return only *contextually* dangerous calls.

        Unlike :meth:`_find_dangerous_calls` (a raw name list), every call is
        classified with :func:`classify_call`, so argument vectors, escaped
        output and parameterised queries are not reported.
        """
        ext = _ext_of(filepath)
        results: List[SecurityCall] = []
        stack: List[TSNode] = [root]
        seen = set()
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(node.children)

            if node.type == 'call':
                callee_node = node.children[0] if node.children else None
                callee = callee_node.text if callee_node else ''
                arg_text = ' '.join(c.text for c in node.children[1:])
                verdict = classify_call(callee, arg_text, ext)
                if verdict:
                    sev, cat, reason = verdict
                    results.append(SecurityCall(
                        name=(callee or '').strip()[:80],
                        line=node.start_line + 1,
                        text=node.text[:160],
                        severity=sev,
                        category=cat,
                        reason=reason,
                    ))
            elif 'assignment' in (node.type or '') and _XSS_ASSIGN.search(node.text or ''):
                results.append(SecurityCall(
                    name='innerHTML',
                    line=node.start_line + 1,
                    text=node.text[:160],
                    severity='HIGH',
                    category='XSS',
                    reason='untrusted data written into the DOM',
                ))

        results.sort(key=lambda c: (c.line, c.name))
        return results


# Global singleton
_parser_instance: Optional[TreeSitterParser] = None


def get_parser() -> TreeSitterParser:
    """Get or create the global Tree-sitter parser instance."""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = TreeSitterParser()
    return _parser_instance


def is_tree_sitter_available() -> bool:
    """Check if tree-sitter is available."""
    return TREE_SITTER_AVAILABLE and TREE_SITTER_LANGS_AVAILABLE

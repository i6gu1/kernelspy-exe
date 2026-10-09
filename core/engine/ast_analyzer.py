import ast
import re
from typing import Dict, List, Optional

from ..models import Finding
from .sanitizers import is_sanitizer, kind_for_sink
from .flow_refine import (
    PY_DANGEROUS, fold_python_constants, constfold_finding,
)


# Values that indicate a template/placeholder rather than a real credential.
PLACEHOLDER_VALUES = {
    '', 'changeme', 'change_me', 'changepassword', 'xxx', 'xxxx', 'xxxxx',
    'placeholder', 'example', 'sample', 'dummy', 'test', 'todo', 'fixme',
    'your-password', 'your_password', 'yourpassword', 'your-api-key',
    'your_api_key', 'yourapikey', 'insert-password-here', 'none', 'null',
    'undefined', 'true', 'false', 'password', 'username', 'secret',
    'my-password', 'mypassword', 'not-set', 'notset', 'unset', 'default',
}


def is_placeholder_value(value: str) -> bool:
    """True when a literal looks like a template placeholder, not a secret."""
    v = value.strip().strip('\'"').lower()
    if v in PLACEHOLDER_VALUES:
        return True
    if len(v) < 6:
        return True
    if v.startswith(('$', '%', '<', '{', '[')) or v.endswith(('}', '>', ']')):
        return True          # ${ENV_VAR}, <password>, {secret}, %s
    if set(v) <= set('x*.·_-' ):
        return True          # xxxx, ****
    if '{{' in value or '{%' in value:
        return True          # Jinja2/Django template expressions
    if '%' in v and v.count('%') >= 1 and len(v.replace('%s', '').replace('%d', '')) < 3:
        return True          # printf-style format templates
    return False


CREDENTIAL_NAME_HINTS = {
    'password', 'passwd', 'pwd', 'db_password', 'database_password',
    'admin_password', 'root_password', 'mysql_password', 'postgres_password',
    'secret', 'secret_key', 'client_secret', 'api_secret',
    'api_key', 'apikey', 'app_key',
    'access_token', 'auth_token', 'private_key', 'signing_key',
    'encryption_key', 'master_key', 'smtp_password', 'aws_secret_access_key',
}

WEAK_HASH_FUNCS = {'md5': 'HIGH', 'sha1': 'MEDIUM'}

# Sinks that no escaper can ever make safe - never suppressed by sanitizers.
NEVER_SAFE = (
    'eval', 'exec', '__import__', 'importlib', 'pickle', 'marshal',
    'render_template_string', 'getattr', 'yaml.load',
)


class PythonASTAnalyzer:
    def analyze(self, filepath: str, content: str) -> List[Finding]:
        findings = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            self._check_call(node, filepath, findings)
            self._check_assign(node, filepath, findings)
            self._check_import(node, filepath, findings)

        self._check_constant_folding(tree, content, filepath, findings)

        return findings

    # ───────── CONSTANT FOLDING & PROPAGATION (KernelSpy 1.4.3) ─────────
    _DICT_ROOTS = ('globals', 'locals', 'vars')

    def _check_constant_folding(self, tree, content: str, filepath: str,
                                findings: List[Finding]):
        """Catch ``globals()[name]()`` where ``name`` folds to ``eval``.

        ``part1 = "ev"; part2 = "al"; name = part1 + part2`` is folded first,
        then every ``globals()/locals()/vars()/__builtins__`` lookup and every
        ``getattr(obj, name)`` is resolved through the folded map.
        """
        consts = fold_python_constants(content)
        if not consts:
            consts = {}                       # keep the type narrow
        def_lines: Dict[str, int] = {}
        for i, raw in enumerate(content.split('\n'), 1):
            m = re.match(r'\s*(\w+)\s*=', raw)
            if m and m.group(1) in consts:
                def_lines.setdefault(m.group(1), i)

        seen = set()
        for node in ast.walk(tree):
            # globals()[name] / locals()[name] / __builtins__[name]
            if isinstance(node, ast.Subscript) and self._is_global_dict(node.value):
                key, var, src_line = self._fold_operand(node.slice, consts, def_lines)
                self._emit_fold(filepath, node, key, var, src_line, findings,
                                seen, f"{self._dict_label(node.value)}[{var or '?'}]")
            # globals().get(name) / locals().get(name)
            elif (isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute)
                  and node.func.attr == 'get'
                  and self._is_global_dict(node.func.value)
                  and node.args):
                key, var, src_line = self._fold_operand(node.args[0], consts, def_lines)
                self._emit_fold(filepath, node, key, var, src_line, findings,
                                seen,
                                f"{self._dict_label(node.func.value)}.get({var or '?'})")
            # getattr(obj, name)
            elif (isinstance(node, ast.Call)
                  and self._call_is(node, 'getattr')
                  and len(node.args) >= 2):
                key, var, src_line = self._fold_operand(node.args[1], consts, def_lines)
                self._emit_fold(filepath, node, key, var, src_line, findings,
                                seen, f"getattr(obj, {var or '?'})")

    def _emit_fold(self, filepath, node, key, var, src_line,
                   findings, seen, expr_text: str):
        if key not in PY_DANGEROUS:
            return
        lineno = getattr(node, 'lineno', 0)
        dedup = (lineno, key)
        if dedup in seen:
            return
        seen.add(dedup)
        findings.append(constfold_finding(
            filepath, lineno, expr_text, var or '', key, src_line))

    def _dict_label(self, node) -> str:
        """Readable name of the dict being indexed: ``globals()`` / ``__builtins__``."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return f"{node.func.id}()"
        return '__builtins__'

    def _is_global_dict(self, node) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return node.func.id in self._DICT_ROOTS
        return isinstance(node, ast.Name) and node.id == '__builtins__'

    @staticmethod
    def _call_is(node: ast.Call, name: str) -> bool:
        return isinstance(node.func, ast.Name) and node.func.id == name

    def _fold_operand(self, node, consts: Dict[str, str], def_lines: Dict[str, int]):
        """(folded value, variable name, definition line) for a name/expr."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, node.value, 0
        if isinstance(node, ast.Name):
            return consts.get(node.id), node.id, def_lines.get(node.id, 0)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, lvar, lline = self._fold_operand(node.left, consts, def_lines)
            right, rvar, rline = self._fold_operand(node.right, consts, def_lines)
            if left is not None and right is not None:
                return left + right, f"{lvar} + {rvar}", lline or rline
        return None, None, 0

    def _check_call(self, node: ast.AST, filepath: str, findings: List[Finding]):
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_call_name(node)
        if not func_name:
            return

        lineno = getattr(node, 'lineno', 0)

        if func_name in ('eval', 'exec') and self._has_user_input(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type=f"AST: {func_name}() with user input",
                severity="CRITICAL",
                snippet=func_name + "()",
                description=f"{func_name}() called with untrusted input - code injection.",
                category="INJECTION",
                analyzer="ast",
            ))

        if func_name in ('__import__', 'importlib.import_module') and self._has_user_input(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type=f"AST: Dynamic import with user input",
                severity="CRITICAL",
                snippet=func_name + "()",
                description="Dynamic module import with untrusted input.",
                category="INJECTION",
                analyzer="ast",
            ))

        if func_name == 'pickle.loads' or func_name == 'pickle.load':
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: pickle deserialization",
                severity="CRITICAL",
                snippet="pickle.load()",
                description="Pickle deserialization allows arbitrary code execution.",
                category="DESERIALIZATION",
                analyzer="ast",
            ))

        if func_name == 'yaml.load' and not self._has_safe_loader(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: yaml.load without SafeLoader",
                severity="HIGH",
                snippet="yaml.load()",
                description="yaml.load() without Loader=SafeLoader.",
                category="DESERIALIZATION",
                analyzer="ast",
            ))

        if func_name in ('os.system', 'os.popen'):
            if not self._suppressed(node, 'INJECTION', func_name):
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type=f"AST: {func_name}",
                    severity="HIGH",
                    snippet=f"{func_name}()",
                    description=f"{func_name} allows command injection. Use subprocess.run().",
                    category="INJECTION",
                    analyzer="ast",
                ))

        if func_name.startswith('subprocess.'):
            shape = self._subprocess_shape(node)
            if shape == 'shell_true':
                # shell=True -> untrusted data is interpreted by /bin/sh
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type="AST: subprocess with shell=True",
                    severity="CRITICAL",
                    snippet=self._call_snippet(node),
                    description="subprocess with shell=True allows command injection. "
                                "Pass an argument list with shell=False instead.",
                    category="INJECTION",
                    analyzer="ast",
                ))
            elif shape == 'string_dynamic' and self._has_dynamic_query(node):
                # single unparsed string command built at runtime -> risky
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type="AST: subprocess command built dynamically",
                    severity="HIGH",
                    snippet=self._call_snippet(node),
                    description="subprocess receives a dynamically built command "
                                "string. Use an argument vector (list) with shell=False.",
                    category="INJECTION",
                    analyzer="ast",
                ))
            elif shape == 'no_shell_dynamic':
                # shell=False explicitly set: no shell metacharacter
                # interpretation, only review-level risk.
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type="AST: subprocess argument built dynamically",
                    severity="LOW",
                    snippet=self._call_snippet(node),
                    description="subprocess is called with shell=False (good) but "
                                "the command string is built at runtime. Prefer an "
                                "argument list.",
                    category="INJECTION",
                    analyzer="ast",
                ))
            # shape == 'list' / 'static' -> argument vector, no shell involved:
            # safe by construction, not reported.

        if func_name == 'open' and self._has_user_input(node):
            if not self._suppressed(node, 'TRAVERSAL', func_name):
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type="AST: open() with user input",
                    severity="HIGH",
                    snippet="open(...)",
                    description="File open with untrusted input - path traversal risk.",
                    category="TRAVERSAL",
                    analyzer="ast",
                ))

        if func_name == 'render_template_string':
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: render_template_string",
                severity="CRITICAL",
                snippet="render_template_string()",
                description="Jinja2 SSTI vulnerability.",
                category="INJECTION",
                analyzer="ast",
            ))

        if func_name == 'getattr' and self._has_user_input(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: getattr with user input",
                severity="HIGH",
                snippet="getattr(...)",
                description="Dynamic attribute access with untrusted input.",
                category="INJECTION",
                analyzer="ast",
            ))

        if func_name == 'marshal.loads' or func_name == 'marshal.load':
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: marshal deserialization",
                severity="CRITICAL",
                snippet="marshal.load()",
                description="Marshal deserialization allows arbitrary code execution.",
                category="DESERIALIZATION",
                analyzer="ast",
            ))

        # ── Context-aware: SQL built through string formatting/concatenation ──
        if self._is_sql_sink(func_name) and self._has_dynamic_query(node):
            if not self._suppressed(node, 'INJECTION', func_name):
                findings.append(Finding(
                    file=filepath,
                    line=lineno,
                    type="AST: SQL query via string formatting",
                    severity="CRITICAL",
                    snippet=self._call_snippet(node),
                    description=(
                        f"{func_name}() builds its SQL from string formatting or "
                        "concatenation - SQL injection risk. Use parameterized queries."
                    ),
                    category="INJECTION",
                    analyzer="ast",
                ))

        # ── Context-aware: weak hash functions ──
        base_func = func_name.rsplit('.', 1)[-1]
        if func_name in ('hashlib.md5', 'hashlib.sha1') or (
                func_name.endswith(('.md5', '.sha1')) and '.' in func_name):
            sev = WEAK_HASH_FUNCS['md5'] if 'md5' in func_name else WEAK_HASH_FUNCS['sha1']
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type=f"AST: weak hash ({'MD5' if 'md5' in func_name else 'SHA1'})",
                severity=sev,
                snippet=f"{func_name}()",
                description=f"{func_name}() is cryptographically broken/deprecated. Use SHA-256+.",
                category="CRYPTO",
                analyzer="ast",
            ))
        elif base_func in ('new',) and isinstance(node.args, list) and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                algo = arg0.value.strip().lower().replace('-', '')
                if algo in ('md5', 'sha1'):
                    findings.append(Finding(
                        file=filepath,
                        line=lineno,
                        type=f"AST: weak hash ({algo.upper()})",
                        severity=WEAK_HASH_FUNCS[algo],
                        snippet=f"{func_name}(\"{arg0.value}\")",
                        description=f"{func_name}(\"{algo}\") uses a broken/deprecated digest. Use SHA-256+.",
                        category="CRYPTO",
                        analyzer="ast",
                    ))

        # ── Context-aware: network service bound to all interfaces ──
        if base_func in ('run', 'serve', 'create_server') and self._has_all_interfaces(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: binds 0.0.0.0",
                severity="MEDIUM",
                snippet=self._call_snippet(node),
                description="Service bound to 0.0.0.0 - exposed on all network interfaces.",
                category="NETWORK",
                analyzer="ast",
            ))

    def _check_assign(self, node: ast.AST, filepath: str, findings: List[Finding]):
        if not isinstance(node, ast.Assign):
            return

        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id == 'DEBUG' and isinstance(node.value, ast.Constant):
                    if node.value.value is True:
                        findings.append(Finding(
                            file=filepath,
                            line=getattr(node, 'lineno', 0),
                            type="AST: DEBUG = True",
                            severity="HIGH",
                            snippet="DEBUG = True",
                            description="Django DEBUG mode enabled.",
                            category="CONFIG",
                            analyzer="ast",
                        ))

                # ── Context-aware: hardcoded credential (structurally validated) ──
                if target.id.lower() in CREDENTIAL_NAME_HINTS \
                        and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str):
                    val = node.value.value
                    if not is_placeholder_value(val):
                        findings.append(Finding(
                            file=filepath,
                            line=getattr(node, 'lineno', 0),
                            type=f"AST: hardcoded {target.id}",
                            severity="CRITICAL",
                            snippet=f"{target.id} = \"{'*' * min(len(val), 12)}\"",
                            description=(
                                f"Hardcoded credential '{target.id}' embedded in source "
                                "code. Load it from environment/secret manager instead."
                            ),
                            category="AUTH",
                            analyzer="ast",
                        ))

    def _check_import(self, node: ast.AST, filepath: str, findings: List[Finding]):
        if not isinstance(node, ast.Import):
            return

        for alias in node.names:
            if alias.name == 'pickle':
                pass

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        return None

    def _has_user_input(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._is_untrusted(arg):
                return True
        for kw in node.keywords:
            if self._is_untrusted(kw.value):
                return True
        return False

    def _is_untrusted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            untrusted_names = {
                'request', 'req', 'input', 'args', 'params', 'data',
                'form', 'query', 'json', 'body', 'headers', 'cookies',
                'argv', 'sys', 'environ', 'getenv',
            }
            return node.id in untrusted_names
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                if node.value.id in ('request', 'req', 'input', 'args', 'params', 'data',
                                     'form', 'query', 'json', 'body', 'headers', 'cookies'):
                    return True
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id in ('request', 'req', 'input', 'args', 'params', 'data',
                                     'form', 'query', 'json', 'body', 'headers', 'cookies'):
                    return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_untrusted(node.left) or self._is_untrusted(node.right)
        if isinstance(node, ast.Call):
            return self._has_user_input(node)
        return False

    def _has_safe_loader(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == 'Loader':
                return True
        return False

    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == 'shell':
                if isinstance(kw.value, ast.Constant):
                    return kw.value.value is True
        return False

    # ── Sanitizers / context-aware helpers (KernelSpy 1.3) ────────────

    def _suppressed(self, node: ast.Call, category: str, func_name: str) -> bool:
        """True when every risky argument passes through a trusted helper."""
        if any(n in (func_name or '') for n in NEVER_SAFE):
            return False
        kind = kind_for_sink('.py', func_name or '', category)
        if not kind:
            return False
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if self._call_sanitizes(arg, kind):
                return True
        return False

    def _call_sanitizes(self, node: ast.AST, kind: str) -> bool:
        if isinstance(node, ast.Call):
            name = self._get_call_name(node) or ''
            if is_sanitizer(name, '.py', kind):
                return True
            for sub in ast.iter_child_nodes(node):
                if self._call_sanitizes(sub, kind):
                    return True
        return False

    def _subprocess_shape(self, node: ast.Call) -> str:
        """Classify a subprocess call: shell_true / list / string_dynamic /
        string_static / unknown - drives context-aware severity."""
        for kw in node.keywords:
            if kw.arg == 'shell':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return 'shell_true'
                if self._first_arg_is_dynamic(node) and self._has_dynamic_query(node):
                    return 'no_shell_dynamic'
                return 'list'
        if self._has_shell_true(node):
            return 'shell_true'
        if not node.args:
            return 'unknown'
        first = node.args[0]
        if isinstance(first, (ast.List, ast.Tuple)):
            return 'list'
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return 'string_static'
        if self._is_dynamic_string(first):
            return 'string_dynamic'
        if isinstance(first, (ast.Name, ast.Attribute, ast.Subscript)):
            return 'string_dynamic' if self._has_dynamic_query(node) else 'list'
        return 'unknown'

    @staticmethod
    def _first_arg_is_dynamic(node: ast.Call) -> bool:
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, (ast.List, ast.Tuple)):
            return False
        if isinstance(first, ast.Constant):
            return False
        return True

    # ── Context-aware helpers ─────────────────────────────────────────

    SQL_SINK_SUFFIXES = (
        'execute', 'executemany', 'executescript', 'raw', 'query',
        'execute_query', 'execute_sql',
    )

    def _is_sql_sink(self, func_name: str) -> bool:
        base = func_name.rsplit('.', 1)[-1].lower()
        return base in self.SQL_SINK_SUFFIXES or func_name in (
            'text', 'sqlalchemy.text')

    def _has_dynamic_query(self, node: ast.Call) -> bool:
        """True when any argument builds a string dynamically (f-string,
        concatenation, .format(), % formatting)."""
        args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in args:
            if self._is_dynamic_string(arg):
                return True
        return False

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True                                   # f"...{x}..."
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True                                   # "a" + x / "...%s" % x
        if isinstance(node, ast.Call):
            name = self._get_call_name(node)
            if name and name.rsplit('.', 1)[-1] == 'format':
                return True                               # "...".format(x)
            for sub in ast.iter_child_nodes(node):
                if self._is_dynamic_string(sub):
                    return True
            return False
        for sub in ast.iter_child_nodes(node):
            if self._is_dynamic_string(sub):
                return True
        return False

    def _call_snippet(self, node: ast.Call, limit: int = 120) -> str:
        try:
            return ast.unparse(node)[:limit]
        except Exception:
            return (getattr(node.func, 'id', None)
                    or getattr(node.func, 'attr', None) or 'call()')

    def _has_all_interfaces(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == 'host' and isinstance(kw.value, ast.Constant):
                return kw.value.value in ('0.0.0.0', '::')
        for arg in node.args:
            if isinstance(arg, ast.Constant) and arg.value in ('0.0.0.0', '::'):
                return True
        return False

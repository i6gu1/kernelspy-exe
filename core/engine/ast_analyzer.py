import ast
from typing import List, Optional
from ..models import Finding


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

        return findings

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

        if func_name.startswith('subprocess.') and self._has_shell_true(node):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                type="AST: subprocess with shell=True",
                severity="HIGH",
                snippet="subprocess...(shell=True)",
                description="subprocess with shell=True allows command injection.",
                category="INJECTION",
                analyzer="ast",
            ))

        if func_name == 'open' and self._has_user_input(node):
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

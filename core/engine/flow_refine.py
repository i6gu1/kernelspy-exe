"""Cross-language flow refinements for the taint engine (KernelSpy 1.4.3).

The line-based taint tracker only knows "this name appears on the line".
Three real-world obfuscations need a small memory of the file:

1. Go tainted channels
   ``ch <- tainted`` poisons the channel; ``v := <-ch`` (or ``range ch``)
   inherits the taint, so a sink on the next line is caught.

2. JavaScript object reference maps
   ``const h = { html: (x) => res.send(x) }`` together with
   ``h[key](param)`` and ``key === "html"`` really calls
   ``res.send(param)``.

3. Python constant folding
   ``name = "ev" + "al"`` then ``globals()[name]()`` really calls ``eval``.
   The Python side is AST-based (see ast_analyzer.PythonASTAnalyzer); the
   folding helpers below are shared with the line engine.
"""
import re
from typing import Callable, Dict, List, Optional, Tuple

from ..models import Finding


# ═══════════════════════════════ PYTHON: CONSTANT FOLDING ═══════════════════

# folded name -> short reason.  Anything here reached through a folded
# dynamic dispatch is a real code-execution primitive.
PY_DANGEROUS = {
    'eval': 'evaluates a string as Python code',
    'exec': 'executes a string as Python code',
    'compile': 'compiles a string into code objects',
    '__import__': 'imports a module by name',
    'builtins.eval': 'evaluates a string as Python code',
    'builtins.exec': 'executes a string as Python code',
    'os.system': 'runs a shell command',
    'os.popen': 'runs a shell command',
    'subprocess.call': 'runs an external process',
    'subprocess.run': 'runs an external process',
    'subprocess.Popen': 'runs an external process',
    'subprocess.check_output': 'runs an external process',
    'pickle.loads': 'deserializes untrusted data',
    'marshal.loads': 'deserializes untrusted data',
    'yaml.load': 'deserializes untrusted YAML',
}

PY_SEVERITY = {
    'eval': 'CRITICAL', 'exec': 'CRITICAL', 'compile': 'HIGH',
    '__import__': 'CRITICAL', 'builtins.eval': 'CRITICAL',
    'builtins.exec': 'CRITICAL',
    'os.system': 'CRITICAL', 'os.popen': 'HIGH',
    'subprocess.call': 'HIGH', 'subprocess.run': 'HIGH',
    'subprocess.Popen': 'HIGH', 'subprocess.check_output': 'HIGH',
    'pickle.loads': 'CRITICAL', 'marshal.loads': 'CRITICAL',
    'yaml.load': 'HIGH',
}

_PY_ASSIGN = re.compile(r'^\s*(\w+)\s*=\s*(.+?)\s*(?:#.*)?$')
_PY_WORD = re.compile(r'^[A-Za-z_]\w*$')


def split_plus(expr: str) -> Optional[List[str]]:
    """Split ``"a" + b + 'c'`` on the top-level ``+`` operators.

    Returns None when the expression is not a pure concatenation of string
    literals / known names (quotes are tracked so ``"a+b"`` stays whole).
    """
    parts: List[str] = []
    cur: List[str] = []
    quote = ''
    for ch in expr:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ''
        elif ch in ('"', "'"):
            quote = ch
            cur.append(ch)
        elif ch == '+':
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if quote:
        return None
    parts.append(''.join(cur).strip())
    return parts if len(parts) > 1 else None


def _atom_value(atom: str, consts: Dict[str, str]) -> Optional[str]:
    atom = atom.strip()
    if len(atom) >= 2 and atom[0] in ('"', "'") and atom[-1] == atom[0]:
        inner = atom[1:-1]
        if atom.count(atom[0]) == 2:
            return inner
        return None                      # has escapes / embedded quotes
    if _PY_WORD.match(atom):
        return consts.get(atom)
    return None


def fold_expression(expr: str, consts: Dict[str, str]) -> Optional[str]:
    """Fold a single Python/JS style concatenation expression to a string."""
    expr = expr.strip()
    direct = _atom_value(expr, consts)
    if direct is not None:
        return direct
    parts = split_plus(expr)
    if not parts:
        return None
    out = []
    for part in parts:
        val = _atom_value(part, consts)
        if val is None:
            return None
        out.append(val)
    return ''.join(out)


def fold_python_constants(content: str, max_passes: int = 4) -> Dict[str, str]:
    """Fold ``x = "ev"`` / ``y = x + "al"`` chains into final strings.

    Several passes so longer chains (``a`` -> ``b`` -> ``c``) settle; the
    result maps every variable whose value is statically known.
    """
    consts: Dict[str, str] = {}
    lines = content.split('\n')
    for _ in range(max_passes):
        changed = False
        for raw in lines:
            m = _PY_ASSIGN.match(raw)
            if not m:
                continue
            name, expr = m.group(1), m.group(2).strip()
            if not expr or name in consts and consts[name] == expr:
                continue
            value = fold_expression(expr, consts)
            if value is not None and consts.get(name) != value:
                consts[name] = value
                changed = True
        if not changed:
            break
    return consts


# ═════════════════════════════ JAVASCRIPT: OBJECT REFS ══════════════════════

JS_EXTS = ('.js', '.ts', '.jsx', '.tsx')

_JS_OBJ_START = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{')
_JS_PROP = re.compile(
    r'''(?:"([^"\\]+)"|'([^'\\]+)'|`([^`]+)`|([A-Za-z_$][\w$]*))\s*:\s*''')
_JS_PROP_BOUNDARY = re.compile(
    r'\n\s*(?:"[^"\n]+"|\'[^\'\n]+\'|`[^`\n]+`|[A-Za-z_$][\w$]*)\s*:')

# dangerous callees a handler property may hide
_JS_DANGEROUS = re.compile(
    r'''((?:res|response)\s*\.\s*(?:send|json|render|write|writeHead|end|redirect)
      |document\s*\.\s*(?:write|writeln)
      |[A-Za-z_$][\w$]*\s*\.\s*innerHTML\s*=
      |[A-Za-z_$][\w$]*\s*\.\s*insertAdjacentHTML\s*\(
      |child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync|fork)
      |(?:fs|node:fs)\s*\.\s*(?:writeFile|writeFileSync|readFile|readFileSync|appendFile)
      |(?:db|client|conn|connection|pool|knex)\s*\.\s*(?:query|execute|raw)
      |(?:sql|mysql|postgres|knex)\s*\.\s*query
      |(?:eval|Function)\s*\(
      |require\s*\(
    )''', re.X)

# plain reference form:  send: res.send   (no call parentheses)
_JS_PLAIN_REF = re.compile(
    r'^\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)+)\s*,?\s*$')

_JS_ASSIGN = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*'
    r'''(?:"([^"]*)"|'([^']*)'|`([^`]*)`|([A-Za-z_$][\w$]*))\s*;?\s*$''')
_JS_PLUS_ASSIGN = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?\+.+?)\s*;?\s*$')

# h[key](param)  /  h["html"](param)
JS_DYNAMIC_CALL = re.compile(r'([A-Za-z_$][\w$]*)\[([^\]\n]+)\]\s*\(')


def fold_js_string_constants(content: str, max_passes: int = 3) -> Dict[str, str]:
    """``const key = "html"`` / ``const k = "ht" + "ml"`` -> {'key': 'html'}."""
    consts: Dict[str, str] = {}
    lines = content.split('\n')
    for _ in range(max_passes):
        changed = False
        for raw in lines:
            m = _JS_ASSIGN.search(raw)
            if m:
                name = m.group(1)
                value = next((g for g in m.groups()[1:] if g is not None), None)
                if value is not None and consts.get(name) != value:
                    consts[name] = value
                    changed = True
                    continue
            m = _JS_PLUS_ASSIGN.search(raw)
            if m:
                value = fold_expression(m.group(2), consts)
                if value is not None and consts.get(m.group(1)) != value:
                    consts[m.group(1)] = value
                    changed = True
        if not changed:
            break
    return consts


def _property_value(text: str) -> str:
    """Cut a property body at the next ``key:`` so neighbours do not bleed."""
    m = _JS_PROP_BOUNDARY.search(text)
    return text[:m.start()] if m else text


def _dangerous_callee(value_text: str) -> Optional[str]:
    """Return the normalized dangerous callee inside a property body."""
    body = _property_value(value_text)
    m = _JS_DANGEROUS.search(body)
    if m:
        return re.sub(r'\s+', '', m.group(1)).rstrip('(').rstrip('=')
    m = _JS_PLAIN_REF.match(body.strip().rstrip(',').strip())
    if m:
        ref = re.sub(r'\s+', '', m.group(1))
        if _JS_DANGEROUS.search(ref + '('):
            return ref
    return None


def js_collect_object_handlers(content: str) -> Dict[str, Dict[str, str]]:
    """Build ``{objectName: {propertyKey: dangerousCallee}}`` from literals.

    Only properties whose body hides a dangerous call are kept, so the map
    stays small and every entry is security relevant.
    """
    handlers: Dict[str, Dict[str, str]] = {}
    lines = content.split('\n')
    i = 0
    while i < len(lines):
        m = _JS_OBJ_START.search(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = lines[i].count('{') - lines[i].count('}')
        block = [lines[i][lines[i].index('{'):]]
        j = i + 1
        while j < len(lines) and depth > 0 and (j - i) < 400:
            block.append(lines[j])
            depth += lines[j].count('{') - lines[j].count('}')
            j += 1
        text = '\n'.join(block)
        props: Dict[str, str] = {}
        for pm in _JS_PROP.finditer(text):
            key = next(g for g in pm.groups() if g is not None)
            callee = _dangerous_callee(text[pm.end():pm.end() + 500])
            if callee:
                props[key] = callee
        if props:
            handlers.setdefault(name, {}).update(props)
        i = j if j > i else i + 1
    return handlers


def resolve_js_dynamic_call(
    line: str,
    handlers: Dict[str, Dict[str, str]],
    consts: Dict[str, str],
) -> Optional[Tuple[str, str, str]]:
    """``h[key](x)`` -> (object, key, real callee) when the map knows it."""
    for m in JS_DYNAMIC_CALL.finditer(line):
        obj, key_expr = m.group(1), m.group(2).strip()
        key: Optional[str] = None
        if len(key_expr) >= 2 and key_expr[0] in ('"', "'", '`') \
                and key_expr[-1] == key_expr[0]:
            key = key_expr[1:-1]
        elif _PY_WORD.match(key_expr):
            key = consts.get(key_expr)
        else:
            key = fold_expression(key_expr, consts)
        if key is None:
            continue
        callee = handlers.get(obj, {}).get(key)
        if callee:
            return obj, key, callee
    return None


# ═══════════════════════════════ GO: TAINTED CHANNELS ═══════════════════════

# sends are usually buried in a goroutine:  go func() { ch <- q }()
_GO_SEND = re.compile(r'\b([A-Za-z_]\w*)\s*<-\s*([^;\n}]+)')
_GO_RECV = re.compile(r'\b([A-Za-z_]\w*)\s*:=\s*<-\s*([A-Za-z_]\w*)')
_GO_RECV_EQ = re.compile(r'\b([A-Za-z_]\w*)\s*===\s*<-\s*([A-Za-z_]\w*)')
_GO_RANGE = re.compile(r'for\s+(?:[A-Za-z_]\w*\s*,\s*)?([A-Za-z_]\w*)\s*:?=\s*'
                       r'range\s+([A-Za-z_]\w*)')


def go_channel_update(line: str, line_num: int, sources: Tuple,
                      tainted: Dict[str, int], tainted_channels: Dict[str, int],
                      word_re: Callable[[str], 're.Pattern'],
                      via_channel: Optional[Dict[str, str]] = None) -> None:
    """Propagate taint through Go channel send/receive on a single line.

    ``ch <- expr`` poisons the channel when ``expr`` is untrusted; ``v := <-ch``
    (or ``for v := range ch``) hands the taint to ``v``.  When a
    ``via_channel`` dict is supplied, the receiving var is mapped to the
    channel name so findings can surface the channel flow explicitly.
    """
    m = _GO_SEND.search(line)
    if m:
        ch, rhs = m.group(1), m.group(2)
        # a bare receive (`v := <-ch`) is not a send - the pattern above only
        # fires when the identifier sits directly before the operator
        dirty = any(s in rhs for s in sources)
        if not dirty:
            for name in list(tainted) + list(tainted_channels):
                if word_re(name).search(rhs):
                    dirty = True
                    break
        if dirty and ch not in tainted_channels:
            tainted_channels[ch] = line_num
        return

    m = _GO_RECV.search(line)
    if m:
        var, ch = m.group(1), m.group(2)
        if ch in tainted_channels and var not in tainted:
            tainted[var] = tainted_channels[ch]
            if via_channel is not None:
                via_channel[var] = ch
        return

    m = _GO_RECV_EQ.search(line)
    if m:
        var, ch = m.group(1), m.group(2)
        if ch in tainted_channels and var not in tainted:
            tainted[var] = tainted_channels[ch]
            if via_channel is not None:
                via_channel[var] = ch
        return

    m = _GO_RANGE.search(line)
    if m:
        var, ch = m.group(1), m.group(2)
        if ch in tainted_channels and var not in tainted:
            tainted[var] = tainted_channels[ch]
            if via_channel is not None:
                via_channel[var] = ch


# ═══════════════════════════════════ FINDINGS ═══════════════════════════════

def objref_finding(filepath: str, line_num: int, line: str, obj: str, key: str,
                   callee: str, var: str, source_line: int,
                   severity: str) -> Finding:
    return Finding(
        file=filepath,
        line=line_num,
        type=f"ObjRef: {obj}[{key!r}] -> {callee}",
        severity=severity,
        snippet=line[:120],
        description=(
            f"Dynamic dispatch through an object reference: {obj}[{key!r}] "
            f"resolves to '{callee}'. Untrusted value '{var}' (line "
            f"{source_line}) is passed to it."
        ),
        category="INJECTION",
        analyzer="objref",
    )


def constfold_finding(filepath: str, line_num: int, expr_text: str,
                      var: str, resolved: str, source_line: int = 0) -> Finding:
    reason = PY_DANGEROUS.get(resolved, 'dangerous function')
    where = f" (variable '{var}' defined on line {source_line})" if source_line else ""
    return Finding(
        file=filepath,
        line=line_num,
        type=f"ConstFold: {expr_text} -> {resolved}",
        severity=PY_SEVERITY.get(resolved, 'CRITICAL'),
        snippet=expr_text[:120],
        description=(
            f"Constant folding resolves this dynamic call to '{resolved}' - "
            f"{reason}. The name is built at runtime, which usually hides the "
            f"call from simple grep-style checks{where}."
        ),
        category="INJECTION",
        analyzer="constfold",
    )

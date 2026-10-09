"""Sanitizers & Filters registry (KernelSpy 1.3).

A trusted list of escaping / validation / encoding helpers per language and
per sink kind.  During taint analysis a variable that flows through one of
these helpers changes state from "Tainted" to "Clean", which removes the
biggest source of false positives (e.g. ``he.encode(userInput)`` was still
reported as an XSS source in 1.2).

Kinds
-----
html   : markup/XSS escaping
sql    : database parameterisation helpers
shell  : shell argument quoting
path   : path traversal guards
js     : JavaScript string escaping
"""

from typing import Dict, Iterable, List, Optional

# ext -> kind -> helper names
SANITIZERS: Dict[str, Dict[str, List[str]]] = {
    '.py': {
        'html': ['html.escape', 'cgi.escape', 'markupsafe.escape', 'Markup.escape',
                 'bleach.clean', 'bleach.escape', 'django.utils.html.escape',
                 'flask.escape', 'escape'],
        'sql': ['cursor.mogrify', 'psycopg2.extensions.adapt',
                'sqlite3.register_adapter', 'escape_string'],
        'shell': ['shlex.quote', 'shlex.split'],
        'path': ['os.path.abspath', 'os.path.realpath', 'os.path.normpath',
                 'secure_filename', 'werkzeug.utils.secure_filename',
                 'pathlib.Path.resolve'],
        'js': ['json.dumps'],
    },
    '.js': {
        'html': ['he.encode', 'htmlspecialchars', 'encodeURIComponent', 'encodeURI',
                 'escapeHtml', 'escapeHTML', 'DOMPurify.sanitize',
                 'sanitizeHtml', 'xss', 'validator.escape',
                 'lodash.escape', '_.escape'],
        'sql': ['mysql.escape', 'sequelize.escape', 'sqlstring.escape',
                'pool.escape', 'connection.escape'],
        'shell': ['shell-quote.quote', 'execFile'],
        'path': ['path.normalize', 'path.resolve', 'safe-join', 'path.join'],
        'js': ['JSON.stringify'],
    },
    '.ts': {
        'html': ['he.encode', 'encodeURIComponent', 'escapeHtml', 'DOMPurify.sanitize',
                 'sanitizeHtml', 'validator.escape'],
        'sql': ['sequelize.escape', 'sqlstring.escape', 'mysql.escape'],
        'shell': ['shell-quote.quote', 'execFile'],
        'path': ['path.normalize', 'path.resolve', 'safe-join'],
        'js': ['JSON.stringify'],
    },
    '.php': {
        'html': ['htmlspecialchars', 'htmlentities', 'strip_tags', 'filter_var',
                 'FILTER_SANITIZE_STRING', 'esc_html', 'html_escape'],
        'sql': ['mysqli_real_escape_string', 'mysql_real_escape_string',
                'pg_escape_string', 'PDO::quote', 'quote', 'addslashes',
                'intval', 'intval(', '(int)'],
        'shell': ['escapeshellarg', 'escapeshellcmd'],
        'path': ['basename', 'realpath', 'dirname'],
        'js': ['json_encode'],
    },
    '.java': {
        'html': ['StringEscapeUtils.escapeHtml4', 'escapeHtml', 'escapeXml',
                 'HtmlUtils.htmlEscape', 'Encode.forHtml'],
        'sql': ['setString', 'setInt', 'setLong', 'setDouble', 'setParameter',
                'addWithValue', 'bindValue'],
        'path': ['Paths.get', 'getCanonicalPath'],
        'js': ['StringEscapeUtils.escapeJavaScript'],
    },
    '.go': {
        'html': ['template.HTMLEscapeString', 'html.EscapeString',
                 'template.HTMLEscape', 'bluemonday.UGCPolicy'],
        'shell': [],
        'path': ['filepath.Clean', 'filepath.Abs', 'path.Clean'],
        'js': ['template.JSEscapeString'],
    },
    '.rb': {
        'html': ['ERB::Util.html_escape', 'escape_once', 'CGI.escapeHTML'],
        'sql': ['sanitize_sql_array', 'sanitize_sql_like', 'connection.quote'],
        'shell': ['Shellwords.escape', 'Shellwords.split'],
        'path': ['File.expand_path'],
        'js': ['ERB::Util.json_escape'],
    },
    '.cs': {
        'html': ['HttpUtility.HtmlEncode', 'WebUtility.HtmlEncode', 'HtmlEncoder.Default',
                 'Encode.HtmlEncode', 'AntiXss'],
        'sql': ['SqlParameter', 'AddWithValue', 'Parameters.Add', 'DbParameter'],
        'shell': ['ProcessStartInfo.ArgumentList'],
        'path': ['Path.GetFullPath', 'Path.GetTempFileName'],
        'js': ['HttpUtility.JavaScriptStringEncode'],
    },
    '.c': {
        'path': ['realpath', 'basename'],
        'shell': [''],
        'html': [''],
    },
    '.cpp': {
        'path': ['std::filesystem::weakly_canonical', 'realpath'],
        'html': [''],
    },
    '.kt': {
        'html': ['Html.escapeHtml', 'TextUtils.htmlEncode'],
        'sql': ['selectionArgs', 'bindArgs'],
        'path': ['File.canonicalPath'],
    },
    '.swift': {
        'html': ['addingPercentEncoding', 'escape'],
        'sql': ['parameterized', 'bindValue'],
        'path': ['standardizedPath', 'resolvingSymlinksInPath'],
    },
    '.dart': {
        'html': ['HtmlEscape', 'escapeHtml'],
        'sql': ['rawQuery', 'rawInsert-args'],
        'path': ['p.normalize', 'canonicalize'],
    },
    '.rs': {
        'html': ['htmlescape::escape', 'markup5ever::escape'],
        'sql': ['bind', 'query_builder'],
        'path': ['canonicalize', 'normalize_path'],
    },
    '.lua': {
        'html': [''],
        'path': [''],
    },
    '.pl': {
        'html': ['HTML::Entities::encode_entities'],
        'shell': ['String::ShellQuote::shell_quote'],
        'path': ['File::Spec->canonpath'],
    },
}

# Which sanitizer kind protects which vulnerability category.
CATEGORY_KIND: Dict[str, str] = {
    'XSS': 'html',
    'TRAVERSAL': 'path',
    'REDIRECT': 'path',
    'UPLOAD': 'path',
}

# Category -> kinds that can never be neutralised by an escaper (an escaper
# never makes eval()/unserialize()/pickle.load() safe).
UNSANITIZABLE = {'DESERIALIZATION', 'AUTH', 'CRYPTO', 'SECRET', 'CONFIG',
                 'DEPENDENCY', 'BANDIT', 'INFO'}

_FLAT: Dict[str, set] = {}
_LOWER: Dict[str, set] = {}


def _flatten(ext: str) -> set:
    if ext not in _FLAT:
        names: set = set()
        for kind_names in SANITIZERS.get(ext, {}).values():
            for n in kind_names:
                if n and n not in ('(', ):
                    names.add(n.strip())
        _FLAT[ext] = names
    return _FLAT[ext]


def sanitizer_names(ext: str, kind: Optional[str] = None) -> List[str]:
    """Sanitizer helper names for an extension (optionally for one kind)."""
    table = SANITIZERS.get(ext, {})
    if kind is None:
        return sorted(_flatten(ext))
    return list(table.get(kind, []))


def is_sanitizer(name: str, ext: str, kind: Optional[str] = None) -> bool:
    """True when ``name`` (e.g. ``he.encode``) is a trusted helper."""
    if not name:
        return False
    table = SANITIZERS.get(ext, {})
    names: Iterable[str]
    if kind is None:
        names = _flatten(ext)
    else:
        names = table.get(kind, [])
    for cand in names:
        if not cand:
            continue
        if name == cand or name.endswith('.' + cand) or name.endswith(cand):
            return True
    return False


def kind_for_sink(ext: str, sink_name: str, category: str = '') -> Optional[str]:
    """Resolve the sanitizer kind that would make ``sink_name`` safe."""
    if category in UNSANITIZABLE:
        return None
    if category in CATEGORY_KIND:
        return CATEGORY_KIND[category]

    low = (sink_name or '').lower()
    if any(k in low for k in ('sql', 'query', 'execute', 'cursor', 'statement',
                              'prepared', 'mogrify')):
        return 'sql'
    if any(k in low for k in ('shell', 'system', 'popen', 'exec', 'command',
                              'spawn', 'cmd')):
        return 'shell'
    if any(k in low for k in ('open', 'file', 'path', 'include', 'require',
                              'readfile', 'send_file', 'traversal')):
        return 'path'
    if any(k in low for k in ('html', 'innerhtml', 'xss', 'render', 'echo',
                              'document.write', 'dangerouslysetinnerhtml')):
        return 'html'
    return None


def line_sanitizes(line: str, ext: str, kind: Optional[str] = None) -> bool:
    """True when ``line`` calls a trusted sanitizer for ``kind``."""
    if not line:
        return False
    for name in sanitizer_names(ext, kind):
        if not name:
            continue
        # cheap literal search before any regex work
        token = name.split('(')[0].strip()
        if not token or token not in line:
            continue
        if token.endswith('('):
            if token in line:
                return True
            continue
        if _call_re(token).search(line):
            return True
    return False


_CALL_CACHE: Dict[str, object] = {}


def _call_re(token: str):
    import re
    cached = _CALL_CACHE.get(token)
    if cached is None:
        cached = re.compile(r'(?<![\w.$])' + re.escape(token) + r'\s*[\(\[]')
        _CALL_CACHE[token] = cached
    return cached


def suppresses(ext: str, category: str, sink_name: str, calls: Iterable[str]) -> bool:
    """True when one of ``calls`` neutralises the finding."""
    kind = kind_for_sink(ext, sink_name, category)
    if not kind:
        return False
    for call in calls:
        if is_sanitizer(call, ext, kind):
            return True
    return False

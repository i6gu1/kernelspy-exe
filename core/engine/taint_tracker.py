import re
from typing import Dict, List, Tuple

from ..models import Finding


def _sink(label: str, pattern: str, severity: str) -> Tuple:
    return (label, re.compile(pattern), severity)


SOURCES = {
    '.py': ('request', 'req', 'input', 'args', 'params', 'data', 'form',
            'query', 'json', 'body', 'headers', 'cookies',
            'sys.argv', 'os.environ', 'os.getenv', 'getenv'),
    '.php': ('$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', 'php://input'),
    '.js': ('req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies',
            'request.query', 'request.body', 'request.params',
            'process.argv', 'process.env'),
    '.ts': ('req.query', 'req.body', 'req.params', 'req.headers',
            'process.argv', 'process.env'),
    '.java': ('request.getParameter', 'request.getQueryString',
              'request.getHeader', 'request.getCookies', 'params.get'),
    '.rb': ('params', 'request.params', 'request.query_string'),
    '.go': ('r.URL.Query', 'r.FormValue', 'r.Form', 'c.Query'),
    '.cs': ('Request.QueryString', 'Request.Form', 'Request.Params', 'Request.Headers'),
    '.kt': ('readLine', 'request.getParameter', 'request.getHeader',
            'call.getString', 'params["', "params['", 'System.getenv'),
    '.lua': ('io.read', 'os.getenv', 'arg[', 'ngx.req'),
    '.pl': ('<STDIN>', '$ARGV', 'param(', 'CGI::param', '%ENV'),
    '.c': ('argv', 'fgets', 'gets', 'scanf', 'getenv', 'read('),
    '.cpp': ('std::cin', 'argv', 'getline', 'getenv', 'std::ifstream'),
}

SINKS = {
    '.py': [
        _sink('eval', r'\beval\s*\(', 'CRITICAL'),
        _sink('exec', r'\bexec\s*\(', 'CRITICAL'),
        _sink('__import__', r'\b__import__\s*\(', 'CRITICAL'),
        _sink('os.system', r'\bos\.system\s*\(', 'HIGH'),
        _sink('os.popen', r'\bos\.popen\s*\(', 'HIGH'),
        _sink('subprocess', r'subprocess\.\w+\s*\(', 'HIGH'),
        _sink('pickle.load', r'pickle\.loads?\s*\(', 'CRITICAL'),
        _sink('yaml.load', r'yaml\.load\s*\(', 'HIGH'),
        _sink('marshal.load', r'marshal\.loads?\s*\(', 'CRITICAL'),
        _sink('render_template_string', r'render_template_string\s*\(', 'CRITICAL'),
        _sink('send_file', r'send_file\s*\(', 'HIGH'),
        _sink('open', r'\bopen\s*\(', 'HIGH'),
        _sink('execute', r'(?:cursor\.execute|\.execute|executemany)\s*\(', 'CRITICAL'),
        _sink('text', r'\btext\s*\(', 'HIGH'),
        _sink('raw', r'\.raw\s*\(', 'CRITICAL'),
        _sink('query', r'\bquery\s*\(', 'CRITICAL'),
    ],
    '.php': [
        _sink('eval', r'\beval\s*\(', 'CRITICAL'),
        _sink('exec', r'\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(', 'CRITICAL'),
        _sink('unserialize', r'\bunserialize\s*\(', 'CRITICAL'),
        _sink('include', r'\b(?:include|require)(?:_once)?\s*\(', 'CRITICAL'),
        _sink('echo', r'\b(?:echo|print)\b', 'HIGH'),
        _sink('header', r'\bheader\s*\(', 'HIGH'),
        _sink('file_get_contents', r'\bfile_get_contents\s*\(', 'HIGH'),
        _sink('file_put_contents', r'\bfile_put_contents\s*\(', 'HIGH'),
        _sink('extract', r'\bextract\s*\(', 'HIGH'),
        _sink('preg_replace', r'\bpreg_replace\s*\(', 'CRITICAL'),
        _sink('query', r'->\s*query\s*\(|(?:mysqli_query|mysql_query|pg_query|sqlsrv_query)\s*\(', 'CRITICAL'),
    ],
    '.js': [
        _sink('eval', r'\beval\s*\(', 'HIGH'),
        _sink('Function', r'new\s+Function\s*\(', 'HIGH'),
        _sink('child_process', r'child_process\.\w+\s*\(', 'HIGH'),
        _sink('innerHTML', r'\.innerHTML\s*=', 'HIGH'),
        _sink('document.write', r'document\.write\s*\(', 'HIGH'),
        _sink('insertAdjacentHTML', r'\.insertAdjacentHTML\s*\(', 'HIGH'),
        _sink('require', r'\brequire\s*\(', 'HIGH'),
        _sink('query', r'\.query\s*\(', 'CRITICAL'),
        _sink('execute', r'\.execute\s*\(', 'CRITICAL'),
    ],
    '.ts': [
        _sink('eval', r'\beval\s*\(', 'HIGH'),
        _sink('innerHTML', r'\.innerHTML\s*=', 'HIGH'),
        _sink('query', r'\.query\s*\(', 'CRITICAL'),
        _sink('execute', r'\.execute\s*\(', 'CRITICAL'),
    ],
    '.java': [
        _sink('Runtime.exec', r'Runtime\.getRuntime\(\)\.exec\s*\(', 'CRITICAL'),
        _sink('ProcessBuilder', r'new\s+ProcessBuilder\s*\(', 'HIGH'),
        _sink('readObject', r'ObjectInputStream.*readObject', 'CRITICAL'),
        _sink('Statement.execute', r'(?:Statement|PreparedStatement).*execute', 'CRITICAL'),
        _sink('createStatement', r'\.createStatement\s*\(', 'CRITICAL'),
        _sink('lookup', r'(?:InitialContext|lookup)\s*\(', 'CRITICAL'),
        _sink('LDAP.search', r'(?:DirContext|LdapContext)\.search\s*\(', 'HIGH'),
    ],
    '.rb': [
        _sink('system', r'\bsystem\s*\(', 'HIGH'),
        _sink('exec', r'\bexec\s*\(', 'HIGH'),
        _sink('eval', r'\beval\s*\(', 'HIGH'),
        _sink('Marshal.load', r'Marshal\.load\s*\(', 'CRITICAL'),
        _sink('send', r'\.send\s*\(', 'HIGH'),
        _sink('render', r'render\s+inline:', 'CRITICAL'),
    ],
    '.go': [
        _sink('exec.Command', r'exec\.Command\s*\(', 'HIGH'),
        _sink('sql.Query', r'(?:sql\.Query|db\.Query)\s*\(', 'CRITICAL'),
        _sink('template.HTML', r'template\.HTML\s*\(', 'HIGH'),
        _sink('http.Get', r'http\.(?:Get|Post|Do)\s*\(', 'MEDIUM'),
        _sink('os.Open', r'os\.Open\s*\(', 'MEDIUM'),
    ],
    '.cs': [
        _sink('Process.Start', r'Process\.Start\s*\(', 'MEDIUM'),
        _sink('SqlCommand', r'SqlCommand\s*\(', 'CRITICAL'),
        _sink('BinaryFormatter', r'BinaryFormatter.*Deserialize', 'CRITICAL'),
        _sink('Response.Write', r'Response\.Write\s*\(', 'HIGH'),
    ],
    '.kt': [
        _sink('Runtime.exec', r'Runtime\.getRuntime\(\)\.exec\s*\(', 'CRITICAL'),
        _sink('ProcessBuilder', r'ProcessBuilder\s*\(', 'HIGH'),
        _sink('execute', r'\.execute\s*\(|\.rawQuery\s*\(', 'CRITICAL'),
        _sink('eval', r'eval\s*\(', 'HIGH'),
        _sink('loadUrl', r'\.loadUrl\s*\(', 'MEDIUM'),
    ],
    '.lua': [
        _sink('loadstring', r'(?:loadstring|load)\s*\(', 'CRITICAL'),
        _sink('os.execute', r'os\.execute\s*\(', 'CRITICAL'),
        _sink('io.popen', r'io\.popen\s*\(', 'CRITICAL'),
        _sink('dofile', r'(?:dofile|require)\s*\(?\s*[\'"]?\w', 'HIGH'),
    ],
    '.pl': [
        _sink('system', r'\bsystem\s*\(', 'HIGH'),
        _sink('exec', r'\bexec\s*\(', 'HIGH'),
        _sink('eval', r'\beval\s*\(', 'HIGH'),
        _sink('open', r'\bopen\s*\(', 'HIGH'),
        _sink('backtick', r'`[^`]*\$', 'HIGH'),
    ],
    '.c': [
        _sink('system', r'\bsystem\s*\(', 'CRITICAL'),
        _sink('popen', r'\bpopen\s*\(', 'CRITICAL'),
        _sink('execl', r'\bexec[lv][pe]?\s*\(', 'CRITICAL'),
        _sink('strcpy', r'\bstrcpy\s*\(', 'HIGH'),
        _sink('sprintf', r'\bsprintf\s*\(', 'HIGH'),
    ],
    '.cpp': [
        _sink('system', r'\bsystem\s*\(', 'CRITICAL'),
        _sink('popen', r'\b_popen\s*\(', 'CRITICAL'),
        _sink('strcpy', r'\bstrcpy\s*\(', 'HIGH'),
        _sink('exec-family', r'\bexec[lv][pe]?\s*\(', 'CRITICAL'),
    ],
}

ASSIGN_RE = {
    '.py': re.compile(r'(\w+)\s*=\s*'),
    '.php': re.compile(r'\$(\w+)\s*=\s*'),
    '.js': re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*'),
    '.ts': re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*'),
    '.java': re.compile(r'(?:String|Object|Integer|Long|var)\s+(\w+)\s*=\s*'),
    '.rb': re.compile(r'(\w+)\s*=\s*'),
    '.go': re.compile(r'(\w+)\s*:?=\s*'),
    '.cs': re.compile(r'(?:string|var)\s+(\w+)\s*=\s*'),
    '.kt': re.compile(r'(?:val|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*'),
    '.lua': re.compile(r'(?:local\s+)?(\w+)\s*=\s*'),
    '.pl': re.compile(r'my\s+\$?(\w+)\s*=\s*'),
    '.c': re.compile(r'(?:char|int|char\s*\*)\s*\*?\s*(\w+)\s*=\s*'),
    '.cpp': re.compile(r'(?:std::string|int|auto)\s+\*?\s*(\w+)\s*=\s*'),
}


class TaintTracker:
    def __init__(self):
        self._sources: Dict[str, Tuple] = {}
        self._sinks: Dict[str, List[Tuple]] = {}

    def _get_sources(self, ext: str) -> Tuple:
        if ext not in self._sources:
            self._sources[ext] = SOURCES.get(ext, ())
        return self._sources[ext]

    def _get_sinks(self, ext: str) -> List[Tuple]:
        if ext not in self._sinks:
            self._sinks[ext] = SINKS.get(ext, [])
        return self._sinks[ext]

    def analyze(self, filepath: str, content: str, ext: str) -> List[Finding]:
        if ext not in SOURCES or ext not in SINKS:
            return []

        sources = self._get_sources(ext)
        sinks = self._get_sinks(ext)
        assign_re = ASSIGN_RE.get(ext)
        tainted: Dict[str, int] = {}
        findings: List[Finding] = []
        used_keys = set()

        def emit(line_num: int, var: str, sink_label: str, severity: str, snippet: str):
            key = (line_num, var, sink_label)
            if key in used_keys:
                return
            used_keys.add(key)
            source_line = tainted.get(var, line_num)
            findings.append(Finding(
                file=filepath,
                line=line_num,
                type=f"Taint: {var} -> {sink_label}",
                severity=severity,
                snippet=snippet,
                description=(
                    f"Taint flow: untrusted value '{var}' (line {source_line}) "
                    f"reaches dangerous sink '{sink_label}' (line {line_num})."
                ),
                category="INJECTION",
                analyzer="taint",
            ))

        for idx, raw in enumerate(content.split('\n')):
            line = raw.strip()
            if not line:
                continue
            line_num = idx + 1

            for sink_label, sink_re, severity in sinks:
                if not sink_re.search(line):
                    continue
                present_vars = [
                    v for v in tainted
                    if re.search(r'\b' + re.escape(v) + r'\b', line)
                ]
                if present_vars:
                    emit(line_num, present_vars[0], sink_label, severity, line[:120])
                else:
                    direct = [s for s in sources if s in line]
                    if direct:
                        emit(line_num, direct[0], sink_label, severity, line[:120])

            if assign_re:
                for src in sources:
                    if src not in line:
                        continue
                    m = assign_re.search(line)
                    if m and m.group(1):
                        tainted[m.group(1)] = line_num

                for v, sl in list(tainted.items()):
                    if re.search(r'\b' + re.escape(v) + r'\b', line):
                        m = assign_re.search(line)
                        if m and m.group(1) and m.group(1) != v:
                            tainted[m.group(1)] = sl

        return findings
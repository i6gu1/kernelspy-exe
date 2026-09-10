"""
Code Property Graph (CPG) builder for KernelSpy Scanner.
Combines AST + CFG + DDG for comprehensive code analysis.

CPG enables:
- Elimination of false positives by understanding execution flow
- Precise taint tracking from Sources to Sinks
- Context-aware analysis (comments, unreachable code detection)
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple
from enum import Enum
import re


class NodeType(Enum):
    """Types of CPG nodes."""
    FUNCTION = "function"
    CLASS = "class"
    ASSIGNMENT = "assignment"
    CALL = "call"
    RETURN = "return"
    IF = "if"
    WHILE = "while"
    FOR = "for"
    VARIABLE = "variable"
    LITERAL = "literal"
    PARAMETER = "parameter"
    COMMENT = "comment"
    STRING_CONCAT = "string_concat"
    SOURCE = "source"
    SINK = "sink"


class EdgeType(Enum):
    """Types of CPG edges."""
    FLOWS_TO = "flows_to"           # CFG edge
    DATA_FLOW = "data_flow"         # DDG edge
    CONTAINS = "contains"           # AST containment
    CALLS = "calls"                 # Call graph
    DEFINES = "defines"             # Definition
    USES = "uses"                   # Usage
    GUARDS = "guards"              # Control dependency
    DOMINATES = "dominates"        # Dominator relationship


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: str
    node_type: NodeType
    label: str
    line: int
    col: int = 0
    end_line: int = 0
    end_col: int = 0
    language: str = ""
    metadata: Dict = field(default_factory=dict)
    is_source: bool = False
    is_sink: bool = False
    is_comment: bool = False
    is_string_literal: bool = False


@dataclass
class CPGEdge:
    """An edge in the Code Property Graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    metadata: Dict = field(default_factory=list)


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    source: CPGNode
    sink: CPGNode
    path: List[CPGNode]
    path_vars: List[str]
    severity: str = "CRITICAL"


# Known source points (user input entry points)
SOURCES = {
    'python': {
        'request.args', 'request.form', 'request.values', 'request.json',
        'request.data', 'request.files', 'request.cookies',
        'input(', 'sys.stdin', 'os.environ',
        'request.GET', 'request.POST',
    },
    'javascript': {
        'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
        'document.URL', 'document.documentURI', 'document.referrer',
        'window.location', 'location.search', 'location.hash',
        'process.argv', 'prompt(',
    },
    'java': {
        'request.getParameter', 'request.getQueryString',
        'request.getHeader', 'request.getCookies',
        'System.in', 'Scanner.nextLine',
    },
    'php': {
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER',
        'php://input', 'file_get_contents', 'fopen',
    },
    'go': {
        'r.FormValue', 'r.URL.Query', 'r.Header.Get',
        'r.Body', 'bufio.Scanner',
    },
    'ruby': {
        'params[', 'request.params', 'request.headers',
        'gets', 'STDIN.gets',
    },
    'generic': {
        'argv', 'stdin', 'env',
    },
}

# Known sink points (dangerous functions)
SINKS = {
    'python': {
        'eval(', 'exec(', 'os.system(', 'os.popen(',
        'subprocess.call(', 'subprocess.Popen(', 'subprocess.run(',
        'pickle.load(', 'pickle.loads(',
        'yaml.load(',
        'marshal.load(', 'marshal.loads(',
        'open(',
        'render_template_string(',
        'execute(', 'raw(',
    },
    'javascript': {
        'eval(', 'Function(', 'setTimeout(', 'setInterval(',
        'innerHTML', 'document.write(', 'document.writeln(',
        'dangerouslySetInnerHTML',
        'child_process.exec(', 'child_process.spawn(',
        'execSync(', 'spawnSync(',
        'require(', 'import(',
    },
    'java': {
        'Runtime.exec(', 'ProcessBuilder(',
        'ObjectInputStream.readObject(',
        'Statement.execute(', 'Statement.executeQuery(',
        'PreparedStatement.execute(',
        'XPath.evaluate(',
        'DocumentBuilder.parse(',
    },
    'php': {
        'eval(', 'assert(', 'system(', 'exec(', 'passthru(',
        'shell_exec(', 'popen(', 'proc_open(',
        'unserialize(', 'include(', 'require(',
        'include_once(', 'require_once(',
        'file_get_contents(', 'file_put_contents(',
        'mysqli_query(', 'mysql_query(',
        'pg_query(', 'sqlite_query(',
    },
    'go': {
        'exec.Command(', 'os/exec.',
        'sql.Query(', 'sql.Exec(',
        'template.HTML(', 'template.JS(',
        'http.Get(', 'http.Post(',
    },
    'ruby': {
        'eval(', 'system(', 'exec(', 'send(',
        'render(', 'render inline:',
        'send_file(', 'send_data(',
        'open(', 'IO.read(',
    },
    'generic': {
        'eval(', 'exec(', 'system(', 'popen(',
        'execute(', 'query(',
    },
}


class CPGBuilder:
    """Builds a Code Property Graph from source code."""

    def __init__(self):
        self._node_counter = 0
        self._nodes: Dict[str, CPGNode] = {}
        self._edges: List[CPGEdge] = []
        self._cfg_edges: List[CPGEdge] = []
        self._ddg_edges: List[CPGEdge] = []
        self._variable_defs: Dict[str, List[CPGNode]] = {}
        self._variable_uses: Dict[str, List[CPGNode]] = {}

    def reset(self):
        """Reset the builder for a new file."""
        self._node_counter = 0
        self._nodes.clear()
        self._edges.clear()
        self._cfg_edges.clear()
        self._ddg_edges.clear()
        self._variable_defs.clear()
        self._variable_uses.clear()

    def _new_id(self) -> str:
        self._node_counter += 1
        return f"n{self._node_counter}"

    def build_from_source(self, source: str, language: str, filepath: str = "") -> 'CPG':
        """Build a CPG from source code."""
        self.reset()

        lines = source.split('\n')
        prev_node_id = None

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                continue

            # Detect comments
            if self._is_comment(stripped, language):
                node_id = self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.COMMENT,
                    label=stripped,
                    line=i,
                    language=language,
                    is_comment=True,
                )
                continue

            # Build CFG edges (sequential flow)
            node_id = self._analyze_line(stripped, i, language, filepath)

            if node_id and prev_node_id:
                self._cfg_edges.append(CPGEdge(
                    source_id=prev_node_id,
                    target_id=node_id,
                    edge_type=EdgeType.FLOWS_TO,
                ))

            if node_id:
                prev_node_id = node_id

        # Build DDG from variable definitions and uses
        self._build_ddg()

        return CPG(
            nodes=dict(self._nodes),
            edges=self._edges + self._cfg_edges + self._ddg_edges,
            filepath=filepath,
            language=language,
        )

    def _is_comment(self, line: str, language: str) -> bool:
        """Check if a line is a comment."""
        if language in ('python', 'ruby', 'perl', 'lua', 'bash'):
            return line.startswith('#')
        elif language in ('javascript', 'typescript', 'java', 'c', 'cpp',
                         'c_sharp', 'go', 'rust', 'kotlin', 'swift', 'scala',
                         'dart', 'solidity'):
            return line.startswith('//') or line.startswith('/*') or line.startswith('*')
        elif language == 'php':
            return line.startswith('//') or line.startswith('#') or line.startswith('/*')
        elif language == 'html':
            return line.startswith('<!--')
        return False

    def _analyze_line(self, line: str, lineno: int, language: str, filepath: str) -> Optional[str]:
        """Analyze a single line and create appropriate CPG nodes."""
        node_id = None

        # Detect function definitions
        func_patterns = {
            'python': r'^\s*def\s+(\w+)\s*\(',
            'javascript': r'^\s*(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:function|\()|(?:async\s+)?function\s+(\w+))',
            'typescript': r'^\s*(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:function|\()|(?:async\s+)?function\s+(\w+))',
            'java': r'^\s*(?:public|private|protected|static|\s)*\s+\w+\s+(\w+)\s*\(',
            'go': r'^\s*func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(',
            'rust': r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
            'php': r'^\s*(?:public|private|protected|\s)*\s*function\s+(\w+)',
            'ruby': r'^\s*(?:def)\s+(\w+)',
            'c_sharp': r'^\s*(?:public|private|protected|internal|\s)*\s+(?:static\s+)?(?:async\s+)?\w+\s+(\w+)\s*\(',
            'kotlin': r'^\s*(?:fun)\s+(\w+)',
            'swift': r'^\s*func\s+(\w+)',
            'lua': r'^\s*function\s+(\w+)',
            'perl': r'^\s*sub\s+(\w+)',
            'dart': r'^\s*(?:void|int|String|bool|Future|List|Map|\w+)\s+(\w+)\s*\(',
            'scala': r'^\s*(?:def)\s+(\w+)',
        }

        pattern = func_patterns.get(language)
        if pattern:
            m = re.match(pattern, line)
            if m:
                func_name = next(g for g in m.groups() if g)
                node_id = self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.FUNCTION,
                    label=func_name,
                    line=lineno,
                    language=language,
                    metadata={'name': func_name},
                )

        # Detect variable assignments
        assign_patterns = {
            'python': r'^\s*(\w+)\s*=\s*(.+)',
            'javascript': r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(.+)',
            'typescript': r'^\s*(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(.+)',
            'java': r'^\s*(?:\w+\s+)+(\w+)\s*=\s*(.+)',
            'go': r'^\s*(?::=)\s*(\w+)\s*=\s*(.+)',
            'php': r'^\s*\$\w+\s*=\s*(.+)',
            'ruby': r'^\s*(\w+)\s*=\s*(.+)',
            'c_sharp': r'^\s*(?:var|int|string|bool|\w+)\s+(\w+)\s*=\s*(.+)',
            'kotlin': r'^\s*(?:val|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(.+)',
            'swift': r'^\s*(?:let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(.+)',
            'lua': r'^\s*(\w+)\s*=\s*(.+)',
            'perl': r'^\s*my\s+\$(\w+)\s*=\s*(.+)',
            'dart': r'^\s*(?:var|final|int|String|bool|\w+)\s+(\w+)\s*=\s*(.+)',
            'scala': r'^\s*(?:val|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(.+)',
        }

        pattern = assign_patterns.get(language)
        if pattern:
            m = re.match(pattern, line)
            if m:
                var_name = m.group(1)
                value = m.group(2) if m.lastindex >= 2 else ""
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.ASSIGNMENT,
                    label=f"{var_name} = {value[:50]}",
                    line=lineno,
                    language=language,
                    metadata={'variable': var_name, 'value': value},
                )
                # Track variable definitions for DDG
                if var_name not in self._variable_defs:
                    self._variable_defs[var_name] = []
                self._variable_defs[var_name].append(self._nodes[node_id])

        # Detect dangerous function calls (sinks)
        for sink in SINKS.get(language, SINKS['generic']):
            if sink.rstrip('(') in line:
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.SINK,
                    label=sink.rstrip('('),
                    line=lineno,
                    language=language,
                    is_sink=True,
                    metadata={'function': sink},
                )
                break

        # Detect source points
        for source in SOURCES.get(language, SOURCES['generic']):
            if source.rstrip('(') in line or source.rstrip('[') in line:
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.SOURCE,
                    label=source.rstrip('(['),
                    line=lineno,
                    language=language,
                    is_source=True,
                    metadata={'source': source},
                )
                break

        # Detect string concatenation (potential injection)
        if language == 'python':
            if 'f"' in line or "f'" in line or '%' in line or '.format(' in line:
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.STRING_CONCAT,
                    label=line[:60],
                    line=lineno,
                    language=language,
                    metadata={'pattern': 'python_format'},
                )
        elif language in ('javascript', 'typescript'):
            if '`' in line or '+' in line:
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.STRING_CONCAT,
                    label=line[:60],
                    line=lineno,
                    language=language,
                    metadata={'pattern': 'js_concat'},
                )
        elif language == 'java':
            if '+' in line and ('"' in line or 'String' in line):
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.STRING_CONCAT,
                    label=line[:60],
                    line=lineno,
                    language=language,
                    metadata={'pattern': 'java_concat'},
                )
        elif language == 'php':
            if '.' in line and '"' in line:
                node_id = node_id or self._new_id()
                self._nodes[node_id] = CPGNode(
                    id=node_id,
                    node_type=NodeType.STRING_CONCAT,
                    label=line[:60],
                    line=lineno,
                    language=language,
                    metadata={'pattern': 'php_concat'},
                )

        return node_id

    def _build_ddg(self):
        """Build Data Dependency Graph edges."""
        for var_name, defs in self._variable_defs.items():
            for def_node in defs:
                for node_id, node in self._nodes.items():
                    if node == def_node:
                        continue
                    if node.is_comment:
                        continue
                    # Check if the variable is used in this node
                    if var_name in node.label or var_name in str(node.metadata.get('value', '')):
                        self._ddg_edges.append(CPGEdge(
                            source_id=def_node.id,
                            target_id=node_id,
                            edge_type=EdgeType.DATA_FLOW,
                            label=f"{var_name} flows to",
                        ))

    @property
    def nodes(self) -> Dict[str, CPGNode]:
        return self._nodes

    @property
    def edges(self) -> List[CPGEdge]:
        return self._edges + self._cfg_edges + self._ddg_edges


@dataclass
class CPG:
    """Complete Code Property Graph for a source file."""
    nodes: Dict[str, CPGNode]
    edges: List[CPGEdge]
    filepath: str = ""
    language: str = ""

    def get_sources(self) -> List[CPGNode]:
        """Get all source nodes (user input entry points)."""
        return [n for n in self.nodes.values() if n.is_source]

    def get_sinks(self) -> List[CPGNode]:
        """Get all sink nodes (dangerous functions)."""
        return [n for n in self.nodes.values() if n.is_sink]

    def get_comments(self) -> List[CPGNode]:
        """Get all comment nodes."""
        return [n for n in self.nodes.values() if n.is_comment]

    def get_functions(self) -> List[CPGNode]:
        """Get all function definition nodes."""
        return [n for n in self.nodes.values() if n.node_type == NodeType.FUNCTION]

    def get_string_concats(self) -> List[CPGNode]:
        """Get all string concatenation nodes (potential injection)."""
        return [n for n in self.nodes.values() if n.node_type == NodeType.STRING_CONCAT]

    def trace_taint_flow(self, source: CPGNode, sink: CPGNode) -> Optional[TaintFlow]:
        """Trace taint flow from a source to a sink via data dependencies."""
        # BFS through data flow edges
        visited = set()
        queue = [(source, [source])]
        visited.add(source.id)

        while queue:
            current, path = queue.pop(0)
            if current.id == sink.id:
                return TaintFlow(
                    source=source,
                    sink=sink,
                    path=path,
                    path_vars=[n.metadata.get('variable', n.label) for n in path],
                )

            for edge in self.edges:
                if edge.edge_type == EdgeType.DATA_FLOW and edge.source_id == current.id:
                    next_node = self.nodes.get(edge.target_id)
                    if next_node and next_node.id not in visited:
                        visited.add(next_node.id)
                        queue.append((next_node, path + [next_node]))

        return None

    def find_all_taint_flows(self) -> List[TaintFlow]:
        """Find all taint flows from sources to sinks."""
        flows = []
        for source in self.get_sources():
            for sink in self.get_sinks():
                flow = self.trace_taint_flow(source, sink)
                if flow:
                    flows.append(flow)
        return flows

    def is_in_comment(self, line: int) -> bool:
        """Check if a line is inside a comment block."""
        for node in self.get_comments():
            if node.line <= line <= node.end_line:
                return True
        return False

    def is_unreachable(self, line: int) -> bool:
        """Heuristic: check if a line might be unreachable."""
        # Simple heuristic: if the line before has a return/break/continue/raise
        for node in self.nodes.values():
            if node.node_type == NodeType.RETURN and node.line == line - 1:
                return True
        return False

    def get_security_summary(self) -> Dict:
        """Get a security-focused summary of the CPG."""
        sources = self.get_sources()
        sinks = self.get_sinks()
        comments = self.get_comments()
        string_concats = self.get_string_concats()

        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'sources': len(sources),
            'sinks': len(sinks),
            'comments': len(comments),
            'string_concatenations': len(string_concats),
            'taint_flows': len(self.find_all_taint_flows()),
            'functions': len(self.get_functions()),
            'high_risk': len(sources) > 0 and len(sinks) > 0,
        }


class CPGAnalyzer:
    """Analyzes CPG for security vulnerabilities."""

    def __init__(self):
        self._builder = CPGBuilder()

    def analyze(self, source: str, language: str, filepath: str = "") -> Dict:
        """Analyze source code using CPG and return security findings."""
        cpg = self._builder.build_from_source(source, language, filepath)
        summary = cpg.get_security_summary()
        taint_flows = cpg.find_all_taint_flows()

        findings = []
        for flow in taint_flows:
            severity = "CRITICAL" if flow.source.is_source and flow.sink.is_sink else "HIGH"
            findings.append({
                'type': f"Taint: {flow.source.label} -> {flow.sink.label}",
                'severity': severity,
                'source_line': flow.source.line,
                'sink_line': flow.sink.line,
                'description': (
                    f"Taint flow: '{flow.source.label}' (line {flow.source.line}) "
                    f"flows into dangerous '{flow.sink.label}' (line {flow.sink.line}). "
                    f"Path: {' -> '.join(flow.path_vars)}"
                ),
                'category': 'INJECTION',
                'analyzer': 'cpg',
            })

        # Check for string concatenation in SQL/query contexts
        for concat in cpg.get_string_concats():
            findings.append({
                'type': 'String Concatenation in Query',
                'severity': 'MEDIUM',
                'line': concat.line,
                'description': f'Potential injection via string concatenation: {concat.label[:80]}',
                'category': 'INJECTION',
                'analyzer': 'cpg',
            })

        return {
            'cpg': cpg,
            'summary': summary,
            'findings': findings,
        }


# Global singleton
_cpg_analyzer: Optional[CPGAnalyzer] = None


def get_cpg_analyzer() -> CPGAnalyzer:
    """Get or create the global CPG analyzer."""
    global _cpg_analyzer
    if _cpg_analyzer is None:
        _cpg_analyzer = CPGAnalyzer()
    return _cpg_analyzer

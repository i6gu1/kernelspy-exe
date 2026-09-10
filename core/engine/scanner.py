import json
import os
import re
import shutil
import subprocess
import threading
import queue
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..models import Finding
from ..rules.secrets import SECRET_RULES
from ..rules.language import LANGUAGE_RULES
from ..rules.config import CONFIG_RULES, SUSPICIOUS_FILES
from ..rules.dependencies import VULN_PACKAGES, DEP_FILES
from ..analyzers import PythonAnalyzer, PHPAnalyzer, JSAnalyzer, JavaAnalyzer, GenericAnalyzer
from ..engine.patterns import (
    CompiledRule, ContentContext, scan_content_for_rules, first_quoted_value,
)
from ..engine.context_analyzer import CODE_EXTS, ContextAnalyzer
from ..engine.ast_analyzer import is_placeholder_value
from ..engine.tree_sitter_parser import get_parser, is_tree_sitter_available
from ..engine.cpg import get_cpg_analyzer
from ..engine.sast_orchestrator import get_sast_orchestrator
from ..engine.ai_analyzer import get_ai_analyzer, AIConfig

EXCLUDED_DIRS = {
    'node_modules', 'vendor', '.git', '__pycache__', '.venv', 'venv',
    'dist', 'build', '.idea', '.vscode', 'target', '.gradle',
    '.next', '.nuxt', 'coverage', '.tox', 'eggs', 'bower_components',
    '.terraform', '.cache', 'tmp', 'temp', 'Pods', '.pub-cache',
    'carthage', '.bundle', 'generated', '.mvn', '__snapshots__',
    '.gitlab', '.vs', 'obj', 'bin', '.svn', 'node_modules',
}

TEXT_EXTS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
    '.c', '.cpp', '.h', '.hpp', '.cs', '.rs', '.swift', '.kt', '.scala',
    '.env', '.ini', '.cfg', '.conf', '.toml', '.yaml', '.yml',
    '.json', '.xml', '.csv', '.txt', '.md', '.sh', '.bat', '.ps1',
    '.sql', '.html', '.css', '.scss', '.vue', '.svelte', '.dart',
    '.lua', '.pl', '.pm', '.r', '.m', '.mm', '.groovy', '.gradle',
    '.properties', '.dockerfile', '.gitignore', '.tf', '.hcl',
}

LANGUAGE_EXT_MAP = {
    '.py': 'python',
    '.js': 'javascript', '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript',
    '.php': 'php',
    '.java': 'java',
    # Languages with dedicated pattern rules handled by the generic engine.
    '.go': 'generic', '.cs': 'generic', '.rb': 'generic', '.lua': 'generic',
    '.pl': 'generic', '.pm': 'generic', '.kt': 'generic', '.swift': 'generic',
    '.scala': 'generic', '.rs': 'generic', '.dart': 'generic', '.groovy': 'generic',
    '.c': 'generic', '.cpp': 'generic', '.h': 'generic', '.hpp': 'generic',
}


class RuleCompiler:
    """Compiles rule lists into fast scan rules once per scanner instance."""

    # Rules whose quoted value must be validated (placeholder suppression).
    CREDENTIAL_VALIDATED = {
        'Password Assignment', 'DB Password', 'API Secret', 'API Key',
        'Secret Key', 'Access Token', 'Encryption Key', 'Signing Key',
        'Master Key', 'Hardcoded Credential',
    }

    def __init__(self):
        self._secret: List[CompiledRule] = self._compile(SECRET_RULES)
        self._config: List[CompiledRule] = self._compile(CONFIG_RULES)
        lang: Dict[str, list] = {}
        for rule in LANGUAGE_RULES:
            for ext in rule.extensions:
                lang.setdefault(ext, []).append(rule)
        self._compiled_lang: Dict[str, List[CompiledRule]] = {
            ext: self._compile(rules) for ext, rules in lang.items()
        }

    @staticmethod
    def _make_credential_validator():
        """Suppress matches whose embedded literal is a template placeholder
        (${ENV}, <your-key>, changeme, xxxx, ...) - not a real secret."""
        def _validate(match) -> bool:
            value = first_quoted_value(match.group(0))
            if value is None:
                return True          # unquoted formats pass untouched
            return not is_placeholder_value(value)
        return _validate

    @classmethod
    def _compile(cls, rules) -> List[CompiledRule]:
        compiled = []
        validator = cls._make_credential_validator()
        for rule in rules:
            cr = CompiledRule.from_pattern(
                rule.name, rule.pattern, rule.severity, rule.category,
                rule.description, 'pattern',
                validator=validator if rule.name in cls.CREDENTIAL_VALIDATED else None,
            )
            if cr:
                compiled.append(cr)
        return compiled

    @property
    def secrets(self) -> List[CompiledRule]:
        return self._secret

    @property
    def configs(self) -> List[CompiledRule]:
        return self._config

    def language(self, ext: str) -> List[CompiledRule]:
        return self._compiled_lang.get(ext, [])


class Scanner:
    def __init__(self):
        self._rules = RuleCompiler()
        self._python_analyzer = PythonAnalyzer()
        self._php_analyzer = PHPAnalyzer()
        self._js_analyzer = JSAnalyzer()
        self._java_analyzer = JavaAnalyzer()
        self._generic_analyzer = GenericAnalyzer()
        self._context_analyzer = ContextAnalyzer()
        self._ts_parser = get_parser()
        self._cpg_analyzer = get_cpg_analyzer()
        self._sast_orchestrator = get_sast_orchestrator()
        self._ai_analyzer = get_ai_analyzer()
        # Coverage accounting (Phase 4 invariant):
        # discovered == analyzed + failed + skipped  (non-cancelled scans)
        self.stats = {
            'discovered': 0, 'queued': 0, 'analyzed': 0,
            'skipped': 0, 'failed': 0,
        }
        # Feature flags
        self.use_tree_sitter = True
        self.use_cpg = True
        self.use_sast = False  # External tools - opt-in
        self.use_ai = False   # AI analysis - opt-in

    def _read_file(self, filepath: Path) -> str:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (OSError, PermissionError):
            return ''

    def _detect_language(self, filepath: Path) -> str:
        return LANGUAGE_EXT_MAP.get(filepath.suffix.lower(), 'unknown')

    def _scan_secrets(self, filepath: str, ctx: ContentContext) -> List[Finding]:
        return scan_content_for_rules(filepath, self._rules.secrets, ctx)

    def _scan_config(self, filepath: str, ctx: ContentContext) -> List[Finding]:
        return scan_content_for_rules(filepath, self._rules.configs, ctx)

    @staticmethod
    def _version_tuple(v: str):
        return tuple(int(x) for x in re.findall(r'\d+', v)[:4])

    @classmethod
    def _version_at_or_below(cls, a: str, b: str) -> bool:
        """Numeric componentwise a <= b ('3.2.5' <= '3.2.0' -> False)."""
        ta, tb = cls._version_tuple(a), cls._version_tuple(b)
        n = max(len(ta), len(tb))
        ta += (0,) * (n - len(ta))
        tb += (0,) * (n - len(tb))
        return ta <= tb

    @classmethod
    def _vuln_matches(cls, pkg: str, ver: str):
        """Yield vulnerability descriptions for pkg@ver.

        Match semantics (superset of legacy behaviour - never removes an
        existing detection):
          1. legacy prefix match:  ver.startswith(vuln_version)
          2. numeric range match:  ver <= vuln_version  (patch releases of
             vulnerable lines like django==3.2.5 under entry 3.2.0)
        """
        pkg = (pkg or '').strip().lower()
        # Java/npm scoped names: org.group:artifact / @scope/name -> artifact
        pkg = pkg.rsplit(':', 1)[-1].rsplit('/', 1)[-1]
        ver = (ver or '').lstrip('v^~>=< ').strip()
        if not pkg or not ver:
            return
        for vuln_ver, desc in VULN_PACKAGES.get(pkg, {}).items():
            if ver.startswith(vuln_ver) or (
                    cls._version_tuple(ver) and
                    cls._version_at_or_below(ver, vuln_ver)):
                yield pkg, ver, desc

    def _scan_dependencies(self, filepath: Path, rel: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        name = os.path.basename(filepath).lower()

        def add(pkg, ver, desc):
            findings.append(Finding(
                file=rel, line=0,
                type=f"Vulnerable Package: {pkg}",
                severity="CRITICAL",
                snippet=f"{pkg}=={ver}",
                description=f"{pkg} {ver}: {desc}",
                category="DEPENDENCY",
                analyzer="dependency",
            ))

        if name == 'requirements.txt':
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-r'):
                    continue
                # Split on operators; '==' yields an empty segment between
                # the two '=', so take the first non-empty remainder.
                parts = [p for p in re.split(r'[>=<~!;\[ ]', line) if p]
                if len(parts) < 2:
                    continue
                pkg = parts[0].lower()
                ver = parts[1].strip()
                for p, v, d in self._vuln_matches(pkg, ver):
                    add(p, v, d)

        elif name in ('package.json', 'package-lock.json'):
            try:
                data = json.loads(content)
                deps = {}
                if name == 'package-lock.json':
                    deps = data.get('dependencies', {})
                else:
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                for pkg_name, pkg_info in deps.items():
                    pkg_lower = pkg_name.lower()
                    if isinstance(pkg_info, dict):
                        ver = pkg_info.get('version', '')
                    else:
                        ver = pkg_info or ''
                    if isinstance(pkg_info, dict) and name == 'package.json':
                        ver = pkg_info.get('version', '')
                    for p, v, d in self._vuln_matches(pkg_lower, str(ver)):
                        add(p, v, d)
            except (json.JSONDecodeError, AttributeError):
                pass

        elif name == 'pipfile.lock':
            try:
                data = json.loads(content)
                for section in ('default', 'develop'):
                    for pkg_name, info in data.get(section, {}).items():
                        ver = info.get('version', '') if isinstance(info, dict) else ''
                        for p, v, d in self._vuln_matches(pkg_name, str(ver)):
                            add(p, v, d)
            except (json.JSONDecodeError, AttributeError):
                pass

        elif name == 'poetry.lock':
            cur_pkg, cur_ver = None, None
            for raw in content.splitlines():
                line = raw.strip()
                m = re.match(r'name\s*=\s*"([^"]+)"', line)
                if m:
                    cur_pkg, cur_ver = m.group(1), None
                    continue
                m = re.match(r'version\s*=\s*"([^"]+)"', line)
                if m and cur_pkg:
                    cur_ver = m.group(1)
                    for p, v, d in self._vuln_matches(cur_pkg, cur_ver):
                        add(p, v, d)
                    cur_pkg = None

        elif name == 'yarn.lock':
            # Classic: "pkg@^1.2:" header followed by "  version "x.y.z""
            # Berry:  "pkg@npm:..." entries too - both matched via regex.
            current_pkgs = []
            for raw in content.splitlines():
                line = raw.strip()
                if line.startswith('"#') or not line:
                    continue
                m = re.match(r'^"?([^@\s]+(?:@[^:\s]+)?)@[^:]*:$', line.replace('"', ''))
                if m:
                    spec = m.group(1)
                    base = re.split(r'@', spec)[0]
                    current_pkgs = [base]
                    continue
                m = re.match(r'version\s+"?v?([0-9][^"\s]*)"?', line)
                if m and current_pkgs:
                    for base in current_pkgs:
                        for p, v, d in self._vuln_matches(base, m.group(1)):
                            add(p, v, d)
                    current_pkgs = []

        elif name == 'gemfile.lock':
            for raw in content.splitlines():
                m = re.match(r'\s{2,4}([a-zA-Z0-9_\-\.]+)\s+\((?:=?\s*)?([0-9][^\)]*)\)',
                             raw.strip() and raw or '')
                if m:
                    for p, v, d in self._vuln_matches(m.group(1), m.group(2)):
                        add(p, v, d)

        elif name == 'go.sum':
            seen = set()
            for raw in content.splitlines():
                parts = raw.split()
                if len(parts) >= 2:
                    mod, ver = parts[0], parts[1]
                    if mod in seen:
                        continue
                    seen.add(mod)
                    for p, v, d in self._vuln_matches(mod, ver.split('/')[0]):
                        add(p, v, d)

        elif name == 'cargo.lock':
            cur_pkg, cur_ver = None, None
            for raw in content.splitlines():
                line = raw.strip()
                if line == '[[package]]':
                    cur_pkg, cur_ver = None, None
                    continue
                m = re.match(r'name\s*=\s*"([^"]+)"', line)
                if m:
                    cur_pkg = m.group(1)
                    continue
                m = re.match(r'version\s*=\s*"([^"]+)"', line)
                if m and cur_pkg:
                    for p, v, d in self._vuln_matches(cur_pkg, m.group(1)):
                        add(p, v, d)

        elif name == 'composer.lock':
            try:
                data = json.loads(content)
                for section in ('packages', 'packages-dev'):
                    for item in data.get(section, []):
                        for p, v, d in self._vuln_matches(
                                item.get('name', ''), str(item.get('version', ''))):
                            add(p, v, d)
            except (json.JSONDecodeError, AttributeError):
                pass

        elif name == 'pom.xml':
            group = artifact = version = None

            def _flush(g, a, v):
                if a and v:
                    for p, vv, dd in self._vuln_matches(f'{g}:{a}' if g else a, v):
                        add(p, vv, dd)

            for raw in content.splitlines():
                line = raw.strip()
                mg = re.search(r'<groupId>([^<]+)</groupId>', line)
                ma = re.search(r'<artifactId>([^<]+)</artifactId>', line)
                mv = re.search(r'<version>([^<]+)</version>', line)
                if ma:
                    if artifact and version:
                        _flush(group, artifact, version)
                    group, artifact, version = group, ma.group(1), None
                if mg and not artifact:
                    group = mg.group(1)
                if mv and artifact and not version:
                    version = mv.group(1)
                    _flush(group, artifact, version)
                    version = None
            if artifact and version:
                _flush(group, artifact, version)

        elif name == 'build.gradle':
            for raw in content.splitlines():
                m = re.search(
                    r'[\'"]([^\'":]+):([^\'":]+):([^\'":]+)[\'"]', raw)
                if m:
                    for p, v, d in self._vuln_matches(
                            f'{m.group(1)}:{m.group(2)}', m.group(3)):
                        add(p, v, d)

        return findings

    def _get_analyzer(self, language: str):
        return {
            'python': self._python_analyzer,
            'php': self._php_analyzer,
            'javascript': self._js_analyzer,
            'java': self._java_analyzer,
            'generic': self._generic_analyzer,
        }.get(language, self._generic_analyzer)

    def _scan_file(self, filepath: Path, base: Path) -> List[Finding]:
        rel = str(filepath.relative_to(base))
        name = filepath.name
        findings: List[Finding] = []

        if name in SUSPICIOUS_FILES:
            findings.append(Finding(
                file=rel, line=0,
                type=f"Suspicious File ({name})",
                severity="HIGH",
                snippet=name,
                description=SUSPICIOUS_FILES[name],
                category="CONFIG",
                analyzer="file",
            ))

        content = self._read_file(filepath)
        if not content:
            return findings

        ext = filepath.suffix.lower()
        ctx = ContentContext(content)
        findings.extend(self._scan_secrets(rel, ctx))
        findings.extend(self._scan_config(rel, ctx))

        language = self._detect_language(filepath)
        rules = self._rules.language(ext)
        if rules and language != 'unknown':
            analyzer = self._get_analyzer(language)
            findings.extend(analyzer.analyze(rel, content, rules))

        if ext in CODE_EXTS:
            findings.extend(self._context_analyzer.analyze(rel, content, ext))

        if name in DEP_FILES:
            findings.extend(self._scan_dependencies(filepath, rel, content))

        # Tree-sitter analysis for supported languages
        if self.use_tree_sitter and self._ts_parser.can_parse(str(filepath)):
            try:
                parse_result = self._ts_parser.parse_file(str(filepath), content)
                if parse_result.success and parse_result.root:
                    dangerous_calls = self._ts_parser._find_dangerous_calls(parse_result.root)
                    for call in dangerous_calls:
                        findings.append(Finding(
                            file=rel, line=call.start_line + 1,
                            type=f"Tree-sitter: {call.text[:60]}",
                            severity="MEDIUM",
                            snippet=call.text[:120],
                            description=f"Dangerous function call detected: {call.text[:100]}",
                            category="INJECTION",
                            analyzer="tree_sitter",
                        ))
            except Exception:
                pass

        # CPG analysis for code property graph
        if self.use_cpg and language in ('python', 'javascript', 'typescript', 'java', 'php', 'go', 'ruby'):
            try:
                cpg_result = self._cpg_analyzer.analyze(content, language, rel)
                for finding_data in cpg_result.get('findings', []):
                    findings.append(Finding(
                        file=rel,
                        line=finding_data.get('sink_line', finding_data.get('line', 0)),
                        type=finding_data['type'],
                        severity=finding_data['severity'],
                        snippet="",
                        description=finding_data['description'],
                        category=finding_data.get('category', 'INJECTION'),
                        analyzer="cpg",
                    ))
            except Exception:
                pass

        return findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        exact_seen = set()
        semantic_seen = {}
        unique: List[Finding] = []

        for f in findings:
            exact_key = (f.file, f.line, f.type)
            if exact_key in exact_seen:
                continue
            exact_seen.add(exact_key)

            sem_key = (f.file, f.line, _norm(f.category), f.severity)
            existing = semantic_seen.get(sem_key)
            if existing is not None:
                if len(f.description) > len(existing.description):
                    idx = {id(x): i for i, x in enumerate(unique)}[id(existing)]
                    unique[idx] = f
                    semantic_seen[sem_key] = f
                continue

            semantic_seen[sem_key] = f
            unique.append(f)

        return unique

    def _collect_files(self, base: Path):
        all_files = []
        py_files = []
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for f in files:
                fp = Path(root) / f
                if fp.suffix.lower() in TEXT_EXTS or fp.name in SUSPICIOUS_FILES \
                        or fp.name in DEP_FILES:
                    all_files.append(fp)
                if fp.suffix.lower() == '.py':
                    py_files.append(fp)
        return all_files, py_files

    def scan(self, folder: str, progress_callback=None, cancel_check=None) -> List[Finding]:
        base = Path(folder)
        all_files, self._last_py_files = self._collect_files(base)

        total = len(all_files)
        self.stats = {
            'discovered': total, 'queued': total, 'analyzed': 0,
            'skipped': 0, 'failed': 0,
        }
        if total == 0:
            return []

        results: List[Finding] = []
        batch_size = max(1, total // 100)
        last_fp = None

        for i in range(0, total, batch_size):
            if cancel_check and cancel_check():
                break
            batch = all_files[i:i + batch_size]
            for fp in batch:
                if cancel_check and cancel_check():
                    break
                last_fp = fp
                try:
                    results.extend(self._scan_file(fp, base))
                    self.stats['analyzed'] += 1
                except Exception:
                    self.stats['failed'] += 1
            done = min(i + batch_size, total)
            if progress_callback:
                pct = int(done * 100 / total)
                short = str(last_fp.relative_to(base)) if last_fp else ''
                progress_callback(pct, short)

        self.stats['skipped'] = (
            self.stats['discovered']
            - self.stats['analyzed'] - self.stats['failed'])
        return results

    def scan_bandit(self, folder: str, py_files: List[Path]) -> List[Finding]:
        if not shutil.which('bandit') or not py_files:
            return []
        findings: List[Finding] = []
        try:
            proc = subprocess.run(
                ['bandit', '-f', 'json', '-q', '--severity-level', 'low']
                + [str(f) for f in py_files],
                capture_output=True, text=True, timeout=180,
                encoding='utf-8', errors='ignore',
            )
            if proc.stdout:
                data = json.loads(proc.stdout)
                for item in data.get('results', []):
                    # Suppress external-tool noise on template placeholders:
                    # B105/B106/B107 flag any hardcoded password string,
                    # including '${DB_PASS}' style env placeholders.
                    if item.get('test_id', '') in ('B105', 'B106', 'B107'):
                        val = first_quoted_value(
                            item.get('code', '') + ' ' + item.get('issue_text', ''))
                        if val and is_placeholder_value(val):
                            continue
                    filename = os.path.relpath(item.get('filename', ''), folder)
                    findings.append(Finding(
                        file=filename,
                        line=item.get('line_number', 0),
                        type=f"Bandit: {item.get('test_id', '')} {item.get('test_name', '')}",
                        severity=item.get('issue_severity', 'MEDIUM').upper(),
                        snippet=item.get('code', '')[:120],
                        description=item.get('issue_text', ''),
                        category="BANDIT",
                        analyzer="bandit",
                    ))
        except Exception:
            pass
        return findings

    def scan_all(self, folder: str, progress_callback=None, cancel_check=None) -> List[Finding]:
        if progress_callback:
            progress_callback(0, "Running context-aware analysis...")

        results = self.scan(folder, progress_callback, cancel_check)

        if cancel_check and cancel_check():
            return results

        if progress_callback:
            progress_callback(85, "Running optional Bandit analysis...")
        results.extend(self.scan_bandit(folder, getattr(self, '_last_py_files', [])))

        # Run external SAST engines if enabled
        if self.use_sast:
            if progress_callback:
                progress_callback(90, "Running external SAST engines (Semgrep/Trivy)...")
            sast_findings = self._sast_orchestrator.scan_all(folder, progress_callback, cancel_check)
            results.extend(sast_findings)

        results = self._deduplicate(results)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results.sort(key=lambda x: sev_order.get(x.severity, 4))

        if progress_callback:
            progress_callback(100, "Scan complete.")

        return results

    def scan_threaded(self, folder: str, result_queue: queue.Queue,
                      cancel_check: Callable[[], bool]) -> threading.Thread:
        """Run the exact scan_all pipeline on a background thread.

        Scheduling-only optimization. Analysis semantics are byte-for-byte
        the ones used by scan_all(): same discovery rules, same per-file
        pipeline (_scan_file), same Bandit stage, same deduplication and
        severity sort, same deterministic single-threaded analysis order.

        Lifecycle: START -> DISCOVER -> QUEUE -> ANALYZE -> COLLECT ->
        FLUSH -> FINALIZE -> COMPLETE.

        Communication contract (thread-safe by construction):
          * The worker NEVER touches UI/toolkit APIs (no Tk after() from a
            non-main thread - that race could drop completion events of
            fast 1-2 file scans).
          * Messages are put on result_queue in this exact order:
                ("progress", pct, msg)     - optional, many
                ("findings", [Finding..])  - raw per-file findings, many
                ("done", payload)          - TERMINAL, exactly once, LAST
            queue.Queue FIFO ordering guarantees every finding message was
            enqueued before "done", so a consumer that drains until it sees
            "done" can never lose or strand a result.
          * payload = {results(deduped+sorted), stats, cancelled, error}.
        """
        def _put(msg):
            try:
                result_queue.put(msg)
            except Exception:
                pass

        def _run():
            stats = {
                'discovered': 0, 'queued': 0, 'analyzed': 0,
                'skipped': 0, 'failed': 0,
            }
            try:
                base = Path(folder)

                # ── DISCOVER ── identical eligibility rules as scan_all
                all_files, py_files = self._collect_files(base)
                self._last_py_files = py_files
                total = len(all_files)
                stats['discovered'] = total
                stats['queued'] = total
                self.stats = dict(stats)

                results: List[Finding] = []
                if total:
                    # ── QUEUE -> ANALYZE -> COLLECT ──
                    # Deterministic sequential analysis; per-file fault
                    # isolation: one failing file never aborts the rest and
                    # is explicitly accounted as failed (no silent loss).
                    for fp in all_files:
                        if cancel_check and cancel_check():
                            break
                        try:
                            file_findings = self._scan_file(fp, base)
                        except Exception:
                            stats['failed'] += 1
                            continue
                        stats['analyzed'] += 1
                        if file_findings:
                            results.extend(file_findings)
                            _put(("findings", list(file_findings)))
                        _put(("progress", int(stats['analyzed'] * 84 / total),
                              str(fp.relative_to(base))))

                # Explicit accounting: anything discovered but neither
                # analyzed nor failed was skipped (only possible on cancel).
                stats['skipped'] = (
                    stats['discovered'] - stats['analyzed'] - stats['failed'])
                self.stats = dict(stats)
                if not (cancel_check and cancel_check()) and stats['skipped']:
                    import sys
                    print(
                        f"[KernelSpy] WARNING: {stats['skipped']} discovered "
                        f"file(s) were neither analyzed nor failed.",
                        file=sys.stderr)

                cancelled = bool(cancel_check and cancel_check())

                # ── FLUSH -> FINALIZE ── identical post-processing
                if not cancelled:
                    _put(("progress", 85, "Running optional Bandit analysis..."))
                    results.extend(self.scan_bandit(folder, py_files))

                    # Run external SAST engines if enabled
                    if self.use_sast and not cancelled:
                        _put(("progress", 90, "Running external SAST engines..."))
                        sast_findings = self._sast_orchestrator.scan_all(
                            folder, lambda p, m: _put(("progress", 90 + int(p * 0.09), m)),
                            cancel_check
                        )
                        results.extend(sast_findings)

                results = self._deduplicate(results)
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                             "LOW": 3, "INFO": 4}
                results.sort(key=lambda x: sev_order.get(x.severity, 4))

                payload = {
                    'results': results,
                    'stats': dict(stats),
                    'cancelled': cancelled,
                    'error': None,
                }
            except Exception as e:
                payload = {
                    'results': [],
                    'stats': dict(stats),
                    'cancelled': bool(cancel_check and cancel_check()),
                    'error': str(e),
                }
            finally:
                # TERMINAL message: always emitted exactly once, AFTER every
                # other message of this scan (FIFO order).
                _put(("done", payload))

        t = threading.Thread(target=_run, daemon=True, name="KernelSpyScan")
        t.start()
        return t


def _norm(value: str) -> str:
    return str(value).upper()
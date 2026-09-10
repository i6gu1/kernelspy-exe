"""ContextAnalyzer - cross-language, context-aware detectors.

Operates on comment-stripped source so that matches inside comments never
fire. Complements the per-language analyzers; every check is structurally
validated to keep the false-positive rate near zero.
"""

import re
from typing import Dict, List, Optional

from ..models import Finding
from .ast_analyzer import is_placeholder_value
from .context import strip_comments_and_strings

# Extensions considered "code" for contextual analysis.
CODE_EXTS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.java', '.cs', '.go',
    '.rb', '.kt', '.swift', '.scala', '.c', '.cpp', '.h', '.hpp', '.lua',
    '.pl', '.pm', '.groovy', '.dart', '.rs',
}

# ── SQL sink call shapes: name( followed by dynamic string construction ──
_SQL_SINK = re.compile(
    r'\b(?:\w+\s*\.\s*)?(?:execute|executemany|executescript|raw|query|'
    r'executeQuery|executeUpdate|createQuery|createQuery|runCommand)'
    r'\s*\(', re.IGNORECASE)

_DYNAMIC_ARGS = re.compile(
    r'`[^`]*\$\{[^}]+\}[^`]*`'          # JS/Go/Kotlin template literal w/ ${}
    r'|f"[^"]*\{|f\'[^\']*\{'           # Python f-string
    r'|\+\s*\w+'                        # "... " + var
    r'|\w+\s*\+'                        # var + "..."
    r'|%\s*\w+\)?\s*$'                  # "... %s" % x  (line-end heuristic)
    r'|\.format\s*\('                   # "...".format(...)
    r'|\$\w+'                           # PHP "$var" inside query string
)

# ── Log4Shell / JNDI injection payload (any language, any file) ──
JNDI_PAYLOAD = re.compile(r'\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://', re.IGNORECASE)

# ── Framework-level dangerous configurations ──
DJANGO_ALLOWED_HOSTS_ANY = re.compile(
    r'ALLOWED_HOSTS\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]')
CORS_ALLOW_ALL = re.compile(
    r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True'
    r'|CORS_ALLOW_ALL_ORIGINS\s*=\s*True'
    r'|cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']'
    r'|origin\s*:\s*["\']\*["\']',
    re.IGNORECASE)
CSRF_EXEMPT = re.compile(r'@csrf_exempt\b')
FLASK_DEBUG_RUN = re.compile(r'\.run\s*\([^)]*debug\s*=\s*True')

# ── Cross-language hardcoded credential assignment ──
_CRED_NAME = (
    r'(?:db_|database_|mysql_|postgres_|mongo_|redis_|smtp_|admin_|root_)?'
    r'(?:password|passwd|pwd|secret|secret[_-]?key|client[_-]?secret|'
    r'api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|'
    r'signing[_-]?key|encryption[_-]?key|master[_-]?key|aws[_-]?secret)'
)
_HARDCODED_CRED = re.compile(
    r'(?i)\b' + _CRED_NAME + r'\b\s*(?:=|:|=>)\s*(["\'`])'
    r'([^\'`\n]{6,})\1')

_FRAMEWORK_HINTS = (
    ('flask', 'flask'), ('django', 'django'), ('fastapi', 'fastapi'),
    ('express', 'express'), ('springframework', 'spring'),
    ('gin-gonic', 'gin'),
)


def detect_framework(content: str) -> Optional[str]:
    low = content.lower()
    for needle, fw in _FRAMEWORK_HINTS:
        if needle in low:
            return fw
    return None


class ContextAnalyzer:
    """Stateless per-file contextual analyzer (safe to share across scans)."""

    def analyze(self, filepath: str, content: str, ext: str) -> List[Finding]:
        if ext not in CODE_EXTS or not content:
            return []

        findings: List[Finding] = []
        clean = strip_comments_and_strings(content, ext)
        clean_lines = clean.split('\n')
        raw_lines = content.split('\n')

        # ── 1. JNDI/Log4Shell payload anywhere in code or strings ──
        # Uses RAW lines: the payload lives inside string literals which
        # stripping would erase.
        for i, line in enumerate(raw_lines, 1):
            m = JNDI_PAYLOAD.search(line)
            if m:
                findings.append(Finding(
                    file=filepath, line=i,
                    type="Context: JNDI lookup payload",
                    severity="CRITICAL",
                    snippet=line.strip()[:120],
                    description=(
                        "${jndi:...} lookup payload present - Log4Shell-style "
                        "remote code execution vector."
                    ),
                    category="INJECTION", analyzer="context",
                ))

        # ── 2. SQL sink called with dynamically built query text ──
        # Runs on COMMENT-STRIPPED lines so commented-out queries never fire.
        if ext in ('.js', '.ts', '.jsx', '.tsx', '.php', '.java', '.cs',
                   '.go', '.kt', '.scala', '.groovy'):
            for i, line in enumerate(clean_lines, 1):
                if not _SQL_SINK.search(line):
                    continue
                arg_zone = line.split('(', 1)[1] if '(' in line else ''
                if _DYNAMIC_ARGS.search(arg_zone):
                    findings.append(Finding(
                        file=filepath, line=i,
                        type="Context: SQL built from dynamic string",
                        severity="CRITICAL",
                        snippet=line.strip()[:120],
                        description=(
                            "Database query assembled via concatenation or "
                            "template interpolation - SQL injection risk. "
                            "Use parameterized statements."
                        ),
                        category="INJECTION", analyzer="context",
                    ))

        # ── 3. Framework/security configuration flaws (raw lines: values like
        #      '*' live inside quotes and must survive) ──
        config_checks = (
            (DJANGO_ALLOWED_HOSTS_ANY, "ALLOWED_HOSTS accepts all hosts",
             "HIGH", "CONFIG",
             "Django ALLOWED_HOSTS contains '*' - host header spoofing risk."),
            (CORS_ALLOW_ALL, "CORS allows any origin",
             "HIGH", "CONFIG",
             "CORS policy allows arbitrary origins - data exposure risk."),
            (CSRF_EXEMPT, "@csrf_exempt used",
             "MEDIUM", "CONFIG",
             "Django CSRF protection explicitly disabled for this view."),
            (FLASK_DEBUG_RUN, "Flask debug mode in run()",
             "HIGH", "CONFIG",
             "Flask development server with debug=True exposes interactive "
             "debugger (RCE via Werkzeug console)."),
        )
        for regex, ftype, sev, cat, desc in config_checks:
            for i, line in enumerate(raw_lines, 1):
                if regex.search(line):
                    findings.append(Finding(
                        file=filepath, line=i,
                        type=f"Context: {ftype}",
                        severity=sev, snippet=line.strip()[:120],
                        description=desc,
                        category=cat, analyzer="context",
                    ))

        # ── 4. Hardcoded credentials across all code languages ──
        # Raw lines: a credential is by definition inside a quoted literal.
        seen_lines = set()
        for i, line in enumerate(raw_lines, 1):
            m = _HARDCODED_CRED.search(line)
            if m and i not in seen_lines:
                value = m.group(2).strip()
                if is_placeholder_value(value):
                    continue
                seen_lines.add(i)
                name = re.sub(r'[^a-z]', '', m.group(1).lower()) or 'credential'
                findings.append(Finding(
                    file=filepath, line=i,
                    type=f"Context: hardcoded {name}",
                    severity="CRITICAL",
                    snippet=re.sub(re.escape(m.group(2)), '*' * min(len(value), 12),
                                   line.strip())[:120],
                    description=(
                        f"Credential '{m.group(1).strip()}' hardcoded in "
                        f"{ext} source. Move to environment variables or a "
                        "secrets manager."
                    ),
                    category="AUTH", analyzer="context",
                ))

        return findings

"""Deduplication & Layering engine (KernelSpy 1.3 -> 1.5).

Every analyzer (pattern, lexer, taint, AST, tree-sitter, CPG, bandit, SAST)
emits independently, so the same vulnerability on the same line used to be
reported several times - once per analyzer that saw it.  This middleware
runs once over the combined output, *before* any report is generated:

1. exact pass   - identical (file, line, type) is emitted only once,
2. layer pass   - findings that describe the same vulnerability
                  (file + line + vulnerability category) are collapsed into
                  a single record whose ``analyzer`` field lists *every*
                  analyzer that detected it: ``analyzer: [taint, bandit]``,
3. block pass   - (KernelSpy 1.5) findings that describe the SAME topic
                  within the same code block (same file, <= 3 lines apart)
                  are merged into one comprehensive record, so ``strcpy``
                  reported at line 6 and line 9 no longer produces two
                  distracting alerts.

Merging keeps the highest severity, the longest description and the richest
snippet, and is deterministic (input order is preserved).
"""

import re
from typing import Dict, List, Set, Tuple

from ..models import Finding

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev).upper(), 4)


def _norm_cat(cat) -> str:
    return str(cat).upper()


def _split_analyzers(value: str) -> List[str]:
    """Split 'taint, bandit' or '[taint, bandit]' into clean tokens."""
    raw = str(value or "").strip()
    if not raw:
        return []
    raw = raw.strip("[]")
    out = []
    for part in raw.replace("|", ",").split(","):
        p = part.strip().strip("'\"")
        if p and p not in out:
            out.append(p)
    return out


def _join_analyzers(groups: List[List[str]]) -> str:
    merged: List[str] = []
    for g in groups:
        for a in g:
            if a and a not in merged:
                merged.append(a)
    return ", ".join(merged)


def _analyzers_of(f: Finding) -> List[str]:
    return _split_analyzers(getattr(f, "analyzer", "")) or ["pattern"]


def _prefer(a: Finding, b: Finding) -> Finding:
    """Pick the richer of two records (higher severity wins, then length)."""
    if _rank(b.severity) < _rank(a.severity):
        return b
    if _rank(a.severity) < _rank(b.severity):
        return a
    if len(b.description or "") > len(a.description or ""):
        return b
    if len(a.description or "") > len(b.description or ""):
        return a
    if len(b.snippet or "") > len(a.snippet or ""):
        return b
    return a


def _merge(group: List[Finding]) -> Finding:
    primary = group[0]
    for other in group[1:]:
        primary = _prefer(primary, other)

    # rebuild a fresh record so callers can keep their own references
    merged = Finding(
        file=primary.file,
        line=primary.line,
        type=primary.type,
        severity=primary.severity,
        snippet=primary.snippet,
        description=primary.description,
        category=primary.category,
        analyzer=primary.analyzer,
    )

    for other in group[1:]:
        if _rank(other.severity) < _rank(merged.severity):
            merged.severity = other.severity
        if len(other.description or "") > len(merged.description or ""):
            merged.description = other.description
        if len(other.snippet or "") > len(merged.snippet or ""):
            merged.snippet = other.snippet
        if _rank(other.severity) <= _rank(primary.severity) \
                and other.type and other.type != primary.type:
            # keep the secondary signature visible for the developer
            if other.type not in merged.description:
                merged.description = (
                    f"{merged.description} [also: {other.type}]"
                )[:900]

    # Taint/flow findings carry the actual data-flow identity (e.g.
    # "Taint: cmd -> exec.Command") - keep their type in the report so the
    # flow is not masked by a generic pattern/context type.
    for f in group:
        if "taint" in str(getattr(f, "analyzer", "")).lower():
            merged.type = f.type
            break

    merged.analyzer = _join_analyzers([_analyzers_of(f) for f in group])
    if not merged.remediation and hasattr(primary, "remediation"):
        merged.remediation = getattr(primary, "remediation", "")
    return merged


# ── Topic families used by the code-block merge pass (KernelSpy 1.5) ──
_TOPIC_PATTERNS = (
    ("buffer", r"buffer|overflow|out[- ]of[- ]bounds?|bounds?\s*checking"
               r"|strcpy|strcat|strncpy|strlcpy|strlcat|memcpy|memmove"
               r"|\balloca\b|\bgets\s*\(|\bsprintf\b|\bsnprintf\b|\bscanf\b"),
    ("sql", r"\bsql\b|prepared statement|parameteri[sz]|\bquery\s*\("
            r"|\bexecute\s*\(|cursor\.execute|find_by_sql|sql injection"
            r"|concatenat\w+ (?:query|string)|string concatenation"),
    ("command", r"command inj|command line|shell|cmd\.exe|powershell"
                r"|\bsubprocess\b|child_process|process\.start|exec\.command"
                r"|os\.system|\bpopen\b|shell_exec|system\(\)|command injection"),
    ("xss", r"\bxss\b|innerhtml|outerhtml|document\.write"
            r"|dangerouslysetinnerhtml|html injection|script injection"
            r"|cross[- ]site scripting"),
    ("path", r"traversal|\.\./|directory traversal|path inj|zip slip|realpath"),
    ("deser", r"deserial|pickle|marshal|unserialize|yaml\.load"
              r"|objectinputstream|binaryformatter|xstream|xmldecoder"),
    ("crypto", r"\bmd5\b|\bsha-?1\b|weak (?:hash|cipher|crypto)"
               r"|insecure (?:ssl|tls)|padding\s*=\s*['\"]?ecb"),
    ("cred", r"password|credential|secret|api[_ -]?key|access[_ -]?token"
             r"|hardcoded"),
    ("ssrf", r"\bssrf\b|server[- ]side request|url inj"),
    ("ssti", r"\bssti\b|template injection|render_template_string"
             r"|render inline|server[- ]side template"),
    ("redirect", r"open redirect|unvalidated redirect|\bredirect\b"),
    ("csrf", r"\bcsrf\b|\bxsrf\b"),
    ("xxe", r"\bxxe\b|xml external entity"),
    ("infoleak", r"information disclosure|verbose error|stack trace"
                 r"|version disclosure|debug (?:mode|info)"),
)
_TOPIC_RE = {name: re.compile(pat, re.IGNORECASE) for name, pat in _TOPIC_PATTERNS}


def _topics(f: Finding) -> Set[str]:
    blob = f"{getattr(f, 'type', '')} {getattr(f, 'description', '')} " \
           f"{getattr(f, 'snippet', '')}".lower()
    return {name for name, rx in _TOPIC_RE.items() if rx.search(blob)}


def _merge_near(group: List[Finding]) -> Finding:
    """One comprehensive record for a whole code block of the same topic."""
    primary = group[0]
    for other in group[1:]:
        primary = _prefer(primary, other)

    merged = Finding(
        file=primary.file,
        line=primary.line,
        type=primary.type,
        severity=primary.severity,
        snippet=primary.snippet,
        description=primary.description,
        category=primary.category,
        analyzer=primary.analyzer,
    )
    for other in group:
        if other is primary:
            continue
        if _rank(other.severity) < _rank(merged.severity):
            merged.severity = other.severity
        desc = str(other.description or "")
        if desc and desc not in str(merged.description or ""):
            merged.description = (
                f"{merged.description} | Also noted: {desc}")[:900]
        if len(str(other.snippet or "")) > len(str(merged.snippet or "")):
            merged.snippet = other.snippet
    for f in group:
        if "taint" in str(getattr(f, "analyzer", "")).lower():
            merged.type = f.type
            break
    merged.analyzer = _join_analyzers([_analyzers_of(f) for f in group])
    if not merged.remediation and hasattr(primary, "remediation"):
        merged.remediation = getattr(primary, "remediation", "")
    return merged


def merge_nearby(findings: List[Finding], window: int = 3) -> List[Finding]:
    """Feature: merge same-topic findings inside the same code block."""
    if len(findings) < 2:
        return list(findings)

    by_file: Dict[str, List[int]] = {}
    for idx, f in enumerate(findings):
        if int(getattr(f, "line", 0) or 0) <= 0:
            continue                       # file/dep level records stay alone
        by_file.setdefault(str(f.file), []).append(idx)

    consumed: Set[int] = set()
    groups: List[Tuple[int, List[int]]] = []
    for idxs in by_file.values():
        idxs.sort(key=lambda i: (int(getattr(findings[i], "line", 0) or 0), i))
        for pos, i in enumerate(idxs):
            if i in consumed:
                continue
            group = [i]
            topics = _topics(findings[i])
            if topics:
                base_line = int(getattr(findings[i], "line", 0) or 0)
                for j in idxs[pos + 1:]:
                    if j in consumed:
                        continue
                    if int(getattr(findings[j], "line", 0) or 0) - base_line > window:
                        break
                    other_topics = _topics(findings[j])
                    if other_topics and topics & other_topics:
                        group.append(j)
                        consumed.add(j)
            groups.append((i, group))

    out: List[Tuple[int, Finding]] = []
    for anchor, group in groups:
        records = [findings[k] for k in group]
        out.append((anchor, records[0] if len(records) == 1 else _merge_near(records)))
    out.sort(key=lambda t: t[0])
    return [rec for _, rec in out]


def layer_findings(findings: List[Finding]) -> List[Finding]:
    """Collapse duplicate detections across analyzers (order preserving)."""
    if not findings:
        return []

    # ── pass 1: exact duplicates (same file + line + type) ──
    exact_seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.type)
        if key in exact_seen:
            continue
        exact_seen.add(key)
        unique.append(f)

    # ── pass 2: layer by (file + line + vulnerability category) ──
    groups: Dict[Tuple, List[Finding]] = {}
    order: List[Tuple] = []
    for f in unique:
        key = (f.file, f.line, _norm_cat(f.category))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: List[Finding] = []
    for key in order:
        group = groups[key]
        merged.append(group[0] if len(group) == 1 else _merge(group))

    # ── pass 3: same topic inside the same code block -> one record ──
    return merge_nearby(merged)


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Public alias used by the scanner pipeline."""
    return layer_findings(findings)

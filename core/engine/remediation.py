"""Remediation & Auto-Fix engine (KernelSpy 1.3).

Loads ``core/rules/remediation.json`` and attaches a "How to fix" guidance
plus a safe code template to every finding.  The rules file ships with the
app (bundled by PyInstaller); a missing/corrupt file degrades to a generic
built-in guidance instead of raising.
"""

import json
import os
import threading
from typing import Dict, List, Optional, Tuple

_LOCK = threading.Lock()
_RULES: Optional[Dict[str, dict]] = None

_FALLBACK = {
    "GENERIC": {
        "title": "Security Finding",
        "remediation": (
            "Review the flagged code, confirm whether untrusted input can "
            "reach it, and use the framework-recommended safe API."
        ),
        "code": {"default": "use the framework-recommended safe API"},
    }
}

# file extension -> language key used in the "code" block of a rule
_EXT_LANG = {
    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
    '.mjs': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
    '.php': 'php', '.java': 'java', '.go': 'go', '.rb': 'ruby',
    '.cs': 'csharp', '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
    '.dart': 'dart', '.rs': 'rust', '.lua': 'lua', '.pl': 'perl',
    '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
}


def _candidate_paths() -> List[str]:
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    base = getattr(sys, '_MEIPASS', here)
    return [
        os.path.join(base, 'core', 'rules', 'remediation.json'),
        os.path.join(here, '..', 'rules', 'remediation.json'),
        os.path.join(os.getcwd(), 'core', 'rules', 'remediation.json'),
    ]


def load_rules(force: bool = False) -> Dict[str, dict]:
    """Load (and cache) the remediation rule book."""
    global _RULES
    if _RULES is not None and not force:
        return _RULES
    with _LOCK:
        if _RULES is not None and not force:
            return _RULES
        rules = {}
        for path in _candidate_paths():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict) and data:
                    rules = data
                    break
            except Exception:
                continue
        if not rules:
            rules = dict(_FALLBACK)
        _RULES = rules
        return _RULES


def _lang_for(file_path: str) -> str:
    name = (file_path or '').lower()
    for ext, lang in _EXT_LANG.items():
        if name.endswith(ext):
            return lang
    return 'default'


def _score(rule: dict, category: str, type_str: str) -> int:
    """Rank how well a rule matches a finding (higher = better)."""
    cats = [str(c).upper() for c in rule.get('categories', [])]
    kws = [str(k).lower() for k in rule.get('type_keywords', [])]
    cat = (category or '').upper()
    typ = (type_str or '').lower()

    score = 0
    if cats and cat in cats:
        score += 10
    elif not cats:
        score += 1
    for kw in kws:
        if kw and kw in typ:
            score += 3
            break
    if not kws and not cats:
        score = 1 if score == 0 else score
    return score


# Bandit test-id -> remediation rule id (so external reports get a fix too)
_BANDIT_MAP = {
    'B101': 'GENERIC', 'B102': 'CODE_INJECTION',
    'B103': 'INSECURE_CONFIG', 'B104': 'INSECURE_CONFIG',
    'B105': 'HARDCODED_SECRET', 'B106': 'HARDCODED_SECRET',
    'B107': 'HARDCODED_SECRET', 'B108': 'PATH_TRAVERSAL',
    'B110': 'GENERIC', 'B112': 'GENERIC', 'B113': 'INSECURE_CONFIG',
    'B201': 'INSECURE_CONFIG', 'B202': 'PATH_TRAVERSAL',
    'B301': 'DESERIALIZATION', 'B302': 'DESERIALIZATION',
    'B303': 'WEAK_CRYPTO', 'B304': 'DESERIALIZATION',
    'B305': 'DESERIALIZATION', 'B306': 'DESERIALIZATION',
    'B307': 'CODE_INJECTION', 'B324': 'WEAK_CRYPTO',
    'B403': 'DESERIALIZATION', 'B404': 'GENERIC',
    'B405': 'DESERIALIZATION',
    'B501': 'WEAK_CRYPTO', 'B502': 'WEAK_CRYPTO',
    'B503': 'WEAK_CRYPTO', 'B504': 'WEAK_CRYPTO',
    'B505': 'WEAK_CRYPTO', 'B506': 'DESERIALIZATION',
    'B507': 'WEAK_CRYPTO', 'B508': 'WEAK_CRYPTO',
    'B509': 'WEAK_CRYPTO', 'B601': 'WEAK_CRYPTO',
    'B602': 'COMMAND_INJECTION', 'B603': 'COMMAND_INJECTION',
    'B604': 'COMMAND_INJECTION', 'B605': 'COMMAND_INJECTION',
    'B606': 'COMMAND_INJECTION', 'B607': 'COMMAND_INJECTION',
    'B608': 'SQL_INJECTION', 'B609': 'COMMAND_INJECTION',
    'B610': 'SQL_INJECTION', 'B611': 'SQL_INJECTION',
    'B612': 'INSECURE_CONFIG', 'B613': 'GENERIC',
    'B614': 'DESERIALIZATION', 'B615': 'INSECURE_CONFIG',
    'B701': 'XSS', 'B702': 'XSS', 'B703': 'XSS', 'B704': 'XSS',
}


def _rule_for_bandit(type_str: str) -> Optional[str]:
    import re
    m = re.match(r'Bandit:\s*(B\d+)', (type_str or '').strip())
    if not m:
        return None
    return _BANDIT_MAP.get(m.group(1))


def resolve(category: str, type_str: str, file_path: str = "") -> dict:
    """Pick the best matching rule for a finding."""
    rules = load_rules()

    # External Bandit ids map directly onto a rule.
    forced = _rule_for_bandit(type_str)
    if forced and forced in rules:
        best_name, best_rule = forced, rules[forced]
    else:
        best_name, best_rule, best_score = "GENERIC", _FALLBACK["GENERIC"], 0
        for name, rule in rules.items():
            if not isinstance(rule, dict):
                continue
            s = _score(rule, category, type_str)
            if s > best_score:
                best_name, best_rule, best_score = name, rule, s

    lang = _lang_for(file_path)
    code_map = best_rule.get('code', {}) or {}
    code = code_map.get(lang) or code_map.get('default') or ""
    return {
        "id": best_name,
        "title": best_rule.get("title", "Security Finding"),
        "remediation": best_rule.get("remediation", _FALLBACK["GENERIC"]["remediation"]),
        "code": code,
        "language": lang,
    }


def guidance(category: str, type_str: str, file_path: str = "") -> Tuple[str, str]:
    """Return ``(remediation_text, safe_code_template)``."""
    rule = resolve(category, type_str, file_path)
    return rule["remediation"], rule["code"]


def attach(findings: List) -> List:
    """Set ``remediation`` / ``fix_title`` / ``fix_code`` on every finding."""
    for f in findings:
        try:
            if getattr(f, 'remediation', ''):
                continue
            text, code = guidance(getattr(f, 'category', ''),
                                  getattr(f, 'type', ''),
                                  getattr(f, 'file', ''))
            rule = resolve(getattr(f, 'category', ''), getattr(f, 'type', ''),
                           getattr(f, 'file', ''))
            f.remediation = text
            f.fix_title = rule['title']
            f.fix_code = code
        except Exception:
            continue
    return findings

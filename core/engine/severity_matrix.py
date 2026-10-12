"""Context-Aware Severity Matrix + Absolute Fatal Sinks (KernelSpy 1.5.0).

Feature 1 - Context-Aware Severity Matrix
    Severity used to be a fixed property of the rule name: ``Process.Start``
    was always MEDIUM, no matter how the call was written.  The matrix
    re-scores command execution findings from the *source context* instead::

        shell + untrusted input concatenated -> CRITICAL / OS Command Injection
        shell + literal arguments            -> MEDIUM
        normal program + dynamic arguments   -> MEDIUM
        normal program + literal arguments   -> LOW

    "Shell" covers cmd.exe / PowerShell / bash / sh / wscript, ``system()`` /
    ``popen()`` and ``shell=True``.  "Untrusted" covers string concatenation,
    interpolation, printf/format placeholders and anything that is not a
    plain literal (a variable argument already makes the launch dynamic).

Feature 2 - Absolute Fatal Sinks
    Some sinks are non-negotiable: if a tainted value reaches ``eval``,
    ``exec``, ``system`` ... the outcome is remote code execution, so the
    severity is forced to CRITICAL and every other scoring rule is skipped.
"""

import os
import re
from typing import Dict, List, Optional, Set

from ..models import Finding
from .filters import SourceLoader

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _worse(a: str, b: str) -> str:
    return a if _SEV_RANK.get(str(a).upper(), 4) <= _SEV_RANK.get(str(b).upper(), 4) else b


# ───────────────────────────────────────────────────────────────────
#  Shell / dynamic-argument detection
# ───────────────────────────────────────────────────────────────────
_SHELL_RE = re.compile(
    r"(?i)"
    r"\bcmd(?:\.exe)?\b|\bpowershell(?:\.exe)?\b|\bpwsh\b"
    r"|\bbash\b|\bzsh\b|\bsh\b|/bin/(?:ba|z|k)?sh"
    r"|shell\s*=\s*true|shell_exec|\bcmd\s*/c"
    r"|wscript\b|\bcscript\b"
    r"|\bsystem\s*\(|\bpopen\s*\(|_popen\s*\(|os\.system"
)

# concat / interpolation / formatting markers - checked on the RAW argument
# zone, before literals are stripped (a concat of two literals stays static).
_INTERP_RE = re.compile(
    r"(?i)"
    r"\+\s*[\"'`\[\($A-Za-z_]"          #  + "text"   + var   + [x]
    r"|[A-Za-z_$)\]]\s*\+"               #  var +      ) +
    r"|\$\{[^}]+\}"                       #  ${var}   JS template
    r"|\{[A-Za-z_][A-Za-z0-9_.]*\}"       #  {var}    f-string / C# $"" 
    r"|%\s*[sdfixXu]|%\(\w+\)s"           #  printf %s / %(name)s
    r"|\.format\s*\(|string\.format\s*\("
    r"|\bsprintf\s*\(|\bstrformat\b|concat\s*\("
    r"|f[\"']"                             #  f"..."    python f-string
    r"|\+\$[\"']"                          #  +"..."    C# $"..."
)

_STRIPPED = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`")
_KWARG_BOOL = re.compile(r"\b[\w.]+\s*=\s*(?:True|False|\d+(?:\.\d+)?)\b", re.I)
_KWARG_EMPTY = re.compile(r"\b[\w.]+\s*=\s*(?=[,)\]}]|$)")


def _is_dynamic(zone: str) -> bool:
    """True when the argument zone is not a bag of plain literals."""
    if zone is None:
        return True                       # unknown shape -> assume dynamic
    if _INTERP_RE.search(zone):
        return True
    z = _STRIPPED.sub("", zone)
    z = _KWARG_BOOL.sub("", z)
    z = _KWARG_EMPTY.sub("", z)
    return bool(re.search(r"[A-Za-z_$]", z))


def _arg_zone(statement: str) -> Optional[str]:
    i = statement.find("(")
    if i < 0:
        return None
    return statement[i + 1:]


# ───────────────────────────────────────────────────────────────────
#  Which findings the matrix is allowed to re-score
# ───────────────────────────────────────────────────────────────────
_COMMAND_RE = re.compile(
    r"(?i)"
    r"process\.start|processbuilder|process\.run|processstartinfo"
    r"|runtime\s*\w*\.?\s*exec|runtime\.getruntime"
    r"|os\.system|os\.popen|subprocess|shell\s*=\s*true"
    r"|exec\.command|exec\.cmd|command::new|execl|execv"
    r"|child_process|execsync|execfile|\bspawn\b|\bexeca\b"
    r"|\bsystem\s*\(|\bpopen\s*\(|_popen\s*\(|shell_exec|proc_open"
    r"|wscript\b|cscript\b|cmd\.exe|powershell"
    r"|\bprocess\s*\(\s*name\s*:|shell=True"
)


def _is_command_finding(f: Finding) -> bool:
    text = f"{getattr(f, 'type', '')} {getattr(f, 'snippet', '')}"
    return bool(_COMMAND_RE.search(text))


def _ext_of(relpath: str) -> str:
    return os.path.splitext(str(relpath or ""))[1].lower()


def evaluate_statement(statement: str) -> Optional[dict]:
    """Return the context verdict for one call site (None = not applicable)."""
    if not statement:
        return None
    shell = bool(_SHELL_RE.search(statement))
    dynamic = _is_dynamic(_arg_zone(statement))

    if shell and dynamic:
        return {
            "severity": "CRITICAL",
            "type": "OS Command Injection",
            "category": "INJECTION",
            "description": (
                "Direct untrusted input injected into command line shell "
                "execution - operating system command injection."
            ),
        }
    if shell:
        return {
            "severity": "MEDIUM",
            "description": (
                "Shell is invoked with fixed arguments - keep the shell out "
                "of the call (argument vector) wherever possible."
            ),
        }
    if dynamic:
        return {
            "severity": "MEDIUM",
            "description": (
                "Process started with external/dynamic arguments - validate "
                "and allow-list every value before execution."
            ),
        }
    return {
        "severity": "LOW",
        "description": (
            "Static program launch with literal arguments - no untrusted "
            "data flows into the command line."
        ),
    }


def apply_severity_matrix(findings: List[Finding],
                          loader: Optional[SourceLoader] = None) -> List[Finding]:
    """Feature 1: re-score command execution findings from their context."""
    for f in findings:
        if not _is_command_finding(f):
            continue
        statement = ""
        if loader is not None and int(getattr(f, "line", 0) or 0) > 0:
            statement = loader.statement(f.file, f.line)
        statement = statement or str(f.snippet or "")
        verdict = evaluate_statement(statement)
        if not verdict:
            continue

        old_sev = str(getattr(f, "severity", "INFO")).upper()
        is_taint = "taint" in str(getattr(f, "analyzer", "")).lower()
        # Never weaken an already CRITICAL record, and never weaken a proven
        # taint flow: the matrix may escalate them but not de-escalate.
        if old_sev == "CRITICAL" or is_taint:
            new_sev = _worse(old_sev, verdict["severity"])
        else:
            new_sev = verdict["severity"]
        f.severity = new_sev

        if verdict.get("type") and new_sev == "CRITICAL" and not is_taint:
            f.type = verdict["type"]
        if verdict.get("category"):
            f.category = verdict["category"]
        note = verdict.get("description", "")
        if note and note not in str(f.description or ""):
            f.description = (f"{f.description} {note}").strip()
    return findings


# ───────────────────────────────────────────────────────────────────
#  Feature 2 - absolute fatal sinks
# ───────────────────────────────────────────────────────────────────
FATAL_SINKS: Dict[str, Set[str]] = {
    "ruby": {"eval", "instance_eval", "class_eval", "module_eval",
             "instance_exec", "exec", "system"},
    "python": {"eval", "exec", "os.system", "system", "__import__"},
    "php": {"eval", "exec", "system", "passthru", "shell_exec",
            "popen", "proc_open", "assert", "create_function", "pcntl_exec"},
    "javascript": {"eval", "function", "settimeout", "setinterval",
                   "setimmediate", "exec"},
}

# extension -> language key of FATAL_SINKS
_FATAL_LANG: Dict[str, str] = {
    ".py": "python",
    ".rb": "ruby", ".rbw": "ruby",
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php",
    ".php5": "php", ".inc": "php",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
}

# markers that mean "this value came from the user"
_USER_MARKERS = (
    "user", "input", "params", "req.", "request", "argv", "query",
    "body", "form", "cookie", "stdin", "gets", "cgi", "_get", "_post",
    "_request", "cmdline", "environment", "getenv", "readline",
)


def _fatal_sink_name(finding: Finding, ext: str) -> Optional[str]:
    lang = _FATAL_LANG.get(ext)
    if not lang:
        return None
    names = FATAL_SINKS.get(lang)
    if not names:
        return None
    text = str(getattr(finding, "type", "")).lower()
    if "->" in text:                       # taint record: "x -> eval"
        text = text.split("->", 1)[1]
    for name in names:
        if re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", text):
            return name
    return None


def _looks_tainted(finding: Finding) -> bool:
    if "taint" in str(getattr(finding, "analyzer", "")).lower():
        return True
    blob = " ".join((
        str(getattr(finding, "type", "")),
        str(getattr(finding, "description", "")),
        str(getattr(finding, "snippet", "")),
    )).lower()
    return any(marker in blob for marker in _USER_MARKERS)


def apply_fatal_sink_policy(findings: List[Finding],
                            loader: Optional[SourceLoader] = None) -> List[Finding]:
    """Feature 2: tainted data reaching a fatal sink is always CRITICAL."""
    for f in findings:
        ext = _ext_of(getattr(f, "file", ""))
        sink = _fatal_sink_name(f, ext)
        if not sink or not _looks_tainted(f):
            continue
        if str(getattr(f, "severity", "")).upper() == "CRITICAL":
            continue
        f.severity = "CRITICAL"
        f.category = "INJECTION"
        note = (f"Absolute fatal sink: tainted data reaches '{sink}()' - "
                "remote code execution.")
        if note not in str(f.description or ""):
            f.description = (f"{f.description} {note}").strip()
    return findings

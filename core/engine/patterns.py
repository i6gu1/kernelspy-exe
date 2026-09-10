import bisect
import re
from functools import lru_cache
from typing import List, Optional, Union

from ..models import Finding

# Quoted literal spans used by credential-value validation.
_QUOTED_SPAN = re.compile(r"'([^'\n]{2,})'|\"([^\"\n]{2,})\"|`([^`\n]{2,})`")


def first_quoted_value(match_text: str) -> Optional[str]:
    """Return the first quoted literal embedded in *match_text*."""
    for m in _QUOTED_SPAN.finditer(match_text):
        return next(g for g in m.groups() if g is not None)
    return None


def line_offsets(text: str) -> List[int]:
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            offsets.append(i + 1)
    return offsets


@lru_cache(maxsize=256)
def _extract_needle(pattern: str) -> str:
    """Safely extract a literal substring that MUST appear in every match.

    Safety rules (regression-hardened):
      * Only the literal prefix before any regex group/class/quantifier is
        used, so the needle is a true substring of every match.
      * An escape that does not produce a known literal char (\\$, \\+, \\[,
        backrefs, anchors, class shorthands ...) STOPS extraction. Skipping
        past it would bridge a gap that real matches contain, disabling the
        rule entirely (e.g. access_token\\$production once yielded the
        impossible needle 'access_tokenproduction').
      * If a quantifier (? * + {) applies to the final literal char, that
        char is dropped (pickle\\.loads? -> 'pickle.load'), keeping the needle
        a valid substring of both alternates.
    Returns '' (no filtering) when no safe prefix exists.
    """
    i = 0
    n = len(pattern)
    if pattern.startswith('(?i)'):
        i = 4
    out = []
    while i < n:
        c = pattern[i]
        if c == '\\':
            if i + 1 >= n:
                break
            nxt = pattern[i + 1]
            if nxt in 'wWbBsSdDCAZz':
                break                      # class shorthand / boundary / anchor
            if nxt.isalpha():
                out.append(nxt)            # escaped literal letter
                i += 2
                continue
            if nxt in '().,-/':
                out.append(nxt)            # escaped literal punctuation
                i += 2
                continue
            break                          # \$ \+ \[ \\ digits ... : stop, never skip
        if c in '([{*+?|^$]' or c == '.':
            # Quantifier riding on the last literal char invalidates it.
            if c in '?*+{' and out:
                out.pop()
            break
        out.append(c)
        i += 1

    s = ''.join(out)
    return s if len(s) >= 3 else ''


class ContentContext:
    """Precomputed offsets and line cache for a search text."""

    __slots__ = ('text', 'offsets', 'lines', 'lower')

    def __init__(self, text: str):
        self.text = text
        self.offsets = line_offsets(text)
        self.lines = text.split('\n')
        self.lower = text.lower()


class CompiledRule:
    __slots__ = ('name', 'regex', 'severity', 'category', 'description',
                 'analyzer', 'needle', 'validator')

    def __init__(self, name: str, regex: re.Pattern, severity: str,
                 category: str, description: str, analyzer: str = 'pattern',
                 validator=None):
        self.name = name
        self.regex = regex
        self.severity = severity
        self.category = category
        self.description = description
        self.analyzer = analyzer
        self.validator = validator
        self.needle = _extract_needle(regex.pattern)
        # Keep a case-insensitive needle for the lowercase pre-filter.
        self.needle = self.needle.lower()

    @classmethod
    def from_pattern(cls, name, pattern, severity, category, description,
                     analyzer: str = 'pattern',
                     flags: int = re.IGNORECASE | re.MULTILINE,
                     validator=None):
        try:
            return cls(name, re.compile(pattern, flags), severity, category,
                       description, analyzer, validator)
        except re.error:
            return None


def scan_content_for_rules(
    filepath: str,
    rules: List[CompiledRule],
    ctx: ContentContext,
) -> List[Finding]:
    """Run precompiled rules against a cached context using finditer."""
    if not rules or not ctx.text:
        return []

    findings: List[Finding] = []
    offsets = ctx.offsets
    cache_lines = ctx.lines
    lower = ctx.lower

    for rule in rules:
        if rule.needle and rule.needle not in lower:
            continue
        for m in rule.regex.finditer(ctx.text):
            if rule.validator is not None and not rule.validator(m):
                continue
            ln = bisect.bisect_right(offsets, m.start())
            snippet = cache_lines[ln - 1].strip()[:120] if 0 < ln <= len(cache_lines) else ''
            findings.append(Finding(
                file=filepath,
                line=ln,
                type=rule.name,
                severity=rule.severity,
                snippet=snippet,
                description=rule.description,
                category=rule.category,
                analyzer=rule.analyzer,
            ))

    return findings


def compile_language_rules(rules, analyzer: str = 'pattern') -> List[CompiledRule]:
    compiled = []
    for rule in rules:
        cr = CompiledRule.from_pattern(
            getattr(rule, 'name', rule[0]),
            getattr(rule, 'pattern', rule[1]),
            getattr(rule, 'severity', rule[2]),
            getattr(rule, 'category', rule[3]),
            getattr(rule, 'description', rule[4]),
            analyzer,
        )
        if cr:
            compiled.append(cr)
    return compiled
"""
SARIF (Static Analysis Results Interchange Format) reporter for KernelSpy Scanner.
Standard JSON format for unified security report output.
Compatible with GitHub, Microsoft, and other SARIF consumers.
"""
import json
from typing import List
from datetime import datetime
from ..models import Finding


def _severity_to_level(severity: str) -> str:
    """Map KernelSpy severity to SARIF level."""
    return {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'none',
    }.get(severity.upper(), 'warning')


def _category_to_rule_id(category: str, analyzer: str) -> str:
    """Generate a SARIF rule ID from category and analyzer."""
    prefix = analyzer.upper()[:4] if analyzer else "KS"
    return f"{prefix}-{category.upper()}"


def export_sarif(path: str, results: List[Finding], folder: str = "") -> bool:
    """Export findings in SARIF 2.1.0 format.

    SARIF is a JSON-based standard format supported by GitHub, Microsoft,
    and other tools for representing static analysis results.

    Args:
        path: Output file path for the SARIF file.
        results: List of Finding objects to include.
        folder: Root folder being scanned (for URI base).

    Returns:
        True on success, False on failure.
    """
    try:
        # Build rules dictionary (deduplicated)
        rules = {}
        for r in results:
            rule_id = _category_to_rule_id(r.category, r.analyzer)
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": r.type[:80],
                    "shortDescription": {
                        "text": r.type[:120]
                    },
                    "fullDescription": {
                        "text": r.description[:500]
                    },
                    "defaultConfiguration": {
                        "level": _severity_to_level(r.severity)
                    },
                    "properties": {
                        "category": r.category,
                        "analyzer": r.analyzer,
                        "severity": r.severity,
                    }
                }

        # Build results array
        sarif_results = []
        for r in results:
            rule_id = _category_to_rule_id(r.category, r.analyzer)

            sarif_result = {
                "ruleId": rule_id,
                "level": _severity_to_level(r.severity),
                "message": {
                    "text": r.description[:1000]
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": max(1, r.line),
                                "startColumn": 1,
                            }
                        }
                    }
                ],
                "fingerprints": {
                    "kernelspy/primaryLocationLineHash": f"{r.file}:{r.line}:{r.type}"
                },
                "properties": {
                    "severity": r.severity,
                    "category": r.category,
                    "analyzer": r.analyzer,
                    "snippet": r.snippet[:200] if r.snippet else "",
                }
            }
            sarif_results.append(sarif_result)

        # Build complete SARIF document
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "KernelSpy Scanner",
                            "version": "1.1.0",
                            "informationUri": "https://github.com/kernelspy",
                            "rules": list(rules.values()),
                        }
                    },
                    "artifacts": [
                        {
                            "location": {
                                "uri": ".",
                                "uriBaseId": "%SRCROOT%"
                            }
                        }
                    ],
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                            "properties": {
                                "scanStartTime": datetime.now().isoformat(),
                                "totalFindings": len(results),
                            }
                        }
                    ]
                }
            ]
        }

        # Add summary statistics
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in results:
            counts[r.severity.upper()] = counts.get(r.severity.upper(), 0) + 1

        sarif_doc["runs"][0]["tool"]["driver"]["properties"] = {
            "totalFindings": len(results),
            "criticalCount": counts["CRITICAL"],
            "highCount": counts["HIGH"],
            "mediumCount": counts["MEDIUM"],
            "lowCount": counts["LOW"],
            "infoCount": counts["INFO"],
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sarif_doc, f, indent=2, ensure_ascii=False)

        return True
    except Exception:
        return False

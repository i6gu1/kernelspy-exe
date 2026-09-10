import json
from typing import List
from datetime import datetime
from ..models import Finding


def export_json(path: str, results: List[Finding]) -> bool:
    try:
        data = {
            "tool": "KernelSpy Scanner",
            "version": "2.0.0",
            "generated": datetime.now().isoformat(),
            "summary": {
                "total": len(results),
                "critical": sum(1 for r in results if r.severity == "CRITICAL"),
                "high": sum(1 for r in results if r.severity == "HIGH"),
                "medium": sum(1 for r in results if r.severity == "MEDIUM"),
                "low": sum(1 for r in results if r.severity == "LOW"),
            },
            "findings": [r.to_dict() for r in results],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

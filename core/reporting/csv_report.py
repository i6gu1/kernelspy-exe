import csv
from typing import List
from ..models import Finding


def export_csv(path: str, results: List[Finding]) -> bool:
    try:
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f)
            w.writerow(['File', 'Line', 'Threat', 'Category', 'Severity',
                         'Description', 'Snippet', 'Analyzer'])
            for r in results:
                w.writerow([r.file, r.line, r.type, r.category, r.severity,
                             r.description, r.snippet, r.analyzer])
        return True
    except Exception:
        return False

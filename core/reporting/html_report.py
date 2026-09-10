import html
from typing import List
from datetime import datetime
from ..models import Finding


def export_html(path: str, results: List[Finding]) -> bool:
    try:
        rows = ''
        for r in results:
            cls = r.severity.lower()
            analyzer_badge = (
                f'<span style="background:#222;padding:2px 6px;border-radius:3px;'
                f'font-size:11px;">{r.analyzer}</span>'
            )
            cat_badge = (
                f'<span style="background:#1a1a2e;padding:2px 6px;border-radius:3px;'
                f'font-size:11px;color:#c9a84c;">{r.category}</span>'
            )
            rows += f'''<tr>
                <td>{html.escape(r.file)}</td>
                <td style="text-align:center;">{r.line}</td>
                <td>{html.escape(r.type)}</td>
                <td>{cat_badge}</td>
                <td class="{cls}" style="text-align:center;font-weight:bold;">{r.severity}</td>
                <td>{html.escape(r.description)}</td>
                <td><code style="font-size:11px;background:#111;padding:2px 4px;">{html.escape(r.snippet[:80])}</code></td>
                <td>{analyzer_badge}</td>
            </tr>\n'''

        total = len(results)
        critical = sum(1 for r in results if r.severity == 'CRITICAL')
        high = sum(1 for r in results if r.severity == 'HIGH')
        medium = sum(1 for r in results if r.severity == 'MEDIUM')
        low = sum(1 for r in results if r.severity == 'LOW')

        content = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>KernelSpy Security Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#0a0a0a; color:#e0e0e0; font-family:'Segoe UI',system-ui,sans-serif; padding:30px; }}
.header {{ border-bottom:2px solid #c9a84c; padding-bottom:20px; margin-bottom:25px; }}
h1 {{ color:#c9a84c; font-size:24px; }}
.stats {{ display:flex; gap:15px; margin:20px 0; }}
.stat {{ padding:12px 20px; border-radius:8px; background:#141414; border-left:4px solid; }}
.stat.critical {{ border-color:#ff1744; }}
.stat.high {{ border-color:#ff9100; }}
.stat.medium {{ border-color:#e6c200; }}
.stat.low {{ border-color:#00e676; }}
.stat .num {{ font-size:28px; font-weight:bold; }}
.stat .lbl {{ font-size:12px; color:#888; }}
table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
th {{ background:#111; color:#c9a84c; padding:12px 10px; text-align:left; border-bottom:2px solid #333; font-size:13px; }}
td {{ padding:10px; border-bottom:1px solid #1a1a1a; font-size:13px; }}
tr:nth-child(even) {{ background:#0d0d0d; }}
tr:hover {{ background:#1a1a1a; }}
.critical {{ color:#ff1744; }}
.high {{ color:#ff9100; }}
.medium {{ color:#e6c200; }}
.low {{ color:#00e676; }}
.footer {{ color:#555; margin-top:30px; font-size:12px; border-top:1px solid #222; padding-top:15px; }}
</style></head><body>
<div class="header">
<h1>KernelSpy Scanner - Security Report</h1>
<p style="color:#888;margin-top:5px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="stats">
<div class="stat critical"><div class="num">{critical}</div><div class="lbl">CRITICAL</div></div>
<div class="stat high"><div class="num">{high}</div><div class="lbl">HIGH</div></div>
<div class="stat medium"><div class="num">{medium}</div><div class="lbl">MEDIUM</div></div>
<div class="stat low"><div class="num">{low}</div><div class="lbl">LOW</div></div>
<div class="stat" style="border-color:#c9a84c;"><div class="num">{total}</div><div class="lbl">TOTAL</div></div>
</div>
<table><tr>
<th>File</th><th>Line</th><th>Threat</th><th>Category</th><th>Severity</th><th>Description</th><th>Code</th><th>Analyzer</th>
</tr>
{rows}</table>
<p class="footer">Programmed by The L house</p>
</body></html>'''

        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception:
        return False

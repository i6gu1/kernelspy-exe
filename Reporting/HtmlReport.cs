using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using KernelSpyScanner.Models;

namespace KernelSpyScanner.Reporting
{
    public static class HtmlReport
    {
        public static bool Export(string path, IEnumerable<Finding> findings)
        {
            try
            {
                var list = new List<Finding>(findings);
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                var sb = new StringBuilder();
                sb.AppendLine("<!DOCTYPE html>");
                sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"/>");
                sb.AppendLine("<title>KernelSpy Scan Report</title>");
                sb.AppendLine("<style>");
                sb.AppendLine("body{font-family:Segoe UI,Arial,sans-serif;background:#000;color:#f1f5f9;margin:24px;}");
                sb.AppendLine("h1{color:#0ea5e9;} table{width:100%;border-collapse:collapse;margin-top:16px;}");
                sb.AppendLine("th,td{border:1px solid #2a2a2a;padding:8px;font-size:12px;vertical-align:top;}");
                sb.AppendLine("th{background:#121212;color:#0ea5e9;text-align:left;}");
                sb.AppendLine("tr:nth-child(even){background:#0a0a0a;}");
                sb.AppendLine(".CRITICAL{color:#f43f5e;font-weight:bold;} .HIGH{color:#f97316;font-weight:bold;}");
                sb.AppendLine(".MEDIUM{color:#eab308;} .LOW{color:#94a3b8;} .INFO{color:#22c55e;}");
                sb.AppendLine("code{background:#0a0a12;padding:2px 4px;border-radius:4px;}");
                sb.AppendLine("</style></head><body>");
                sb.AppendLine($"<h1>KernelSpy Scanner Report</h1>");
                sb.AppendLine($"<p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} &nbsp;|&nbsp; Total findings: {list.Count}</p>");
                sb.AppendLine("<table><thead><tr>");
                sb.AppendLine("<th>File</th><th>Line</th><th>Type</th><th>Category</th><th>Severity</th><th>Description</th><th>Snippet</th><th>Analyzer</th>");
                sb.AppendLine("</tr></thead><tbody>");

                foreach (var f in list)
                {
                    sb.AppendLine("<tr>");
                    sb.AppendLine($"<td>{Enc(f.File)}</td>");
                    sb.AppendLine($"<td style=\"text-align:center;\">{f.Line}</td>");
                    sb.AppendLine($"<td>{Enc(f.Type)}</td>");
                    sb.AppendLine($"<td>{Enc(f.Category)}</td>");
                    sb.AppendLine($"<td class=\"{f.Severity}\">{f.Severity}</td>");
                    sb.AppendLine($"<td>{Enc(f.Description)}</td>");
                    sb.AppendLine($"<td><code>{Enc(f.Snippet)}</code></td>");
                    sb.AppendLine($"<td>{Enc(f.Analyzer)}</td>");
                    sb.AppendLine("</tr>");
                }
                sb.AppendLine("</tbody></table>");
                sb.AppendLine("<p style=\"margin-top:24px;color:#94a3b8;font-size:11px;\">Programmed by The L house</p>");
                sb.AppendLine("</body></html>");

                File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string Enc(string s) => HtmlEncoder.Default.Encode(s ?? string.Empty);
    }
}

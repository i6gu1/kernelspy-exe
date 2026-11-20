using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using KernelSpyScanner.Models;
using KernelSpyScanner.Integrations;

namespace KernelSpyScanner.Engine
{
    public sealed class ScanProgress
    {
        public int Percent { get; set; }
        public string Message { get; set; } = string.Empty;
        public int FilesDone { get; set; }
        public int TotalFiles { get; set; }
    }

    /// <summary>
    /// Core scanning engine. Runs the built-in rules and then merges the output
    /// of the two external analysers (ESLint and Semgrep).
    /// </summary>
    public sealed class Scanner
    {
        private static readonly string[] SeverityOrder = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

        private const long MaxFileBytes = 10 * 1024 * 1024; // 10 MB per file
        private const int MaxFiles = 100_000;

        private static readonly Regex TaintedAssignment = new(
            @"(?i)\b(?:const\s+|let\s+|var\s+|string\s+)?(?<var>[A-Za-z_$][\w$]*)\s*(?:=|:=)\s*(?:f?['""`][^'""`\n]*(?:\+|\{)|\$\{|[A-Za-z_$][\w$.]*\s*\([^)\n]*(?:user|input|param|request|form|query)[^)\n]*\))",
            RegexOptions.Compiled);

        private static readonly Regex QuerySink = new(
            @"(?i)\b(?:execute|executemany|query|raw)\s*\(\s*(?<arg>[A-Za-z_$][\w$]*)\s*[,)]",
            RegexOptions.Compiled);

        private static readonly Regex ParameterPlaceholder = new(
            @"['""][^'""\n]*\?[^'""\n]*['""]", RegexOptions.Compiled);

        public async Task<List<Finding>> ScanAsync(string folder, IProgress<ScanProgress> progress, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                throw new DirectoryNotFoundException(folder);

            var root = Path.GetFullPath(folder);
            var files = SourceFiles.Enumerate(root).Take(MaxFiles).ToList();
            var findings = new List<Finding>();
            var externalLineCache = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

            int total = files.Count;
            int done = 0;

            progress?.Report(new ScanProgress { Percent = 0, Message = $"Discovered {total} scannable files", TotalFiles = total });

            // 1. Built-in rules.
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                done++;

                try
                {
                    var info = new FileInfo(file);
                    if (!info.Exists || info.Length == 0 || info.Length > MaxFileBytes) continue;

                    var text = await File.ReadAllTextAsync(file, Encoding.UTF8, ct).ConfigureAwait(false);
                    var lines = SplitLines(text, out var lineStarts);
                    var kind = SourceFiles.GetKind(file);
                    var masked = kind == SourceFileKind.Code ? SourceFiles.MaskComments(text, file) : text;

                    var hasDirectSqlFinding = false;

                    foreach (var rule in Patterns.Rules)
                    {
                        if (!RuleApplies(rule, kind)) continue;

                        var searchText = rule.Scope == RuleScope.Config ? text : masked;
                        foreach (Match m in rule.Regex.Matches(searchText))
                        {
                            int lineNo = LineFromOffset(lineStarts, m.Index);
                            string snippet = lineNo >= 1 && lineNo <= lines.Length
                                ? lines[lineNo - 1].Trim()
                                : m.Value.Trim();

                            // Inline suppression on the same or previous line.
                            string previous = lineNo > 1 && lineNo - 2 < lines.Length ? lines[lineNo - 2] : string.Empty;
                            if (snippet.Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase) ||
                                previous.Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase))
                                continue;

                            if (IsSuppressed(rule, snippet))
                                continue;

                            findings.Add(new Finding(
                                file, lineNo, rule.Name, rule.Category, rule.Severity,
                                $"{rule.Name} detected by built-in engine.", snippet, "pattern"));

                            if (rule.Name.StartsWith("SQL Injection", StringComparison.OrdinalIgnoreCase))
                                hasDirectSqlFinding = true;
                        }
                    }

                    // Simple intra-file dataflow: a query assembled from a
                    // concatenation or f-string and later passed to execute().
                    if (kind == SourceFileKind.Code && !hasDirectSqlFinding)
                        AddTaintedSinkFindings(file, lines, findings);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    // Never crash the whole scan because of a single file.
                    progress?.Report(new ScanProgress
                    {
                        Percent = (int)((done / (double)Math.Max(1, total)) * 80),
                        Message = $"Skipped {Path.GetFileName(file)}: {ex.Message}",
                        FilesDone = done,
                        TotalFiles = total
                    });
                }

                int pct = total == 0 ? 100 : (int)((done / (double)total) * 80);
                progress?.Report(new ScanProgress { Percent = pct, Message = $"Scanned {Path.GetFileName(file)}", FilesDone = done, TotalFiles = total });
            }

            // 2. External tool: ESLint.
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgress { Percent = 82, Message = "Running ESLint analysis...", FilesDone = done, TotalFiles = total });
            try
            {
                AddExternalFindings(findings, await EslintRunner.RunAsync(root, ct).ConfigureAwait(false), root, externalLineCache);
            }
            catch (Exception ex)
            {
                progress?.Report(new ScanProgress { Percent = 85, Message = $"ESLint skipped: {ex.Message}", FilesDone = done, TotalFiles = total });
            }

            // 3. External tool: Semgrep.
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgress { Percent = 90, Message = "Running Semgrep analysis...", FilesDone = done, TotalFiles = total });
            try
            {
                AddExternalFindings(findings, await SemgrepRunner.RunAsync(root, ct).ConfigureAwait(false), root, externalLineCache);
            }
            catch (Exception ex)
            {
                progress?.Report(new ScanProgress { Percent = 93, Message = $"Semgrep skipped: {ex.Message}", FilesDone = done, TotalFiles = total });
            }

            // 4. Merge duplicates reported by different analysers.
            var merged = Deduplicate(findings, root);

            progress?.Report(new ScanProgress { Percent = 100, Message = $"Scan complete. {merged.Count} findings.", FilesDone = total, TotalFiles = total });
            return merged;
        }

        private static bool RuleApplies(PatternRule rule, SourceFileKind kind) => rule.Scope switch
        {
            RuleScope.Code => kind == SourceFileKind.Code,
            RuleScope.Config => kind == SourceFileKind.Config,
            _ => true
        };

        /// <summary>
        /// Lightweight sanitizer heuristics. They are deliberately narrow: a
        /// broad "contains ?" check used to hide real findings, while generic
        /// "contains encode" hid unsafe innerHTML assignments.
        /// </summary>
        private static bool IsSuppressed(PatternRule rule, string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            var lower = line.ToLowerInvariant();

            switch (rule.Category)
            {
                case "SECRET":
                case "CREDENTIALS":
                case "CLOUD":
                case "VCS":
                case "PAYMENT":
                case "CHAT":
                case "AI":
                case "EMAIL":
                case "PACKAGE":
                    if (lower.Contains("placeholder") || lower.Contains("your_") ||
                        lower.Contains("example.com") || lower.Contains("dummy") ||
                        lower.Contains("xxxx") || lower.Contains("<token>") ||
                        lower.Contains("changeme") || lower.Contains("fake_"))
                        return true;
                    break;

                case "INJECTION":
                    if (lower.Contains("prepare(") || lower.Contains("parameterized") ||
                        lower.Contains("setparameter") ||
                        ParameterPlaceholder.IsMatch(line))
                        return true;
                    break;

                case "XSS":
                    if (lower.Contains("sanitize(") || lower.Contains("escape(") ||
                        lower.Contains("encodeuricomponent(") || lower.Contains("textcontent"))
                        return true;
                    break;

                case "PATH_TRAVERSAL":
                    if (lower.Contains("getfullpath") || lower.Contains("normalize") ||
                        lower.Contains("canonical") || lower.Contains("realpath") ||
                        lower.Contains("safe_join"))
                        return true;
                    break;
            }
            return false;
        }

        private static void AddTaintedSinkFindings(string file, IReadOnlyList<string> lines, List<Finding> findings)
        {
            var tainted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (var i = 0; i < lines.Count; i++)
            {
                var line = lines[i];

                var assignment = TaintedAssignment.Match(line);
                if (assignment.Success)
                    tainted.Add(assignment.Groups["var"].Value);

                var sink = QuerySink.Match(line);
                if (!sink.Success || ParameterPlaceholder.IsMatch(line)) continue;

                var arg = sink.Groups["arg"].Value;
                if (!tainted.Contains(arg)) continue;

                // The direct concatenation rule already reported this issue at
                // the assignment line; do not report it a second time here.
                if (findings.Any(f => f.File == file && f.Type.StartsWith("SQL Injection", StringComparison.OrdinalIgnoreCase) && Math.Abs(f.Line - (i + 1)) <= 3))
                    continue;

                findings.Add(new Finding(
                    file, i + 1, "SQL Injection (tainted query variable)", "INJECTION", "HIGH",
                    "Query built from concatenated data is passed to a database call.",
                    line.Trim(), "pattern"));
            }
        }

        private static string[] SplitLines(string text, out List<int> lineStarts)
        {
            var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            lineStarts = new List<int>(lines.Length) { 0 };
            var offset = 0;
            foreach (var line in lines)
            {
                offset += line.Length;
                if (offset < text.Length)
                {
                    if (text[offset] == '\r' && offset + 1 < text.Length && text[offset + 1] == '\n') offset += 2;
                    else offset++;
                    lineStarts.Add(offset);
                }
            }
            return lines;
        }

        private static int LineFromOffset(List<int> lineStarts, int offset)
        {
            var index = lineStarts.BinarySearch(offset);
            if (index >= 0) return index + 1;
            var next = ~index;
            return Math.Max(1, next);
        }

        /// <summary>
        /// External analysers do not know about kernelspy-ignore. Apply the same
        /// inline suppression rule to their findings before merging.
        /// </summary>
        private static void AddExternalFindings(
            List<Finding> findings,
            IEnumerable<Finding> external,
            string root,
            Dictionary<string, string[]> lineCache)
        {
            foreach (var finding in external)
            {
                finding.File = NormalizePath(finding.File, root);
                if (IsInlineSuppressed(finding, lineCache)) continue;
                findings.Add(finding);
            }
        }

        private static bool IsInlineSuppressed(Finding finding, Dictionary<string, string[]> lineCache)
        {
            try
            {
                if (!lineCache.TryGetValue(finding.File, out var lines))
                {
                    if (!File.Exists(finding.File) || new FileInfo(finding.File).Length > MaxFileBytes)
                        return false;
                    lines = File.ReadAllLines(finding.File);
                    lineCache[finding.File] = lines;
                }

                if (finding.Line >= 1 && finding.Line <= lines.Length &&
                    lines[finding.Line - 1].Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase))
                    return true;

                if (finding.Line > 1 && finding.Line - 2 < lines.Length &&
                    lines[finding.Line - 2].Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch
            {
                // An unreadable file cannot be suppressed; keep the finding.
            }
            return false;
        }

        /// <summary>
        /// Normalises paths and collapses the same issue reported by different
        /// analysers into one finding while keeping every analyser name.
        /// </summary>
        private static List<Finding> Deduplicate(List<Finding> input, string root)
        {
            var map = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);

            foreach (var original in input)
            {
                var finding = Clone(original);
                finding.File = NormalizePath(finding.File, root);
                finding.Severity = NormalizeSeverity(finding.Severity);

                var canonical = CanonicalIssue(finding);
                var key = $"{finding.File}|{finding.Line}|{canonical}";
                if (!map.TryGetValue(key, out var existing))
                {
                    // A SQL query is often reported once where it is built and
                    // once where it is executed. Those are the same finding.
                    if (canonical == "SQL_INJECTION")
                    {
                        existing = map.Values.FirstOrDefault(v =>
                            CanonicalIssue(v) == canonical &&
                            string.Equals(v.File, finding.File, StringComparison.OrdinalIgnoreCase) &&
                            Math.Abs(v.Line - finding.Line) <= 2);
                    }

                    if (existing == null)
                    {
                        map[key] = finding;
                        continue;
                    }
                }

                Merge(existing, finding);
            }

            return map.Values
                .OrderByDescending(f => Rank(f.Severity))
                .ThenBy(f => f.File, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Line)
                .ToList();
        }

        private static void Merge(Finding existing, Finding finding)
        {
            if (!existing.Analyzer.Contains(finding.Analyzer, StringComparison.OrdinalIgnoreCase))
                existing.Analyzer = existing.Analyzer + ", " + finding.Analyzer;

            if (Rank(finding.Severity) > Rank(existing.Severity))
                existing.Severity = finding.Severity;

            if ((finding.Description?.Length ?? 0) > (existing.Description?.Length ?? 0))
                existing.Description = finding.Description ?? string.Empty;
            if ((finding.Snippet?.Length ?? 0) > (existing.Snippet?.Length ?? 0))
                existing.Snippet = finding.Snippet ?? string.Empty;
        }

        private static Finding Clone(Finding f) => new()
        {
            File = f.File,
            Line = f.Line,
            Type = f.Type,
            Category = f.Category,
            Severity = f.Severity,
            Description = f.Description,
            Snippet = f.Snippet,
            Analyzer = f.Analyzer
        };

        private static string NormalizePath(string file, string root)
        {
            if (string.IsNullOrWhiteSpace(file)) return root;

            var candidate = file;
            // semgrep-core reports the synthetic ppath (for example /src/app.py)
            // instead of a real filesystem path.
            if (candidate.StartsWith('/') || candidate.StartsWith('\\'))
            {
                var relative = candidate.TrimStart('/', '\\').Replace('/', Path.DirectorySeparatorChar);
                candidate = Path.Combine(root, relative);
            }

            try { return Path.GetFullPath(candidate); }
            catch { return candidate; }
        }

        private static string NormalizeSeverity(string? severity) => severity?.Trim().ToUpperInvariant() switch
        {
            "ERROR" => "HIGH",
            "WARNING" => "MEDIUM",
            "WARN" => "MEDIUM",
            "NOTE" => "LOW",
            "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "INFO" => severity.Trim().ToUpperInvariant(),
            _ => "MEDIUM"
        };

        /// <summary>
        /// Converts analyser-specific rule names into a greppable issue id so
        /// "Dangerous Eval", "ESLint: no-eval" and the Semgrep eval rule merge.
        /// </summary>
        private static string CanonicalIssue(Finding f)
        {
            var text = $"{f.Type} {f.Description} {f.Snippet}".ToLowerInvariant();

            if (text.Contains("eval") || text.Contains("new function") || text.Contains("no-implied-eval"))
                return "CODE_EXECUTION";
            if (text.Contains("xss") || text.Contains("innerhtml") || text.Contains("document.write") ||
                text.Contains("script-url") || text.Contains("dangerouslysetinnerhtml"))
                return "XSS";
            if (text.Contains("sql") || text.Contains("injection (dynamic query)"))
                return "SQL_INJECTION";
            if (text.Contains("command") || text.Contains("shell") || text.Contains("process.start") ||
                text.Contains("os.system"))
                return "COMMAND_INJECTION";
            if (text.Contains("traversal") || text.Contains("readalltext") || text.Contains("readfile"))
                return "PATH_TRAVERSAL";
            if (text.Contains("crypto") || text.Contains("md5") || text.Contains("sha1") ||
                text.Contains("sha-1") || text.Contains("des") || text.Contains("rc4"))
                return "WEAK_CRYPTO";
            if (text.Contains("deserial") || text.Contains("pickle") || text.Contains("binaryformatter") ||
                text.Contains("type handling"))
                return "DESERIALIZATION";
            if (text.Contains("xxe") || text.Contains("external entity") || text.Contains("dtdprocessing"))
                return "XXE";
            if (text.Contains("ssrf") || text.Contains("request forgery"))
                return "SSRF";
            if (text.Contains("redirect"))
                return "OPEN_REDIRECT";
            if (text.Contains("secret") || text.Contains("password") || text.Contains("token") ||
                text.Contains("credential") || text.Contains("access key") || text.Contains("api key"))
                return "SECRET";
            return f.Type.ToLowerInvariant();
        }

        private static int Rank(string? sev)
        {
            var index = Array.IndexOf(SeverityOrder, NormalizeSeverity(sev));
            return index < 0 ? 1 : index;
        }
    }
}

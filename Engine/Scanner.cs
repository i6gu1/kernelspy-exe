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
    /// Core scanning engine. Runs the built-in regex rules and then merges the
    /// output of the two external analysers (ESLint and Semgrep).
    /// </summary>
    public sealed class Scanner
    {
        private static readonly string[] SeverityOrder = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

        private static readonly HashSet<string> IgnoredDirectories = new(StringComparer.OrdinalIgnoreCase)
        {
            ".git", ".svn", "node_modules", "bin", "obj", "dist", "build", "__pycache__",
            ".venv", "venv", ".idea", ".vs", "packages", "vendor", "tools"
        };

        private const long MaxFileBytes = 2 * 1024 * 1024; // 2 MB per file

        public async Task<List<Finding>> ScanAsync(string folder, IProgress<ScanProgress> progress, CancellationToken ct)
        {
            var findings = new List<Finding>();

            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                throw new DirectoryNotFoundException(folder);

            var files = EnumerateSourceFiles(folder)
                .Take(20000) // hard safety limit for very large trees
                .ToList();

            int total = files.Count;
            int done = 0;

            progress?.Report(new ScanProgress { Percent = 0, Message = $"Discovered {total} scannable files", TotalFiles = total });

            // 1. Built-in regex engine
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(file);
                    if (!info.Exists || info.Length == 0 || info.Length > MaxFileBytes)
                    {
                        done++;
                        continue;
                    }

                    var text = await File.ReadAllTextAsync(file, Encoding.UTF8, ct).ConfigureAwait(false);
                    var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                    foreach (var rule in Patterns.Rules)
                    {
                        foreach (Match m in rule.Regex.Matches(text))
                        {
                            int lineNo = 1;
                            for (int i = 0; i < m.Index && i < text.Length; i++)
                                if (text[i] == '\n') lineNo++;

                            string snippet = lineNo >= 1 && lineNo <= lines.Length
                                ? lines[lineNo - 1].Trim()
                                : m.Value.Trim();

                            // Inline suppression: // kernelspy-ignore  or  # kernelspy-ignore
                            string previous = lineNo > 1 && lineNo - 2 < lines.Length ? lines[lineNo - 2] : string.Empty;
                            if (snippet.Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase) ||
                                previous.Contains("kernelspy-ignore", StringComparison.OrdinalIgnoreCase))
                                continue;

                            // Sanitizer / placeholder filters (mirrors filters.py + sanitizers.py)
                            if (IsSuppressed(rule, snippet))
                                continue;

                            findings.Add(new Finding(
                                file, lineNo, rule.Name, rule.Category, rule.Severity,
                                $"{rule.Name} detected by built-in engine.", snippet, "pattern"));
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Never crash the whole scan because of a single file.
                    progress?.Report(new ScanProgress { Percent = (int)((done / (double)Math.Max(1, total)) * 100), Message = $"Skipped {file}: {ex.Message}", FilesDone = done, TotalFiles = total });
                }

                done++;
                int pct = total == 0 ? 100 : (int)((done / (double)total) * 80); // reserve 20% for tools
                progress?.Report(new ScanProgress { Percent = pct, Message = $"Scanned {Path.GetFileName(file)}", FilesDone = done, TotalFiles = total });
            }

            // 2. External tool: ESLint
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgress { Percent = 82, Message = "Running ESLint analysis...", FilesDone = done, TotalFiles = total });
            try
            {
                var eslintFindings = await EslintRunner.RunAsync(folder, ct).ConfigureAwait(false);
                findings.AddRange(eslintFindings);
            }
            catch (Exception ex)
            {
                progress?.Report(new ScanProgress { Percent = 85, Message = $"ESLint skipped: {ex.Message}", FilesDone = done, TotalFiles = total });
            }

            // 3. External tool: Semgrep
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgress { Percent = 90, Message = "Running Semgrep analysis...", FilesDone = done, TotalFiles = total });
            try
            {
                var semgrepFindings = await SemgrepRunner.RunAsync(folder, ct).ConfigureAwait(false);
                findings.AddRange(semgrepFindings);
            }
            catch (Exception ex)
            {
                progress?.Report(new ScanProgress { Percent = 93, Message = $"Semgrep skipped: {ex.Message}", FilesDone = done, TotalFiles = total });
            }

            // 4. Dedup / merge
            var merged = Deduplicate(findings);

            progress?.Report(new ScanProgress { Percent = 100, Message = $"Scan complete. {merged.Count} findings.", FilesDone = total, TotalFiles = total });
            return merged;
        }

        /// <summary>
        /// Applies lightweight sanitizer and placeholder heuristics so obvious
        /// safe patterns do not become false positives.
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
                        lower.Contains("example") || lower.Contains("dummy") ||
                        lower.Contains("xxxx") || lower.Contains("<token>") ||
                        lower.Contains("changeme"))
                        return true;
                    break;

                case "INJECTION":
                    if (lower.Contains("prepare(") || lower.Contains("parameterized") ||
                        lower.Contains("setparameter") || lower.Contains("?") && lower.Contains("execute("))
                        return true;
                    break;

                case "XSS":
                    if (lower.Contains("sanitize") || lower.Contains("escape") ||
                        lower.Contains("encode") || lower.Contains("textcontent"))
                        return true;
                    break;

                case "PATH_TRAVERSAL":
                    if (lower.Contains("getfullpath") || lower.Contains("normalize") ||
                        lower.Contains("canonical"))
                        return true;
                    break;
            }
            return false;
        }

        /// <summary>
        /// Safely walks the folder tree, skipping vendor/build directories and
        /// reparse points. Any inaccessible directory is silently ignored.
        /// </summary>
        private static IEnumerable<string> EnumerateSourceFiles(string root)
        {
            var stack = new Stack<string>();
            stack.Push(root);

            while (stack.Count > 0)
            {
                var dir = stack.Pop();

                List<string> files = new();
                try { files.AddRange(Directory.EnumerateFiles(dir)); }
                catch { /* inaccessible directory */ }

                foreach (var file in files)
                {
                    if (Patterns.ScannableExtensions.Contains(Path.GetExtension(file)))
                        yield return file;
                }

                List<string> subDirs = new();
                try { subDirs.AddRange(Directory.EnumerateDirectories(dir)); }
                catch { /* inaccessible directory */ }

                foreach (var sub in subDirs)
                {
                    var name = Path.GetFileName(sub);
                    if (IgnoredDirectories.Contains(name)) continue;
                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    catch { continue; }
                    stack.Push(sub);
                }
            }
        }

        private static List<Finding> Deduplicate(List<Finding> input)
        {
            var map = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in input)
            {
                var key = $"{f.File}|{f.Line}|{f.Type}";
                if (!map.TryGetValue(key, out var existing))
                {
                    map[key] = f;
                }
                else
                {
                    // merge analyzer names
                    if (!existing.Analyzer.Contains(f.Analyzer, StringComparison.OrdinalIgnoreCase))
                        existing.Analyzer = existing.Analyzer + ", " + f.Analyzer;

                    // keep worse severity
                    if (Rank(f.Severity) > Rank(existing.Severity))
                        existing.Severity = f.Severity;

                    // keep longer description / snippet
                    if ((f.Description?.Length ?? 0) > (existing.Description?.Length ?? 0))
                        existing.Description = f.Description ?? string.Empty;
                    if ((f.Snippet?.Length ?? 0) > (existing.Snippet?.Length ?? 0))
                        existing.Snippet = f.Snippet ?? string.Empty;

                    if (string.IsNullOrEmpty(existing.Type) && !string.IsNullOrEmpty(f.Type))
                        existing.Type = f.Type;
                }
            }
            return map.Values.OrderByDescending(f => Rank(f.Severity)).ThenBy(f => f.File).ThenBy(f => f.Line).ToList();
        }

        private static int Rank(string sev) => Array.IndexOf(SeverityOrder, sev?.ToUpperInvariant() ?? "INFO");
    }
}

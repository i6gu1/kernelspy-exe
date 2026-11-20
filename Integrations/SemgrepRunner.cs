using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KernelSpyScanner.Engine;
using KernelSpyScanner.Models;

namespace KernelSpyScanner.Integrations
{
    /// <summary>
    /// Adapter that runs Semgrep and converts its JSON output into findings.
    ///
    /// The preferred engine is the bundled <c>semgrep-core.exe</c>, which is a
    /// native standalone binary and needs no Python installation. When that is
    /// not present the adapter can still use a bundled Python package, a system
    /// <c>semgrep</c> on PATH, or a semgrep binary under <c>tools</c>.
    /// </summary>
    public static class SemgrepRunner
    {
        private sealed class SemgrepLaunch
        {
            public string FileName { get; init; } = string.Empty;
            public string PrefixArgs { get; init; } = string.Empty;
            public string? PythonPath { get; init; }
            public bool IsCore { get; init; }
        }

        private sealed class SemgrepTarget
        {
            public string FullPath { get; init; } = string.Empty;
            public string RelativePath { get; init; } = string.Empty;
            public string Language { get; init; } = string.Empty;
        }

        private static readonly Dictionary<string, string> LanguageByExtension = new(StringComparer.OrdinalIgnoreCase)
        {
            [".py"] = "python",
            [".pyi"] = "python",
            [".js"] = "javascript",
            [".jsx"] = "javascript",
            [".mjs"] = "javascript",
            [".cjs"] = "javascript",
            [".ts"] = "typescript",
            [".tsx"] = "typescript",
            [".java"] = "java",
            [".cs"] = "csharp",
            [".php"] = "php",
            [".rb"] = "ruby",
            [".go"] = "go",
            [".rs"] = "rust",
            [".c"] = "c",
            [".h"] = "c",
            [".cc"] = "cpp",
            [".cpp"] = "cpp",
            [".cxx"] = "cpp",
            [".hpp"] = "cpp",
            [".hh"] = "cpp",
            [".kt"] = "kotlin",
            [".kts"] = "kotlin",
            [".swift"] = "swift",
            [".scala"] = "scala",
            [".sh"] = "bash",
            [".bash"] = "bash",
            [".ex"] = "elixir",
            [".exs"] = "elixir",
            [".clj"] = "clojure",
            [".lua"] = "lua",
            [".sol"] = "solidity",
            [".tf"] = "terraform",
            [".yaml"] = "yaml",
            [".yml"] = "yaml",
            [".json"] = "json",
            [".xml"] = "xml",
            [".html"] = "html",
            [".htm"] = "html",
            [".vue"] = "vue",
        };

        private const int MaxTargets = 100_000;

        private const string PysemgrepEntry =
            "-c \"from semgrep.console_scripts.pysemgrep import main; main()\"";

        public static async Task<List<Finding>> RunAsync(string folder, CancellationToken ct)
        {
            var results = new List<Finding>();
            var launch = FindSemgrep();
            if (launch == null)
                throw new FileNotFoundException("Semgrep was not found. Install it or place a runtime under /tools.");

            string config = FindRulesFile();
            string? targetsFile = null;

            try
            {
                string args;
                if (launch.IsCore)
                {
                    if (string.IsNullOrEmpty(config))
                        throw new FileNotFoundException(
                            "Semgrep rules were not found. Expected Rules/kernelspy-semgrep.yml next to the application.");

                    targetsFile = await WriteTargetsFileAsync(folder, ct).ConfigureAwait(false);
                    if (targetsFile == null)
                        return results;

                    args = $"-rules \"{config}\" -targets \"{targetsFile}\" -json";
                }
                else
                {
                    string configArg = string.IsNullOrEmpty(config) ? "--config=auto" : $"--config \"{config}\"";
                    args = $"{launch.PrefixArgs} {configArg} --json --quiet --no-git-ignore \"{folder}\"".Trim();
                }

                var psi = new ProcessStartInfo
                {
                    FileName = launch.FileName,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = folder
                };
                if (!string.IsNullOrEmpty(launch.PythonPath))
                    psi.Environment["PYTHONPATH"] = launch.PythonPath;

                using var proc = new Process { StartInfo = psi };
                var stdout = new StringBuilder();
                var stderr = new StringBuilder();
                proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
                proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

                try
                {
                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    await Task.Run(() =>
                    {
                        while (!proc.HasExited)
                        {
                            if (ct.IsCancellationRequested)
                            {
                                try { proc.Kill(entireProcessTree: true); } catch { }
                                ct.ThrowIfCancellationRequested();
                            }
                            Thread.Sleep(100);
                        }
                    }, ct).ConfigureAwait(false);

                    // Drain the asynchronous stdout/stderr readers before parsing.
                    proc.WaitForExit();
                }
                catch (OperationCanceledException)
                {
                    throw;
                }

                string json = stdout.ToString().Trim();
                if (string.IsNullOrEmpty(json))
                {
                    string err = stderr.ToString().Trim();
                    if (!string.IsNullOrEmpty(err))
                        throw new InvalidOperationException(err.Length > 400 ? err.Substring(0, 400) : err);
                    return results;
                }

                int idx = json.IndexOf('{');
                if (idx < 0) return results;
                json = json.Substring(idx);

                try
                {
                    using var doc = JsonDocument.Parse(json);
                    if (!doc.RootElement.TryGetProperty("results", out var res)) return results;
                    foreach (var r in res.EnumerateArray())
                    {
                        string path = r.TryGetProperty("path", out var p) ? p.GetString() ?? folder : folder;
                        path = NormalizeReportedPath(path, folder);
                        int line = 0;
                        if (r.TryGetProperty("start", out var st) && st.TryGetProperty("line", out var ln))
                            line = ln.GetInt32();

                        string checkId = r.TryGetProperty("check_id", out var c) ? c.GetString() ?? "semgrep" : "semgrep";
                        string message = string.Empty;
                        string severity = "MEDIUM";
                        string snippet = string.Empty;
                        if (r.TryGetProperty("extra", out var extra))
                        {
                            if (extra.TryGetProperty("message", out var m)) message = m.GetString() ?? string.Empty;
                            if (extra.TryGetProperty("severity", out var sev)) severity = MapSeverity(sev.GetString());
                            if (extra.TryGetProperty("lines", out var ls)) snippet = ls.GetString() ?? string.Empty;
                        }

                        // semgrep-core does not include source lines; fetch them so
                        // reports keep the same context as the Python front-end.
                        if (string.IsNullOrEmpty(snippet) && line > 0)
                            snippet = TryReadLine(path, line);

                        results.Add(new Finding(
                            path, line, $"Semgrep: {checkId}", "SAST", severity,
                            message, snippet, "semgrep"));
                    }
                }
                catch (JsonException) { }
            }
            finally
            {
                if (!string.IsNullOrEmpty(targetsFile))
                {
                    try { File.Delete(targetsFile); } catch { }
                }
            }

            return results;
        }

        private static string MapSeverity(string? s) => s?.ToUpperInvariant() switch
        {
            "ERROR" => "HIGH",
            "WARNING" => "MEDIUM",
            "INFO" => "LOW",
            _ => "MEDIUM"
        };

        private static SemgrepLaunch? FindSemgrep()
        {
            // 1. Standalone native semgrep-core (preferred: no Python needed).
            var core = AppPaths.FindToolFile(Path.Combine("semgrep-runtime", "semgrep", "bin", "semgrep-core.exe"))
                       ?? AppPaths.FindToolFileRecursive("semgrep-core.exe");
            if (!string.IsNullOrEmpty(core))
                return new SemgrepLaunch { FileName = core, IsCore = true };

            // 2. Bundled Python runtime plus the semgrep package under tools.
            var pythonExe = FindBundledPython();
            var runtimeRoot = FindSemgrepRuntimeRoot();
            if (!string.IsNullOrEmpty(pythonExe) && !string.IsNullOrEmpty(runtimeRoot))
            {
                return new SemgrepLaunch
                {
                    FileName = pythonExe,
                    PrefixArgs = PysemgrepEntry,
                    PythonPath = runtimeRoot
                };
            }

            // 3. System semgrep on PATH.
            try
            {
                var psi = new ProcessStartInfo("semgrep", "--version")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    if (p.WaitForExit(3000) && p.ExitCode == 0)
                        return new SemgrepLaunch { FileName = "semgrep" };
                }
            }
            catch { }

            // 4. Bundled runtime with any python on PATH.
            if (!string.IsNullOrEmpty(runtimeRoot))
            {
                return new SemgrepLaunch
                {
                    FileName = "python",
                    PrefixArgs = PysemgrepEntry,
                    PythonPath = runtimeRoot
                };
            }

            // 5. Common install locations.
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var candidates = new[]
            {
                Path.Combine(programFiles, "Semgrep", "semgrep.exe"),
                Path.Combine(programFiles, "semgrep", "semgrep.exe"),
            };
            foreach (var c in candidates)
                if (File.Exists(c)) return new SemgrepLaunch { FileName = c };

            // 6. Any semgrep executable under tools.
            var toolSemgrep = AppPaths.FindToolFileRecursive("semgrep.exe");
            if (!string.IsNullOrEmpty(toolSemgrep))
                return new SemgrepLaunch { FileName = toolSemgrep };

            return null;
        }

        private static string FindBundledPython()
        {
            var direct = AppPaths.FindToolFile(Path.Combine("python", "python.exe"))
                         ?? AppPaths.FindToolFile(Path.Combine("python", "python3.exe"))
                         ?? AppPaths.FindToolFile(Path.Combine("semgrep-runtime", "python.exe"));
            if (!string.IsNullOrEmpty(direct)) return direct;

            return AppPaths.FindToolFileRecursive("python.exe") ?? string.Empty;
        }

        private static string FindSemgrepRuntimeRoot()
        {
            var root = AppPaths.FindToolDirectory("semgrep-runtime");
            if (!string.IsNullOrEmpty(root) && Directory.Exists(Path.Combine(root, "semgrep")))
                return root;

            return string.Empty;
        }

        private static string FindRulesFile()
        {
            return AppPaths.FindFile("Rules", "kernelspy-semgrep.yml") ?? string.Empty;
        }

        private static async Task<string?> WriteTargetsFileAsync(string folder, CancellationToken ct)
        {
            var targets = new List<SemgrepTarget>();

            foreach (var file in SourceFiles.Enumerate(folder))
            {
                ct.ThrowIfCancellationRequested();

                if (!LanguageByExtension.TryGetValue(Path.GetExtension(file), out var language))
                    continue;

                string relative;
                try { relative = Path.GetRelativePath(folder, file); }
                catch { relative = Path.GetFileName(file); }

                relative = "/" + relative.Replace('\\', '/').TrimStart('/');

                targets.Add(new SemgrepTarget
                {
                    FullPath = Path.GetFullPath(file),
                    RelativePath = relative,
                    Language = language
                });

                if (targets.Count >= MaxTargets) break;
            }

            if (targets.Count == 0) return null;

            var entries = new object[targets.Count];
            for (var i = 0; i < targets.Count; i++)
            {
                var target = targets[i];
                entries[i] = new object[]
                {
                    "CodeTarget",
                    new Dictionary<string, object?>
                    {
                        ["path"] = new Dictionary<string, string>
                        {
                            ["fpath"] = target.FullPath,
                            ["ppath"] = target.RelativePath
                        },
                        ["analyzer"] = target.Language,
                        ["products"] = new[] { "sast" }
                    }
                };
            }

            var document = new object[] { "Targets", entries };
            string json = JsonSerializer.Serialize(document);
            string targetsPath = Path.Combine(Path.GetTempPath(), $"kernelspy-semgrep-{Guid.NewGuid():N}.json");

            // semgrep-core rejects a UTF-8 BOM, so write without one.
            await File.WriteAllTextAsync(targetsPath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), ct)
                .ConfigureAwait(false);

            return targetsPath;
        }

        /// <summary>
        /// semgrep-core reports the synthetic ppath from the targets file
        /// (/src/file.py). Convert it back to a real filesystem path so dedup
        /// and report snippets work on the actual file.
        /// </summary>
        private static string NormalizeReportedPath(string path, string root)
        {
            if (string.IsNullOrWhiteSpace(path)) return root;
            if (!path.StartsWith('/') && !path.StartsWith('\\'))
                return path;

            var relative = path.TrimStart('/', '\\').Replace('/', Path.DirectorySeparatorChar);
            try { return Path.GetFullPath(Path.Combine(root, relative)); }
            catch { return path; }
        }

        private static string TryReadLine(string path, int line)
        {
            try
            {
                if (line <= 0 || !File.Exists(path)) return string.Empty;

                using var reader = new StreamReader(path);
                for (var i = 1; i < line; i++)
                {
                    if (reader.ReadLine() == null) return string.Empty;
                }

                return reader.ReadLine()?.Trim() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}

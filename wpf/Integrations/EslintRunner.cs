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
    /// Adapter that runs the bundled ESLint tool and converts its JSON output
    /// into <see cref="Finding"/> instances.
    ///
    /// Both ESLint and its Node.js runtime are resolved from the application's
    /// own <c>tools</c> folder. The bundled Node.js copy is used when present;
    /// otherwise the process falls back to a system-wide <c>node</c> on PATH.
    ///
    /// ESLint is run with the scanned folder as its working directory and a
    /// relative "." target. This keeps ESLint's flat-config base path inside the
    /// scanned tree, so repositories outside the application folder work too.
    /// </summary>
    public static class EslintRunner
    {
        private const string RulesJson =
            "{\"no-eval\":\"error\",\"no-implied-eval\":\"error\",\"no-new-func\":\"error\"," +
            "\"no-script-url\":\"error\",\"no-prototype-builtins\":\"warn\"}";

        public static async Task<List<Finding>> RunAsync(string folder, CancellationToken ct)
        {
            var results = new List<Finding>();

            string eslintJs = FindEslintJs();
            if (string.IsNullOrEmpty(eslintJs))
                throw new FileNotFoundException("Bundled ESLint (eslint.js) was not found under /tools.");

            string nodeExe = FindNodeExe();
            if (string.IsNullOrEmpty(nodeExe))
                throw new FileNotFoundException("Node.js was not found. The bundled tools/node/node.exe is missing and no node.exe is available on PATH.");

            string args = $"\"{eslintJs}\" --no-config-lookup --no-ignore --ext .js,.jsx,.ts,.tsx,.mjs,.cjs " +
                          $"--rule \"{RulesJson}\" --format json .";

            var psi = new ProcessStartInfo
            {
                FileName = nodeExe,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = folder
            };

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

            // ESLint prints a JSON array. It may be preceded by noise; find first '['.
            int idx = json.IndexOf('[');
            if (idx < 0) return results;
            json = json.Substring(idx);

            try
            {
                using var doc = JsonDocument.Parse(json);
                foreach (var fileNode in doc.RootElement.EnumerateArray())
                {
                    string filePath = fileNode.TryGetProperty("filePath", out var fp) ? fp.GetString() ?? folder : folder;
                    if (!fileNode.TryGetProperty("messages", out var msgs)) continue;
                    foreach (var msg in msgs.EnumerateArray())
                    {
                        int line = msg.TryGetProperty("line", out var l) ? l.GetInt32() : 0;
                        int sevNum = msg.TryGetProperty("severity", out var s) ? s.GetInt32() : 1;
                        string severity = sevNum >= 2 ? "HIGH" : "MEDIUM";
                        string ruleId = msg.TryGetProperty("ruleId", out var r) && r.ValueKind != JsonValueKind.Null ? r.GetString() ?? "eslint" : "eslint";
                        string message = msg.TryGetProperty("message", out var m) ? m.GetString() ?? string.Empty : string.Empty;

                        results.Add(new Finding(
                            filePath, line, $"ESLint: {ruleId}", "LINT", severity,
                            message, string.Empty, "eslint"));
                    }
                }
            }
            catch (JsonException)
            {
                // Output wasn't valid JSON; ignore.
            }

            return results;
        }

        private static string FindEslintJs()
        {
            var direct = AppPaths.FindToolFile(Path.Combine("eslint-10.13.0", "eslint-10.13.0", "bin", "eslint.js"));
            if (!string.IsNullOrEmpty(direct)) return direct;

            return AppPaths.FindToolFileRecursive("eslint.js") ?? string.Empty;
        }

        private static string FindNodeExe()
        {
            var bundled = AppPaths.FindToolFile(Path.Combine("node", "node.exe"))
                          ?? AppPaths.FindToolFile(Path.Combine("nodejs", "node.exe"));
            if (!string.IsNullOrEmpty(bundled)) return bundled;

            // Standalone installs always carry the bundled runtime. The PATH
            // fallback keeps developer machines and advanced deployments working.
            try
            {
                var path = Environment.GetEnvironmentVariable("PATH");
                if (!string.IsNullOrWhiteSpace(path))
                {
                    foreach (var directory in path.Split(Path.PathSeparator))
                    {
                        if (string.IsNullOrWhiteSpace(directory)) continue;
                        var candidate = Path.Combine(directory.Trim().Trim('"'), "node.exe");
                        if (File.Exists(candidate)) return candidate;
                    }
                }
            }
            catch
            {
                // Fall through to the clear "not found" error.
            }

            return string.Empty;
        }
    }
}

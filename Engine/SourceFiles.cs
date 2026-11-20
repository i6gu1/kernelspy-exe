using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace KernelSpyScanner.Engine
{
    public enum SourceFileKind
    {
        Unknown,
        Code,
        Config
    }

    /// <summary>
    /// Shared file discovery and comment masking logic used by the scanner and
    /// by the Semgrep adapter. Keeping the two in sync is important: a file that
    /// is skipped only by one analyser is a missed vulnerability.
    /// </summary>
    public static class SourceFiles
    {
        public static readonly HashSet<string> IgnoredDirectories = new(StringComparer.OrdinalIgnoreCase)
        {
            ".git", ".svn", ".hg", "node_modules", "bin", "obj", "dist", "build",
            "__pycache__", ".venv", "venv", "env", ".idea", ".vs", ".vscode",
            "packages", "vendor", "tools", "publish", "installer", ".next",
            ".nuxt", "coverage", "target", "DerivedData", ".gradle"
        };

        private static readonly HashSet<string> IgnoredFileNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
            "Cargo.lock", "composer.lock", "Pipfile.lock", "poetry.lock"
        };

        private static readonly HashSet<string> CodeExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".csx", ".fs", ".fsx", ".vb", ".py", ".pyi", ".js", ".jsx",
            ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".rs", ".c", ".h",
            ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".php", ".phtml",
            ".rb", ".rake", ".kt", ".kts", ".swift", ".dart", ".lua", ".pl",
            ".scala", ".groovy", ".sql", ".sh", ".bash", ".zsh", ".ps1", ".bat",
            ".cmd", ".vue", ".svelte", ".razor", ".cshtml", ".aspx", ".jsp",
            ".erb", ".haml", ".sol", ".graphql", ".tf", ".tfvars", ".html",
            ".htm", ".xml", ".config", ".csproj", ".props", ".targets"
        };

        private static readonly HashSet<string> ConfigExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".conf",
            ".properties", ".env", ".config"
        };

        /// <summary>Returns the kind of source contained in a path.</summary>
        public static SourceFileKind GetKind(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return SourceFileKind.Unknown;

            var name = Path.GetFileName(path);
            if (string.Equals(name, ".env", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith(".env.", StringComparison.OrdinalIgnoreCase))
                return SourceFileKind.Config;

            var extension = Path.GetExtension(path);
            if (CodeExtensions.Contains(extension)) return SourceFileKind.Code;
            if (ConfigExtensions.Contains(extension)) return SourceFileKind.Config;
            return SourceFileKind.Unknown;
        }

        /// <summary>All extensions that can contain source or configuration.</summary>
        public static HashSet<string> AllExtensions
        {
            get
            {
                var all = new HashSet<string>(CodeExtensions, StringComparer.OrdinalIgnoreCase);
                all.UnionWith(ConfigExtensions);
                return all;
            }
        }

        public static bool IsScannable(string path)
        {
            if (GetKind(path) == SourceFileKind.Unknown) return false;
            var name = Path.GetFileName(path);
            if (IgnoredFileNames.Contains(name)) return false;
            if (name.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".map", StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        public static bool IsIgnoredDirectory(string name) =>
            !string.IsNullOrWhiteSpace(name) && IgnoredDirectories.Contains(name);

        /// <summary>
        /// Walks a folder without following reparse points and without entering
        /// generated/vendor directories. Both analysers use this exact order.
        /// </summary>
        public static IEnumerable<string> Enumerate(string root)
        {
            var stack = new Stack<string>();
            stack.Push(root);

            while (stack.Count > 0)
            {
                var dir = stack.Pop();

                string[] files;
                try { files = Directory.GetFiles(dir); }
                catch { continue; }

                foreach (var file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    if (IsScannable(file)) yield return file;
                }

                string[] subDirs;
                try { subDirs = Directory.GetDirectories(dir); }
                catch { continue; }

                foreach (var sub in subDirs.OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
                {
                    if (IsIgnoredDirectory(Path.GetFileName(sub))) continue;

                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    catch { continue; }

                    stack.Push(sub);
                }
            }
        }

        /// <summary>
        /// Replaces comment characters with spaces while preserving string
        /// literals, offsets and line breaks. Detection rules for code run on
        /// this masked text, so a dangerous-looking token inside a comment or a
        /// Python docstring can no longer create a false alert.
        /// </summary>
        public static string MaskComments(string text, string path)
        {
            if (string.IsNullOrEmpty(text)) return text;

            var tokens = GetCommentTokens(path);
            var chars = text.ToCharArray();
            var extension = Path.GetExtension(path);
            bool isPython = extension.Equals(".py", StringComparison.OrdinalIgnoreCase) ||
                            extension.Equals(".pyi", StringComparison.OrdinalIgnoreCase);

            var i = 0;
            while (i < chars.Length)
            {
                // Python/Ruby docstrings are documentation, not executable code.
                if (isPython && (StartsWith(chars, i, "\"\"\"") || StartsWith(chars, i, "'''")))
                {
                    var marker = new string(chars, i, 3);
                    var end = IndexOf(chars, i + 3, marker);
                    Blank(chars, i, end < 0 ? chars.Length : Math.Min(chars.Length, end + 3));
                    i = end < 0 ? chars.Length : end + 3;
                    continue;
                }

                // Consume a string literal verbatim; comment tokens inside it are
                // data (for example https:// or "#tag") and must stay untouched.
                if (chars[i] == '"' || chars[i] == '\'' || chars[i] == '`')
                {
                    var quote = chars[i];
                    i++;
                    while (i < chars.Length)
                    {
                        if (chars[i] == '\\') { i += 2; continue; }
                        if (chars[i] == quote) { i++; break; }
                        i++;
                    }
                    continue;
                }

                var matched = false;
                foreach (var token in tokens)
                {
                    if (!StartsWith(chars, i, token.Start)) continue;

                    if (string.IsNullOrEmpty(token.End))
                    {
                        var end = i;
                        while (end < chars.Length && chars[end] != '\n' && chars[end] != '\r') end++;
                        Blank(chars, i, end);
                        i = end;
                    }
                    else
                    {
                        var end = IndexOf(chars, i + token.Start.Length, token.End);
                        var stop = end < 0 ? chars.Length : Math.Min(chars.Length, end + token.End.Length);
                        Blank(chars, i, stop);
                        i = stop;
                    }

                    matched = true;
                    break;
                }

                if (!matched) i++;
            }

            return new string(chars);
        }

        private readonly record struct CommentToken(string Start, string End);

        private static CommentToken[] GetCommentTokens(string path)
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();

            switch (extension)
            {
                case ".py": case ".pyi": case ".rb": case ".rake": case ".sh":
                case ".bash": case ".zsh": case ".yaml": case ".yml": case ".toml":
                case ".ini": case ".conf": case ".properties": case ".env":
                case ".ps1": case ".gemfile":
                    return new[] { new CommentToken("#", string.Empty) };

                case ".sql": case ".lua":
                    return new[] { new CommentToken("--", string.Empty), BlockComment };

                case ".html": case ".htm": case ".xml": case ".config":
                case ".csproj": case ".props": case ".targets": case ".aspx":
                    return new[] { new CommentToken("<!--", "-->") };

                case ".vue": case ".svelte": case ".cshtml": case ".razor":
                    return new[] { LineComment, BlockComment, new CommentToken("<!--", "-->") };

                case ".php":
                    return new[] { LineComment, BlockComment, new CommentToken("#", string.Empty) };

                default:
                    return new[] { LineComment, BlockComment };
            }
        }

        private static readonly CommentToken LineComment = new("//", string.Empty);
        private static readonly CommentToken BlockComment = new("/*", "*/");

        private static bool StartsWith(char[] chars, int index, string value)
        {
            if (index < 0 || index + value.Length > chars.Length) return false;
            for (var i = 0; i < value.Length; i++)
                if (chars[index + i] != value[i]) return false;
            return true;
        }

        private static int IndexOf(char[] chars, int start, string value)
        {
            for (var i = Math.Max(0, start); i + value.Length <= chars.Length; i++)
            {
                if (StartsWith(chars, i, value)) return i;
            }
            return -1;
        }

        private static void Blank(char[] chars, int start, int end)
        {
            for (var i = Math.Max(0, start); i < Math.Min(chars.Length, end); i++)
            {
                if (chars[i] != '\n' && chars[i] != '\r') chars[i] = ' ';
            }
        }
    }
}

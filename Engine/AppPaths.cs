using System;
using System.Collections.Generic;
using System.IO;

namespace KernelSpyScanner.Engine
{
    /// <summary>
    /// Resolves files and directories that ship next to the application
    /// (<c>tools/</c>, <c>Rules/</c>, ...).
    ///
    /// Resolution never depends on the process working directory. It checks the
    /// application base directory, the real executable directory (which differs
    /// for single-file/extracted deployments), and the parent directories of
    /// both so a development build under <c>bin/...</c> still finds the
    /// repository-level resources.
    /// </summary>
    public static class AppPaths
    {
        private const int MaxParentLevels = 8;

        private static readonly Lazy<string> BaseDirectoryLazy = new(ResolveBaseDirectory);
        private static readonly Lazy<string?> ExecutableDirectoryLazy = new(ResolveExecutableDirectory);
        private static readonly Lazy<string?> ToolsDirectoryLazy = new(FindToolsDirectoryCore);
        private static readonly Lazy<string?> RulesDirectoryLazy = new(FindRulesDirectoryCore);
        private static readonly Lazy<IReadOnlyList<string>> SearchRootsLazy = new(BuildSearchRoots);

        /// <summary>Directory containing the managed application (AppContext.BaseDirectory).</summary>
        public static string BaseDirectory => BaseDirectoryLazy.Value;

        /// <summary>
        /// Directory containing the actual executable. For single-file builds this
        /// is the deployment folder, not the temporary extraction directory.
        /// </summary>
        public static string? ExecutableDirectory => ExecutableDirectoryLazy.Value;

        /// <summary>Resolved <c>tools</c> directory, or null when it is not installed.</summary>
        public static string? ToolsDirectory => ToolsDirectoryLazy.Value;

        /// <summary>Resolved <c>Rules</c> directory, or null when it is not installed.</summary>
        public static string? RulesDirectory => RulesDirectoryLazy.Value;

        private static IReadOnlyList<string> SearchRoots => SearchRootsLazy.Value;

        /// <summary>
        /// Finds a file below the bundled <c>tools</c> directory using a relative
        /// path such as <c>node\node.exe</c>.
        /// </summary>
        public static string? FindToolFile(string relativePath)
        {
            if (string.IsNullOrWhiteSpace(relativePath)) return null;

            foreach (var root in SearchRoots)
            {
                if (TryGetFile(Path.Combine(root, "tools", relativePath), out var full))
                    return full;
            }

            var tools = ToolsDirectory;
            if (!string.IsNullOrEmpty(tools) && TryGetFile(Path.Combine(tools, relativePath), out var nested))
                return nested;

            return null;
        }

        /// <summary>Finds a directory below the bundled <c>tools</c> directory.</summary>
        public static string? FindToolDirectory(string relativePath)
        {
            if (string.IsNullOrWhiteSpace(relativePath)) return null;

            foreach (var root in SearchRoots)
            {
                if (TryGetDirectory(Path.Combine(root, "tools", relativePath), out var full))
                    return full;
            }

            var tools = ToolsDirectory;
            if (!string.IsNullOrEmpty(tools) && TryGetDirectory(Path.Combine(tools, relativePath), out var nested))
                return nested;

            return null;
        }

        /// <summary>
        /// Last-resort lookup for a tool file that may live in a differently named
        /// subfolder (for example an updated ESLint version). The direct paths
        /// should always be preferred because this can touch many files.
        /// </summary>
        public static string? FindToolFileRecursive(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return null;

            var tools = ToolsDirectory;
            if (string.IsNullOrEmpty(tools)) return null;

            try
            {
                foreach (var file in Directory.EnumerateFiles(tools, fileName, SearchOption.AllDirectories))
                    return file;
            }
            catch
            {
                // Unreadable tool folder: treat the resource as unavailable.
            }

            return null;
        }

        /// <summary>
        /// Finds an application resource (for example <c>Rules/kernelspy-semgrep.yml</c>).
        /// </summary>
        public static string? FindFile(params string[] relativeParts)
        {
            if (relativeParts == null || relativeParts.Length == 0) return null;

            var relativePath = Path.Combine(relativeParts);
            foreach (var root in SearchRoots)
            {
                if (TryGetFile(Path.Combine(root, relativePath), out var full))
                    return full;
            }

            return null;
        }

        /// <summary>Finds an application directory (for example <c>Rules</c>).</summary>
        public static string? FindDirectory(params string[] relativeParts)
        {
            if (relativeParts == null || relativeParts.Length == 0) return null;

            var relativePath = Path.Combine(relativeParts);
            foreach (var root in SearchRoots)
            {
                if (TryGetDirectory(Path.Combine(root, relativePath), out var full))
                    return full;
            }

            return null;
        }

        private static string ResolveBaseDirectory()
        {
            var directory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(directory))
            {
                directory = ResolveExecutableDirectory() ?? Directory.GetCurrentDirectory();
            }

            try
            {
                return Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
            }
            catch
            {
                return directory;
            }
        }

        private static string? ResolveExecutableDirectory()
        {
            try
            {
                var processPath = Environment.ProcessPath;
                if (string.IsNullOrWhiteSpace(processPath)) return null;

                // When launched through "dotnet app.dll", ProcessPath is dotnet.exe.
                // Its folder is unrelated to the application, so ignore it.
                var name = Path.GetFileNameWithoutExtension(processPath);
                if (string.Equals(name, "dotnet", StringComparison.OrdinalIgnoreCase))
                    return null;

                var directory = Path.GetDirectoryName(processPath);
                return string.IsNullOrWhiteSpace(directory) ? null : Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
            }
            catch
            {
                return null;
            }
        }

        private static IReadOnlyList<string> BuildSearchRoots()
        {
            var roots = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(string? directory)
            {
                if (string.IsNullOrWhiteSpace(directory)) return;

                try
                {
                    var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
                    if (seen.Add(full)) roots.Add(full);
                }
                catch
                {
                    // Ignore malformed paths.
                }
            }

            void AddWithParents(string? directory)
            {
                var current = directory;
                for (var level = 0; level <= MaxParentLevels && !string.IsNullOrWhiteSpace(current); level++)
                {
                    // Do not search a filesystem root (for example C:\): it is
                    // not part of the application and could contain unrelated,
                    // attacker-controlled tool binaries.
                    var pathRoot = Path.GetPathRoot(current);
                    if (!string.IsNullOrWhiteSpace(pathRoot) &&
                        string.Equals(
                            Path.TrimEndingDirectorySeparator(current),
                            Path.TrimEndingDirectorySeparator(pathRoot),
                            StringComparison.OrdinalIgnoreCase))
                        break;

                    Add(current);

                    var parent = Path.GetDirectoryName(current);
                    if (string.IsNullOrWhiteSpace(parent) ||
                        string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                        break;

                    current = parent;
                }
            }

            AddWithParents(BaseDirectory);
            AddWithParents(ExecutableDirectory);

            return roots;
        }

        private static string? FindToolsDirectoryCore()
        {
            foreach (var root in SearchRoots)
            {
                if (TryGetDirectory(Path.Combine(root, "tools"), out var full))
                    return full;
            }

            return null;
        }

        private static string? FindRulesDirectoryCore()
        {
            foreach (var root in SearchRoots)
            {
                if (TryGetDirectory(Path.Combine(root, "Rules"), out var full))
                    return full;
            }

            return null;
        }

        private static bool TryGetFile(string path, out string fullPath)
        {
            try
            {
                fullPath = Path.GetFullPath(path);
                return File.Exists(fullPath);
            }
            catch
            {
                fullPath = string.Empty;
                return false;
            }
        }

        private static bool TryGetDirectory(string path, out string fullPath)
        {
            try
            {
                fullPath = Path.GetFullPath(path);
                return Directory.Exists(fullPath);
            }
            catch
            {
                fullPath = string.Empty;
                return false;
            }
        }
    }
}

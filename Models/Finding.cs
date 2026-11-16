using System;

namespace KernelSpyScanner.Models
{
    /// <summary>
    /// Represents a single security finding produced by the engine or external tools.
    /// </summary>
    public sealed class Finding
    {
        public string File { get; set; } = string.Empty;
        public int Line { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Severity { get; set; } = "MEDIUM";
        public string Description { get; set; } = string.Empty;
        public string Snippet { get; set; } = string.Empty;
        public string Analyzer { get; set; } = string.Empty;

        public Finding() { }

        public Finding(string file, int line, string type, string category, string severity,
                      string description, string snippet, string analyzer)
        {
            File = file;
            Line = line;
            Type = type;
            Category = category;
            Severity = severity;
            Description = description;
            Snippet = snippet;
            Analyzer = analyzer;
        }

        public override string ToString() => $"[{Severity}] {Type} @ {File}:{Line}";
    }
}

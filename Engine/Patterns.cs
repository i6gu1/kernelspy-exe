using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace KernelSpyScanner.Engine
{
    /// <summary>
    /// A single regex-based detection rule used by the core engine.
    /// </summary>
    public sealed class PatternRule
    {
        public string Name { get; }
        public string Category { get; }
        public string Severity { get; }
        public Regex Regex { get; }

        public PatternRule(string name, string category, string severity, string pattern,
                           RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Compiled)
        {
            Name = name;
            Category = category;
            Severity = severity;
            Regex = new Regex(pattern, options);
        }
    }

    /// <summary>
    /// Central registry of detection rules. Mirrors the spirit of the Python
    /// pattern/lexer analyzers while staying lightweight and dependency-free.
    /// </summary>
    public static class Patterns
    {
        public static readonly List<PatternRule> Rules = new()
        {
            // SQL Injection - only flag dynamic SQL construction, not every '+'
            new("SQL Injection (dynamic query)", "INJECTION", "HIGH",
                @"(?i)(execute|executemany|query|raw)\s*\(\s*(['""][^'""]*['""]\s*\+|f['""]|`|.*\$\{)"),

            new("SQL Injection (concatenated statement)", "INJECTION", "CRITICAL",
                @"(?i)\b(select|insert|update|delete)\b[^;]{0,200}(\+\s*[A-Za-z_$]|%s|\$\{)"),

            // OS Command Injection
            new("OS Command Injection", "INJECTION", "CRITICAL",
                @"(?i)\b(system|popen|shell_exec|exec|Runtime\.getRuntime\(\)\.exec|Process\.Start)\s*\([^)]*(\+|%s|\$\{)"),

            // Cross-Site Scripting
            new("Cross-Site Scripting (XSS)", "XSS", "HIGH",
                @"(?i)(\.innerHTML\s*=|document\.write\s*\(|Response\.Write\s*\(|dangerouslySetInnerHTML)"),

            // Path Traversal
            new("Path Traversal", "PATH_TRAVERSAL", "HIGH",
                @"(?i)(File\.ReadAllText|File\.ReadAllBytes|open|fopen|readFileSync)\s*\([^)]*\.\."),

            // Hardcoded Secrets
            new("Hardcoded Secret", "SECRET", "HIGH",
                @"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\b\s*[:=]\s*['""][A-Za-z0-9_\-\.]{8,}['""]"),

            // SSRF
            new("Server-Side Request Forgery (SSRF)", "SSRF", "MEDIUM",
                @"(?i)(HttpClient|WebRequest|fetch|requests\.get|urllib\.request)\s*\([^)]*(user|input|url|param)"),

            // Insecure Deserialization
            new("Insecure Deserialization", "DESERIALIZATION", "CRITICAL",
                @"(?i)\b(BinaryFormatter|pickle\.loads|ObjectInputStream|unserialize)\s*\("),

            // Weak Cryptography
            new("Weak Cryptography (MD5/SHA1)", "CRYPTO", "MEDIUM",
                @"(?i)(MD5|SHA1)\.Create|MessageDigest\.getInstance\(\s*['""](MD5|SHA-1)['""]|hashlib\.(md5|sha1)\("),

            // Eval / Code Execution
            new("Dangerous Eval", "CODE_EXECUTION", "CRITICAL",
                @"(?i)\b(eval|exec)\s*\("),

            // LDAP Injection
            new("LDAP Injection", "INJECTION", "MEDIUM",
                @"(?i)DirectorySearcher[^;]*Filter\s*=\s*[^;]*\+"),

            // Open redirect
            new("Open Redirect", "REDIRECT", "MEDIUM",
                @"(?i)(Response\.Redirect|redirect|res\.redirect)\s*\(\s*(request|req|user|param|input)"),

            // XML External Entity
            new("XML External Entity (XXE)", "XXE", "HIGH",
                @"(?i)(XmlReaderSettings|DocumentBuilderFactory|SAXParserFactory).*setFeature\([^)]*(external|doctype)"),

            // ---- Provider / cloud credentials (ported from core/rules/secrets.py) ----
            new("AWS Access Key", "CLOUD", "CRITICAL", @"\bAKIA[0-9A-Z]{16}\b"),
            new("Google API Key", "CLOUD", "HIGH", @"\bAIza[0-9A-Za-z\-_]{35}\b"),
            new("GitHub Token", "VCS", "CRITICAL", @"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
            new("GitLab Token", "VCS", "CRITICAL", @"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
            new("Stripe Live Key", "PAYMENT", "CRITICAL", @"\bsk_live_[0-9a-zA-Z]{24,}\b"),
            new("Slack Bot Token", "CHAT", "CRITICAL", @"\bxoxb-[0-9]{11,}-[A-Za-z0-9]{24,}\b"),
            new("Discord Webhook", "CHAT", "HIGH", @"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
            new("Telegram Bot Token", "CHAT", "CRITICAL", @"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b"),
            new("OpenAI Key", "AI", "CRITICAL", @"\bsk-[A-Za-z0-9]{48,}\b"),
            new("Anthropic Key", "AI", "CRITICAL", @"\bsk-ant-[A-Za-z0-9_\-]{40,}\b"),
            new("Hugging Face Token", "AI", "HIGH", @"\bhf_[A-Za-z0-9]{34,}\b"),
            new("SendGrid Key", "EMAIL", "CRITICAL", @"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"),
            new("NPM Token", "PACKAGE", "HIGH", @"\bnpm_[A-Za-z0-9]{36}\b"),
            new("Private Key Block", "SECRET", "CRITICAL", @"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            new("JWT Token", "SECRET", "MEDIUM", @"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
            new("Database Connection String", "CREDENTIALS", "HIGH",
                @"(?i)(mysql|postgres|postgresql|mongodb|redis|jdbc:[a-z]+)://[^:\s]+:[^@\s]+@"),
            new("Azure Storage Key", "CLOUD", "CRITICAL",
                @"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
        };

        /// <summary>
        /// File extensions considered scannable source code.
        /// </summary>
        public static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs",
            ".cpp", ".c", ".h", ".hpp", ".php", ".rb", ".kt", ".swift", ".dart",
            ".lua", ".pl", ".scala", ".groovy", ".sql", ".sh", ".ps1"
        };
    }
}

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace KernelSpyScanner.Engine
{
    /// <summary>Which files a rule is allowed to run against.</summary>
    public enum RuleScope
    {
        All,
        Code,
        Config
    }

    /// <summary>
    /// A single regex-based detection rule used by the core engine.
    /// </summary>
    public sealed class PatternRule
    {
        public string Name { get; }
        public string Category { get; }
        public string Severity { get; }
        public Regex Regex { get; }
        public RuleScope Scope { get; }

        public PatternRule(string name, string category, string severity, string pattern,
                           RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Compiled,
                           RuleScope scope = RuleScope.All)
        {
            Name = name;
            Category = category;
            Severity = severity;
            Regex = new Regex(pattern, options);
            Scope = scope;
        }
    }

    /// <summary>
    /// Central registry of detection rules. Code rules run on text with
    /// comments masked; credential rules also run on configuration files.
    /// </summary>
    public static class Patterns
    {
        private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.Compiled;
        private const RegexOptions MultiLineOptions = Options | RegexOptions.Multiline;

        public static readonly List<PatternRule> Rules = new()
        {
            // ---- Injection -------------------------------------------------
            new("SQL Injection (dynamic query)", "INJECTION", "HIGH",
                @"\b(execute|executemany|query|raw)\s*\(\s*(['""]?[^)'""]*['""]?\s*\+|f['""]|`|[^)\n]*\$\{)", Options, RuleScope.Code),

            new("SQL Injection (concatenated statement)", "INJECTION", "CRITICAL",
                @"\b(select|insert|update|delete)\b[^;\n]{0,200}(\+\s*[A-Za-z_$]|%s|\$\{|\{[A-Za-z_][\w]*\})", Options, RuleScope.Code),

            new("OS Command Injection", "INJECTION", "CRITICAL",
                @"\b(system|popen|shell_exec|exec|execSync|spawn|Runtime\.getRuntime\(\)\.exec|Process\.Start)\s*\([^)\n]*(\+|%s|\$\{|\{[A-Za-z_][\w]*\})", Options, RuleScope.Code),

            new("LDAP Injection", "INJECTION", "MEDIUM",
                @"DirectorySearcher[^;\n]*Filter\s*=\s*[^;\n]*(\+|\$|<)", Options, RuleScope.Code),

            // ---- Cross-site scripting --------------------------------------
            new("Cross-Site Scripting (XSS)", "XSS", "HIGH",
                @"(\.(?:inner|outer)HTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|Response\.Write\s*\(|dangerouslySetInnerHTML|v-html\s*=|bypassSecurityTrustHtml\s*\()", Options, RuleScope.Code),

            // ---- Path traversal --------------------------------------------
            new("Path Traversal", "PATH_TRAVERSAL", "HIGH",
                @"\b(File\.ReadAllText|File\.ReadAllBytes|File\.OpenRead|open|fopen|readFileSync|fs\.readFile)\s*\([^)\n]*(\.\./|%2e%2e|\$\{[^}\n]*(user|input|param)|\+\s*[A-Za-z_$])", Options, RuleScope.Code),

            new("Path Traversal (user-controlled path)", "PATH_TRAVERSAL", "MEDIUM",
                @"\bPath\.Combine\s*\([^)\n]*(user|input|param|filename|file)[^)\n]*\)", Options, RuleScope.Code),

            // ---- Server-side request forgery --------------------------------
            new("Server-Side Request Forgery (SSRF)", "SSRF", "MEDIUM",
                @"(?<!\bdef\s)(?<!\bfunction\s)(?<!\bconst\s)(?<!\blet\s)(?<!\bvar\s)\b(fetch|axios\.(?:get|post)|requests\.(?:get|post)|urllib\.request\.urlopen|WebRequest\.Create|HttpClient\.GetAsync|http\.Get)\s*\(\s*[^)\n]*(user|input|param|query|target|url|href|link|addr)", Options, RuleScope.Code),

            // ---- Deserialization -------------------------------------------
            new("Insecure Deserialization", "DESERIALIZATION", "CRITICAL",
                @"\b(BinaryFormatter|ObjectInputStream|XMLDecoder|pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.load|unserialize|readObject)\s*\(", Options, RuleScope.Code),

            new("Unsafe JSON type handling", "DESERIALIZATION", "HIGH",
                @"TypeNameHandling\s*=\s*TypeNameHandling\.All", Options, RuleScope.Code),

            // ---- Cryptography ----------------------------------------------
            new("Weak Cryptography (MD5/SHA1/DES/RC4)", "CRYPTO", "MEDIUM",
                @"\b(MD5|SHA1|SHA-1|DES|RC4|ARC4)\.Create\s*\(|MessageDigest\.getInstance\(\s*['""](MD5|SHA-1|DES|RC4)['""]|hashlib\.(md5|sha1)\s*\(|CryptoJS\.(MD5|SHA1)\s*\(", Options, RuleScope.Code),

            // ---- Code execution --------------------------------------------
            new("Dangerous Eval", "CODE_EXECUTION", "CRITICAL",
                @"\b(eval|exec|execScript)\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['""][^'""\n]*['""]", Options, RuleScope.Code),

            // ---- Redirects and XML -----------------------------------------
            new("Open Redirect", "REDIRECT", "MEDIUM",
                @"\b(Response\.Redirect|redirect|res\.redirect)\s*\(\s*(request|req|user|param|input|query)|\b(?:window\.)?location(?:\.href)?\s*=\s*(?:request|req|user|param|input|query)", Options, RuleScope.Code),

            new("XML External Entity (XXE)", "XXE", "HIGH",
                @"DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new|setFeature\s*\([^)\n]*(external-general-entities|external-parameter-entities|load-external-dtd)|XMLParser\s*\([^)\n]*resolve_entities\s*=\s*True|libxml_disable_entity_loader\s*\(\s*false", Options, RuleScope.Code),

            new("CSRF protection disabled", "CSRF", "MEDIUM",
                @"\b(csrf|antiforgery|xsrf)[^;\n]{0,40}(disable|disabled|off|false)", Options, RuleScope.Code),

            // ---- Credentials and provider tokens ---------------------------
            new("Hardcoded Secret", "SECRET", "HIGH",
                @"\b(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key)\b\s*[:=]\s*['""][A-Za-z0-9_\-./+=]{8,}['""]", Options),

            new("Hardcoded Secret (config value)", "SECRET", "HIGH",
                @"^\s*['""]?(?:export\s+)?(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key|token)\b['""]?\s*[:=]\s*['""]?[A-Za-z0-9_\-./+=]{8,}['""]?", MultiLineOptions, RuleScope.Config),

            new("Bearer token in configuration", "SECRET", "HIGH",
                @"\bAuthorization\s*[:=]\s*['""]?Bearer\s+[A-Za-z0-9_\-\.]{16,}", Options, RuleScope.Config),

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
            new("Private Key Block", "SECRET", "CRITICAL", @"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            new("JWT Token", "SECRET", "MEDIUM", @"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
            new("Database Connection String", "CREDENTIALS", "HIGH",
                @"\b(mysql|postgres|postgresql|mongodb|redis|jdbc:[a-z]+)://[^:\s]+:[^@\s]+@"),
            new("Azure Storage Key", "CLOUD", "CRITICAL",
                @"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
        };

        /// <summary>
        /// Kept for callers that only need the set of scannable extensions.
        /// </summary>
        public static HashSet<string> ScannableExtensions => SourceFiles.AllExtensions;
    }
}

from dataclasses import dataclass
from typing import List, Set, Optional


@dataclass(frozen=True)
class ConfigRule:
    name: str
    pattern: str
    severity: str
    category: str
    description: str
    extensions: Optional[Set[str]] = None


CONFIG_RULES: List[ConfigRule] = [
    ConfigRule("Debug Mode",
               r'(?i)debug\s*[=:]\s*(?:true|1|on|yes)|DEBUG\s*=\s*(?:True|1)',
               "MEDIUM", "CONFIG", "Debug mode enabled."),
    ConfigRule("CORS Wildcard",
               r'(?i)Access-Control-Allow-Origin.*\*',
               "MEDIUM", "CONFIG", "CORS wildcard allows any origin."),
    ConfigRule("SSL Verify Disabled",
               r'verify\s*=\s*False',
               "HIGH", "NETWORK", "SSL verification disabled."),
    ConfigRule("SSL Verify Disabled (Go)",
               r'TLSClientConfig.*InsecureSkipVerify\s*:\s*true',
               "HIGH", "NETWORK", "Go TLS verification disabled."),
    ConfigRule("Insecure HTTP",
               r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)',
               "LOW", "NETWORK", "HTTP instead of HTTPS."),
    ConfigRule("Version Disclosure",
               r'(?i)(?:X-Powered-By|Server)\s*[=:]\s*["\'][^"\']+["\']',
               "LOW", "INFO", "Server version disclosed."),
    ConfigRule("Directory Listing",
               r'(?i)Options\s*\+\s*Indexes',
               "MEDIUM", "CONFIG", "Directory listing enabled."),
    ConfigRule("CORS Origin Reflection",
               r'(?i)Access-Control-Allow-Origin.*req\.headers',
               "HIGH", "CONFIG", "CORS reflects origin - CSRF risk."),
    ConfigRule("Verbose Errors",
               r'(?i)(?:traceback\.print|e\.printStackTrace)',
               "LOW", "INFO", "Verbose error output."),
    ConfigRule("Info Disclosure (print secrets)",
               r'(?i)print\s*\(.*(?:password|token|secret|key|credential)',
               "HIGH", "INFO", "Sensitive data printed."),
    ConfigRule("Info Disclosure (console.log)",
               r'console\.log\s*\(.*(?:password|token|secret|key|credential)',
               "HIGH", "INFO", "Sensitive data logged."),
    ConfigRule("Mass Assignment (Rails)",
               r'(?:attr_accessible|permit!|params\[)',
               "MEDIUM", "LOGIC", "Rails mass assignment risk."),
    ConfigRule("Log Injection",
               r'(?i)(?:log|logger|logging)\.\w+\s*\(.*\+',
               "LOW", "INJECTION", "Log injection via concatenation."),
    ConfigRule("File Upload (Django)",
               r'FileField|ImageField',
               "LOW", "UPLOAD", "Django file field - validate uploads."),
]

SUSPICIOUS_FILES = {
    '.env': 'Hardcoded secrets in environment file.',
    '.env.local': 'Local env file with secrets.',
    '.env.production': 'Production secrets in plaintext.',
    '.env.staging': 'Staging secrets exposed.',
    '.env.development': 'Dev secrets exposed.',
    'config.json': 'May contain hardcoded API keys.',
    'config.yaml': 'May contain hardcoded credentials.',
    'config.yml': 'May contain hardcoded credentials.',
    'config.toml': 'May contain hardcoded credentials.',
    'config.ini': 'May contain hardcoded credentials.',
    'credentials.json': 'Plaintext credentials file.',
    'secrets.json': 'Secrets file in plaintext.',
    'database.yml': 'Database credentials exposed.',
    'database.json': 'Database credentials exposed.',
    'settings.json': 'May contain embedded secrets.',
    'settings.yaml': 'May contain embedded secrets.',
    '.htpasswd': 'Password file exposed.',
    '.htaccess': 'Access control exposed.',
    'id_rsa': 'SSH private key exposed.',
    'id_ed25519': 'SSH private key exposed.',
    'id_dsa': 'SSH private key exposed.',
    'docker-compose.override.yml': 'Docker secrets exposed.',
    'wp-config.php': 'WordPress DB credentials exposed.',
    '.npmrc': 'NPM auth tokens exposed.',
    '.pypirc': 'PyPI tokens exposed.',
    'kubeconfig': 'Kubernetes cluster access exposed.',
    'server.key': 'TLS private key exposed.',
    'application.yml': 'Spring config with secrets.',
    'application.properties': 'Spring config with secrets.',
    'web.config': 'IIS config may contain secrets.',
    'dump.sql': 'Database dump may contain sensitive data.',
    '.bash_history': 'Shell history may contain passwords.',
    '.zsh_history': 'Shell history may contain passwords.',
    '.mysql_history': 'MySQL history may contain passwords.',
    '.psql_history': 'PostgreSQL history may contain passwords.',
}

from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: str
    severity: str
    category: str
    description: str
    extensions: Optional[Set[str]] = None


SECRET_RULES: List[SecretRule] = [
    # ── AWS ──
    SecretRule("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CRITICAL", "CLOUD",
               "AWS access key - full cloud access if leaked."),
    SecretRule("AWS Secret Key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
               "CRITICAL", "CLOUD", "AWS secret key - complete AWS control."),
    SecretRule("AWS Session Token", r"(?i)aws_session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
               "CRITICAL", "CLOUD", "AWS session token."),

    # ── GCP ──
    SecretRule("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH", "CLOUD", "Google API key."),
    SecretRule("Google OAuth Secret", r"(?i)client_secret\s*[=:]\s*['\"]([A-Za-z0-9_\-]{24,})['\"]",
               "CRITICAL", "AUTH", "Google OAuth secret."),
    SecretRule("GCP Service Account", r'"type"\s*:\s*"service_account"', "HIGH", "CLOUD", "GCP service account key file."),

    # ── Azure ──
    SecretRule("Azure Connection String",
               r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
               "CRITICAL", "CLOUD", "Azure storage account key."),
    SecretRule("Azure SAS Token",
               r"(?i)sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}",
               "HIGH", "CLOUD", "Azure SAS token."),

    # ── Payment ──
    SecretRule("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}", "CRITICAL", "PAYMENT", "Stripe live secret key."),
    SecretRule("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}", "HIGH", "PAYMENT", "Stripe test key."),
    SecretRule("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "CRITICAL", "PAYMENT", "Stripe restricted key."),
    SecretRule("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "CRITICAL", "PAYMENT", "Square access token."),
    SecretRule("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "CRITICAL", "PAYMENT", "Square OAuth secret."),
    SecretRule("PayPal Client Secret", r"(?i)client_secret\s*[=:]\s*['\"]?A[A-Za-z0-9_\-]{50,}['\"]?",
               "CRITICAL", "PAYMENT", "PayPal client secret."),
    SecretRule("Braintree Access Token",
               r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
               "CRITICAL", "PAYMENT", "Braintree access token."),

    # ── VCS ──
    SecretRule("GitHub Token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
               "CRITICAL", "VCS", "GitHub personal access token."),
    SecretRule("GitHub Fine-Grained", r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59,}",
               "CRITICAL", "VCS", "GitHub fine-grained token."),
    SecretRule("GitLab Token", r"glpat-[A-Za-z0-9\-_]{20,}", "CRITICAL", "VCS", "GitLab personal access token."),
    SecretRule("GitLab Pipeline Token", r"glptt-[A-Za-z0-9\-_]{20,}", "HIGH", "VCS", "GitLab pipeline token."),

    # ── Cloud/Platform ──
    SecretRule("Heroku API Key",
               r"(?i)HEROKU_API_KEY\s*[=:]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
               "CRITICAL", "CLOUD", "Heroku API key."),

    # ── Chat ──
    SecretRule("Discord Bot Token", r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
               "CRITICAL", "CHAT", "Discord bot token."),
    SecretRule("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
               "HIGH", "CHAT", "Discord webhook URL."),
    SecretRule("Telegram Bot Token", r"[0-9]+:AA[A-Za-z0-9_-]{33}", "CRITICAL", "CHAT", "Telegram bot token."),
    SecretRule("Slack Bot Token", r"xoxb-[0-9]{11,}-[A-Za-z0-9]{24,}", "CRITICAL", "CHAT", "Slack bot token."),
    SecretRule("Slack User Token", r"xoxp-[0-9]{11,}-[A-Za-z0-9]{24,}", "HIGH", "CHAT", "Slack user token."),
    SecretRule("Slack Webhook",
               r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
               "HIGH", "CHAT", "Slack incoming webhook."),

    # ── Communications ──
    SecretRule("Twilio API Key", r"SK[A-Za-z0-9]{32}", "CRITICAL", "COMM", "Twilio API key."),
    SecretRule("Twilio Account SID", r"AC[a-f0-9]{32}", "HIGH", "COMM", "Twilio Account SID."),

    # ── Social ──
    SecretRule("Facebook Access Token", r"EAAG[A-Za-z0-9]{30,}", "HIGH", "SOCIAL", "Facebook access token."),
    SecretRule("Facebook App Secret", r"(?i)fb_app_secret\s*[=:]\s*['\"]([a-f0-9]{32})['\"]",
               "CRITICAL", "SOCIAL", "Facebook app secret."),
    SecretRule("Instagram Access Token", r"IGQV[A-Za-z0-9]{30,}", "HIGH", "SOCIAL", "Instagram access token."),

    # ── Package Registries ──
    SecretRule("NPM Token", r"npm_[A-Za-z0-9]{36}", "HIGH", "PACKAGE", "NPM auth token."),
    SecretRule("PyPI Token", r"pypi-[A-Za-z0-9_\-]{50,}", "CRITICAL", "PACKAGE", "PyPI upload token."),
    SecretRule("RubyGems API Key", r"rubygems_[a-f0-9]{48}", "CRITICAL", "PACKAGE", "RubyGems API key."),
    SecretRule("NuGet API Key", r"oy2[a-z0-9]{43}", "CRITICAL", "PACKAGE", "NuGet API key."),

    # ── AI ──
    SecretRule("OpenAI Key", r"sk-[A-Za-z0-9]{48,}", "CRITICAL", "AI", "OpenAI API key."),
    SecretRule("Anthropic Key", r"sk-ant-[A-Za-z0-9_\-]{40,}", "CRITICAL", "AI", "Anthropic API key."),
    SecretRule("Hugging Face Token", r"hf_[A-Za-z0-9]{34,}", "HIGH", "AI", "Hugging Face token."),
    SecretRule("Replicate Token", r"r8_[A-Za-z0-9]{40}", "HIGH", "AI", "Replicate API token."),
    SecretRule("Groq API Key", r"gsk_[A-Za-z0-9]{20,}", "CRITICAL", "AI", "Groq API key."),
    SecretRule("xAI API Key", r"xai-[A-Za-z0-9]{20,}", "CRITICAL", "AI", "xAI (Grok) API key."),
    SecretRule("Perplexity API Key", r"pplx-[a-f0-9]{40,}", "HIGH", "AI", "Perplexity API key."),
    SecretRule("Mistral API Key", r"(?i)mistral[_-]?api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9]{24,})['\"]",
               "CRITICAL", "AI", "Mistral API key."),
    SecretRule("DeepSeek API Key", r"sk-(?:proj|none)-[A-Za-z0-9_\-]{20,}|deepseek[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
               "CRITICAL", "AI", "DeepSeek/OpenAI project key."),

    # ── Cloud platforms ──
    SecretRule("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "CRITICAL", "CLOUD", "DigitalOcean personal token."),
    SecretRule("Shopify Access Token", r"shp(?:at|ca|pa)_[a-fA-F0-9]{32}", "CRITICAL", "CLOUD", "Shopify access token."),
    SecretRule("Stripe Webhook Secret", r"whsec_[A-Za-z0-9]{24,}", "CRITICAL", "PAYMENT", "Stripe webhook signing secret."),
    SecretRule("Databricks Token", r"dapi[a-f0-9]{32}", "HIGH", "CLOUD", "Databricks API token."),
    SecretRule("Heroku Platform Token", r"heroku_[0-9a-zA-Z]{32}|hxgt-[0-9a-zA-Z\-]{36}", "CRITICAL", "CLOUD", "Heroku platform token."),
    SecretRule("Notion Integration Token", r"secret_[A-Za-z0-9]{43}", "HIGH", "CLOUD", "Notion integration secret."),
    SecretRule("Linear API Key", r"lin_api_(?:live|test)_[A-Za-z0-9]{40}", "CRITICAL", "CLOUD", "Linear API key."),

    # ── Email ──
    SecretRule("SendGrid Key", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "CRITICAL", "EMAIL", "SendGrid API key."),
    SecretRule("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "HIGH", "EMAIL", "Mailgun API key."),
    SecretRule("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "HIGH", "EMAIL", "Mailchimp API key."),

    # ── Database ──
    SecretRule("MySQL Connection",
               r"(?i)(mysql|jdbc:mysql|mysqli)://[^:]+:[^@]+@[^:]+:[0-9]+/[^\s]+",
               "CRITICAL", "DATABASE", "MySQL connection string with credentials."),
    SecretRule("PostgreSQL Connection",
               r"(?i)(postgres|postgresql)://[^:]+:[^@]+@[^:]+:[0-9]+/[^\s]+",
               "CRITICAL", "DATABASE", "PostgreSQL connection string."),
    SecretRule("MongoDB Connection", r"(?i)mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+",
               "CRITICAL", "DATABASE", "MongoDB connection with credentials."),
    SecretRule("Redis Connection", r"(?i)redis://[^:]+:[^@]+@[^\s]+",
               "HIGH", "DATABASE", "Redis connection with password."),

    # ── Crypto/Keys ──
    SecretRule("Private Key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
               "CRITICAL", "CRYPTO", "Private key exposed."),
    SecretRule("JWT Token", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
               "HIGH", "AUTH", "JWT token in code."),
    SecretRule("Basic Auth", r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",
               "HIGH", "AUTH", "Basic auth header (base64 credentials)."),

    # ── Generic Credentials ──
    SecretRule("API Secret", r"(?i)api[\-_ ]*secret\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "CRITICAL", "CRYPTO", "API secret key."),
    SecretRule("API Key", r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
               "HIGH", "CRYPTO", "API key in code."),
    SecretRule("Password Assignment",
               r"(?i)(password|passwd|pwd|pass)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
               "CRITICAL", "AUTH", "Hardcoded password."),
    SecretRule("Secret Key", r"(?i)(secret|secret_key|secretkey)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "HIGH", "CRYPTO", "Hardcoded secret key."),
    SecretRule("Access Token", r"(?i)(access_token|accesstoken)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "HIGH", "AUTH", "Hardcoded access token."),
    SecretRule("Encryption Key",
               r"(?i)(encryption[\-_ ]*key|encrypt[\-_ ]*key|cipher[\-_ ]*key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "CRITICAL", "CRYPTO", "Hardcoded encryption key."),
    SecretRule("Signing Key",
               r"(?i)(signing[\-_ ]*key|sign[\-_ ]*key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "CRITICAL", "CRYPTO", "Hardcoded signing key."),
    SecretRule("Master Key", r"(?i)master[\-_ ]*key\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
               "CRITICAL", "CRYPTO", "Hardcoded master key."),
    SecretRule("DB Password",
               r"(?i)(db_|database_|mysql_|postgres_|mongo_|redis_)?password\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
               "CRITICAL", "DATABASE", "Database password in code."),
    SecretRule("Hardcoded Credential",
               r"(?i)(?:username|user|login)\s*[=:]\s*[\'\"][^\'\"]{3,}[\'\"]",
               "MEDIUM", "AUTH", "Hardcoded username."),
]

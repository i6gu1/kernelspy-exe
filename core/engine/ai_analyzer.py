"""
AI Integration module for KernelSpy Scanner.
Supports Google AI Studio API and local GGUF models via llama-cpp-python.
"""
import json
import os
import threading
import time
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field


@dataclass
class AIConfig:
    """Configuration for AI integration."""
    provider: str = "google"  # "google" or "gguf"
    google_api_key: str = ""
    google_model: str = "gemini-2.0-flash"
    gguf_model_path: str = ""
    gguf_n_ctx: int = 4096
    gguf_n_threads: int = 4
    temperature: float = 0.2
    max_tokens: int = 2048


@dataclass
class ChatMessage:
    """A single chat message."""
    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class AIResponse:
    """Response from AI analysis."""
    success: bool
    content: str = ""
    error: str = ""
    provider: str = ""
    model: str = ""
    tokens_used: int = 0


class GoogleAIAnalyzer:
    """Google AI Studio (Gemini) integration."""

    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    SYSTEM_PROMPT = """You are an expert cybersecurity AI assistant integrated into KernelSpy Scanner.
Your role is to analyze code for security vulnerabilities and provide actionable remediation advice.

When analyzing code:
1. Identify all security vulnerabilities (injection, XSS, SSRF, deserialization, etc.)
2. Rate severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Provide specific fix suggestions with code examples
4. Explain the root cause of each vulnerability

Be concise, accurate, and focus on actionable security findings."""

    def __init__(self, config: AIConfig):
        self.config = config

    @property
    def available(self) -> bool:
        return bool(self.config.google_api_key)

    def _make_request(self, payload: dict) -> AIResponse:
        """Make a request to the Google AI Studio API."""
        if not self.available:
            return AIResponse(
                success=False,
                error="Google AI API key not configured",
                provider="google"
            )

        try:
            import urllib.request
            import urllib.error

            url = self.API_URL.format(
                model=self.config.google_model,
                api_key=self.config.google_api_key
            )

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            content = ""
            for candidate in data.get('candidates', []):
                for part in candidate.get('content', {}).get('parts', []):
                    content += part.get('text', '')

            usage = data.get('usageMetadata', {})

            return AIResponse(
                success=True,
                content=content,
                provider="google",
                model=self.config.google_model,
                tokens_used=usage.get('totalTokenCount', 0),
            )

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode('utf-8')
                error_data = json.loads(error_body)
                error_body = error_data.get('error', {}).get('message', error_body)
            except Exception:
                pass
            return AIResponse(
                success=False,
                error=f"API Error {e.code}: {error_body}",
                provider="google"
            )
        except Exception as e:
            return AIResponse(
                success=False,
                error=str(e),
                provider="google"
            )

    def analyze_code(self, code: str, language: str = "",
                     context: str = "") -> AIResponse:
        """Analyze code for vulnerabilities using Gemini."""
        prompt = f"""Analyze the following {language} code for security vulnerabilities.

{f'Context: {context}' if context else ''}

Code to analyze:
```{language}
{code[:8000]}
```

Provide:
1. List of vulnerabilities found (with line numbers if possible)
2. Severity rating for each
3. Specific fix suggestions with code examples
4. Overall security assessment"""

        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": prompt}]}
            ],
            "systemInstruction": {
                "parts": [{"text": self.SYSTEM_PROMPT}]
            },
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            }
        }

        return self._make_request(payload)

    def chat(self, messages: List[ChatMessage]) -> AIResponse:
        """Chat with Gemini about code security."""
        if not self.available:
            return AIResponse(
                success=False,
                error="Google AI API key not configured",
                provider="google"
            )

        contents = []
        for msg in messages:
            if msg.role == "system":
                continue
            contents.append({
                "role": "model" if msg.role == "assistant" else "user",
                "parts": [{"text": msg.content}]
            })

        system_msg = next((m for m in messages if m.role == "system"), None)

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            }
        }

        if system_msg:
            payload["systemInstruction"] = {
                "parts": [{"text": system_msg.content}]
            }

        return self._make_request(payload)


class GGUFAnalyzer:
    """Local GGUF model integration via llama-cpp-python."""

    SYSTEM_PROMPT = """You are an expert cybersecurity AI assistant integrated into KernelSpy Scanner.
Analyze code for security vulnerabilities and provide actionable remediation advice.
Be concise and focus on critical security issues."""

    def __init__(self, config: AIConfig):
        self.config = config
        self._llm = None
        self._loading = False
        self._load_error = ""

    @property
    def available(self) -> bool:
        try:
            from llama_cpp import Llama
            return True
        except ImportError:
            return False

    @property
    def model_loaded(self) -> bool:
        return self._llm is not None

    @property
    def loading(self) -> bool:
        return self._loading

    @property
    def load_error(self) -> str:
        return self._load_error

    def load_model(self, model_path: str, callback: Optional[Callable] = None) -> bool:
        """Load a GGUF model in a background thread."""
        if self._loading:
            return False

        if not os.path.exists(model_path):
            self._load_error = f"Model file not found: {model_path}"
            return False

        self._loading = True
        self._load_error = ""

        def _load():
            try:
                from llama_cpp import Llama
                self._llm = Llama(
                    model_path=model_path,
                    n_ctx=self.config.gguf_n_ctx,
                    n_threads=self.config.gguf_n_threads,
                    verbose=False,
                )
                self._loading = False
                if callback:
                    callback(True, "Model loaded successfully")
            except Exception as e:
                self._loading = False
                self._load_error = str(e)
                if callback:
                    callback(False, str(e))

        t = threading.Thread(target=_load, daemon=True)
        t.start()
        return True

    def unload_model(self):
        """Unload the current model to free memory."""
        self._llm = None
        import gc
        gc.collect()

    def analyze_code(self, code: str, language: str = "",
                     context: str = "") -> AIResponse:
        """Analyze code using the local GGUF model."""
        if not self.available:
            return AIResponse(
                success=False,
                error="llama-cpp-python not installed. Run: pip install llama-cpp-python",
                provider="gguf"
            )

        if not self._llm:
            return AIResponse(
                success=False,
                error="No model loaded. Please load a GGUF model first.",
                provider="gguf"
            )

        try:
            prompt = f"""{self.SYSTEM_PROMPT}

Analyze the following {language} code for security vulnerabilities:

```{language}
{code[:4096]}
```

Provide:
1. Vulnerabilities found
2. Severity for each
3. Fix suggestions"""

            response = self._llm(
                prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                stop=["```", "\n\n\n"],
            )

            content = response['choices'][0]['text'] if response.get('choices') else ""

            return AIResponse(
                success=True,
                content=content,
                provider="gguf",
                model=os.path.basename(self.config.gguf_model_path),
            )

        except Exception as e:
            return AIResponse(
                success=False,
                error=str(e),
                provider="gguf"
            )

    def chat(self, messages: List[ChatMessage]) -> AIResponse:
        """Chat with the local model about code security."""
        if not self.available:
            return AIResponse(
                success=False,
                error="llama-cpp-python not installed",
                provider="gguf"
            )

        if not self._llm:
            return AIResponse(
                success=False,
                error="No model loaded",
                provider="gguf"
            )

        try:
            formatted_messages = []
            for msg in messages:
                role = "assistant" if msg.role == "assistant" else "user"
                formatted_messages.append({"role": role, "content": msg.content})

            response = self._llm.create_chat_completion(
                messages=formatted_messages,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
            )

            content = ""
            if response.get('choices'):
                content = response['choices'][0].get('message', {}).get('content', '')

            return AIResponse(
                success=True,
                content=content,
                provider="gguf",
                model=os.path.basename(self.config.gguf_model_path),
            )

        except Exception as e:
            return AIResponse(
                success=False,
                error=str(e),
                provider="gguf"
            )


class AIAnalyzer:
    """Unified AI analyzer that manages both Google and GGUF providers."""

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self._google = GoogleAIAnalyzer(self.config)
        self._gguf = GGUFAnalyzer(self.config)
        self._chat_history: List[ChatMessage] = []

    @property
    def google(self) -> GoogleAIAnalyzer:
        return self._google

    @property
    def gguf(self) -> GGUFAnalyzer:
        return self._gguf

    @property
    def active_provider(self) -> str:
        """Get the currently active provider."""
        if self.config.provider == "gguf" and self._gguf.model_loaded:
            return "gguf"
        elif self.config.provider == "google" and self._google.available:
            return "google"
        elif self._gguf.model_loaded:
            return "gguf"
        elif self._google.available:
            return "google"
        return "none"

    @property
    def chat_history(self) -> List[ChatMessage]:
        return list(self._chat_history)

    def clear_history(self):
        """Clear chat history."""
        self._chat_history.clear()

    def analyze_code(self, code: str, language: str = "",
                     context: str = "") -> AIResponse:
        """Analyze code using the active provider."""
        provider = self.active_provider
        if provider == "gguf":
            return self._gguf.analyze_code(code, language, context)
        elif provider == "google":
            return self._google.analyze_code(code, language, context)
        return AIResponse(
            success=False,
            error="No AI provider available. Configure Google API key or load a GGUF model.",
            provider="none"
        )

    def chat(self, message: str) -> AIResponse:
        """Send a chat message and get a response."""
        # Add system prompt if first message
        if not self._chat_history:
            self._chat_history.append(ChatMessage(
                role="system",
                content=GoogleAIAnalyzer.SYSTEM_PROMPT
            ))

        # Add user message
        self._chat_history.append(ChatMessage(role="user", content=message))

        provider = self.active_provider
        if provider == "gguf":
            response = self._gguf.chat(self._chat_history)
        elif provider == "google":
            response = self._google.chat(self._chat_history)
        else:
            return AIResponse(
                success=False,
                error="No AI provider available",
                provider="none"
            )

        if response.success:
            self._chat_history.append(ChatMessage(
                role="assistant",
                content=response.content
            ))

        return response

    def analyze_findings(self, findings: list) -> AIResponse:
        """Analyze scan findings and provide AI-powered insights."""
        if not findings:
            return AIResponse(
                success=False,
                error="No findings to analyze",
                provider=self.active_provider
            )

        # Build a summary of findings
        summary_lines = []
        for f in findings[:20]:  # Limit to first 20 findings
            summary_lines.append(
                f"- [{f.severity}] {f.type} in {f.file}:{f.line} - {f.description[:100]}"
            )

        findings_text = "\n".join(summary_lines)

        prompt = f"""Analyze these security scan findings and provide:

1. **Priority Summary**: Which findings are most critical and why?
2. **Common Patterns**: Are there recurring vulnerability patterns?
3. **Remediation Plan**: Step-by-step fix recommendations ordered by priority.
4. **Root Cause Analysis**: What systemic issues might these findings indicate?

Findings ({len(findings)} total):
{findings_text}

{"... and " + str(len(findings) - 20) + " more findings" if len(findings) > 20 else ""}"""

        return self.chat(prompt)


# Global singleton
_ai_analyzer: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    """Get or create the global AI analyzer."""
    global _ai_analyzer
    if _ai_analyzer is None:
        _ai_analyzer = AIAnalyzer()
    return _ai_analyzer

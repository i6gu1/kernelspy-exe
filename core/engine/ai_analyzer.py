"""
AI Integration module for KernelSpy Scanner.
Supports Google AI Studio API and local GGUF models via llama-cpp-python.

KernelSpy 1.3:
  * the API key is actually sent with every request (1.2 built the URL
    without it, so every call failed with "API key not valid"),
  * ``AIAnalyzer.config`` propagates to both providers (in 1.2 the UI
    updated the wrapper but the Google client kept the old empty config),
  * the provider is optional - without a key the built-in analyzers keep
    working exactly as before,
  * clear, actionable error messages + a ``test_connection()`` probe.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field


# Default model: the stable alias that always points at Google's current
# Flash model.  "gemini-2.0-flash" was retired for new projects, which made
# every request fail with "model not found" (KernelSpy 1.3.1).
DEFAULT_MODEL = "gemini-flash-latest"

# Tried in order when the configured model is not available to this key.
MODEL_FALLBACKS = (
    "gemini-flash-latest",
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
)

# Chat history window.  A session that kept growing was rejected by the API
# with HTTP 400 "input token limit exceeded" - the history is now trimmed
# (oldest turn first, the system prompt is always kept).
MAX_HISTORY_MESSAGES = 40
MAX_HISTORY_CHARS = 24000
# headroom kept for the assistant reply the current turn will produce
# (max_tokens 2048 ~= 8 KB worst case)
RESPONSE_RESERVE_CHARS = 8000


def _is_region_block(code: int, body: str) -> bool:
    """True when Google answered with the 'this country is not supported'
    precondition - a geography block, not a bad model name or a bad key."""
    low = (body or '').lower()
    if 'location is not supported' in low:
        return True
    return 'failed_precondition' in low and 'location' in low


@dataclass
class AIConfig:
    """Configuration for AI integration."""
    provider: str = "google"  # "google" or "gguf"
    google_api_key: str = ""
    google_model: str = DEFAULT_MODEL
    google_api_base: str = ""   # override endpoint (relay/gateway); "" = Google
    proxy_url: str = ""         # HTTP(S) proxy, e.g. http://127.0.0.1:7890
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
        # why the /models list could not be fetched ("" = fine / unknown)
        self.last_list_error: str = ""

    @property
    def region_blocked(self) -> bool:
        """True when the API answers with the geography precondition."""
        return _is_region_block(0, (self.last_list_error or "").lower())

    @property
    def api_key(self) -> str:
        """Configured key, falling back to the standard environment vars."""
        key = (getattr(self.config, 'google_api_key', '') or '').strip()
        if not key:
            key = (os.environ.get('GEMINI_API_KEY')
                   or os.environ.get('GOOGLE_API_KEY')
                   or os.environ.get('GOOGLE_AI_API_KEY') or '').strip()
        return key

    @property
    def _base_url(self) -> str:
        """Effective API root - custom relay/gateway or the Google default."""
        custom = (getattr(self.config, 'google_api_base', '') or '').strip().rstrip('/')
        if custom:
            return custom
        return "https://generativelanguage.googleapis.com"

    def _opener(self) -> 'urllib.request.OpenerDirector':
        """Opener that honours an explicit proxy (VPN/proxy users)."""
        proxy = (getattr(self.config, 'proxy_url', '') or '').strip()
        if proxy:
            handler = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
            return urllib.request.build_opener(handler)
        return urllib.request.build_opener()

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    @property
    def model(self) -> str:
        name = (getattr(self.config, 'google_model', '') or DEFAULT_MODEL).strip()
        name = name.split('/')[-1]           # accept "models/gemini-flash-latest"
        return name or DEFAULT_MODEL

    def _available_models(self) -> Optional[List[str]]:
        """generateContent-capable models this key may use (None = could not list)."""
        url = (f"{self._base_url}/v1beta/models"
               "?pageSize=200")
        req = urllib.request.Request(url, method='GET',
                                     headers={'x-goog-api-key': self.api_key})
        try:
            with self._opener().open(req, timeout=20) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            self.last_list_error = ""
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode('utf-8')
                err = json.loads(raw)
                self.last_list_error = err.get('error', {}).get('message', raw)
            except Exception:
                self.last_list_error = str(e)
            return None
        except Exception as e:
            self.last_list_error = str(e)
            return None
        names = []
        for m in data.get('models', []) or []:
            name = (m.get('name') or '').split('/')[-1]
            if not name:
                continue
            methods = (m.get('supportedGenerationMethods')
                       or m.get('supportedActions') or [])
            if methods and 'generateContent' not in methods:
                continue
            names.append(name)
        return names or None

    def list_models(self) -> List[str]:
        """Model selector data: every generateContent model this key can use.

        Falls back to the built-in catalogue when the list cannot be fetched
        (offline / rate-limited), so the dropdown is never empty.
        """
        names = self._available_models()
        if names:
            seen = set()
            out: List[str] = []
            for n in names:
                if n and n not in seen:
                    seen.add(n)
                    out.append(n)
            return out
        return list(MODEL_FALLBACKS)

    def _pick_fallback(self, failed_model: str) -> Optional[str]:
        """Choose a model the key can actually use after 'model not found'."""
        tried = {failed_model}
        available = self._available_models()
        if available:
            aset = set(available)
            for cand in MODEL_FALLBACKS:
                if cand in aset and cand not in tried:
                    return cand
            for name in available:            # any usable Flash-class model
                if name in tried or not name.startswith('gemini-'):
                    continue
                if 'flash' in name and 'image' not in name and 'audio' not in name:
                    return name
            for name in available:
                if name not in tried and name.startswith('gemini-'):
                    return name
            return None                       # key sees nothing usable
        for cand in MODEL_FALLBACKS:          # models list unavailable (offline)
            if cand not in tried:
                return cand
        return None

    def _make_request(self, payload: dict, model: Optional[str] = None,
                      timeout: int = 60, allow_fallback: bool = True) -> AIResponse:
        """Make a request to the Google AI Studio API (key is always sent)."""
        if not self.available:
            return AIResponse(
                success=False,
                error="Google AI API key not configured. Paste your key in the "
                      "AI Chat page and press Save - or leave AI off and use "
                      "the built-in analyzers.",
                provider="google"
            )

        model = model or self.model

        # Gemini 3.x rejects the deprecated sampling parameters (temp/top_p).
        cfg = payload.get('generationConfig')
        if isinstance(cfg, dict) and model.startswith('gemini-3'):
            for key in ('temperature', 'top_p', 'top_k'):
                cfg.pop(key, None)

        url = f"{self._base_url}/v1beta/models/{model}:generateContent"

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'x-goog-api-key': self.api_key,     # <- 1.2 never sent this
            },
            method='POST'
        )

        try:
            with self._opener().open(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            content = ""
            for candidate in data.get('candidates', []):
                for part in candidate.get('content', {}).get('parts', []):
                    if part.get('thought'):     # Gemini 3.x reasoning trace
                        continue
                    content += part.get('text', '')

            usage = data.get('usageMetadata', {})
            served = data.get('modelVersion') or model
            if not content:
                return AIResponse(
                    success=False,
                    error="The model returned an empty response. Try again or "
                          "pick another model.",
                    provider="google", model=served,
                )

            return AIResponse(
                success=True,
                content=content,
                provider="google",
                model=served,
                tokens_used=usage.get('totalTokenCount', 0),
            )

        except urllib.error.HTTPError as e:
            # Transient failures (rate limit / gateway hiccups): retry once
            # before reporting an error to the user.
            if allow_fallback and e.code in (429, 500, 502, 503, 504):
                time.sleep(1.5)
                return self._make_request(payload, model, timeout,
                                          allow_fallback=False)

            body = ""
            try:
                raw = e.read().decode('utf-8')
                err = json.loads(raw)
                body = err.get('error', {}).get('message', raw)
            except Exception:
                body = str(e)

            low = body.lower()
            # Region block first: the Generative Language API is not offered
            # in every country.  The message contains "not supported", which
            # the model-missing check below would happily match - that used
            # to burn every fallback candidate and end with a misleading
            # "the model X is not available for this API key".
            if _is_region_block(e.code, low):
                return AIResponse(
                    success=False,
                    error=("Google AI is blocked from your region "
                           f"(HTTP {e.code}: {body[:120]}). Either connect "
                           "through a VPN, or load a local GGUF model in the "
                           "AI Chat page - the built-in scanners keep working "
                           "without any AI provider."),
                    provider="google", model=model,
                )

            missing = (e.code == 404 or (e.code == 400 and (
                'not found' in low or 'unknown model' in low
                or 'is no longer available' in low or 'has been retired' in low
                or ('model' in low and 'not supported' in low))))

            # Model not offered to this key (e.g. retired gemini-2.0-flash):
            # ask the API which models the key can use and retry with one.
            if missing and allow_fallback:
                alt = self._pick_fallback(model)
                if alt:
                    try:
                        self.config.google_model = alt   # remember what works
                    except Exception:
                        pass
                    return self._make_request(payload, alt, timeout,
                                              allow_fallback=False)

            if missing:
                msg = (f"The model '{model}' is not available for this API key. "
                       "Open the AI Chat page, press Test to auto-select a model "
                       f"(or Save a supported one). API said: {body[:160]}")
            elif e.code in (400, 401, 403):
                msg = (f"Authentication failed (HTTP {e.code}): {body[:160]} "
                       "- check that the API key is correct and enabled for the "
                       "Generative Language API.")
            elif e.code == 429:
                msg = "Rate limit reached (HTTP 429). Wait a moment and retry."
            else:
                msg = f"API error {e.code}: {body[:200]}"
            return AIResponse(success=False, error=msg, provider="google",
                              model=model)

        except urllib.error.URLError as e:
            reason = getattr(e, 'reason', e)
            return AIResponse(
                success=False,
                error=f"Network error while reaching the Google AI API: {reason}. "
                      "Check your internet connection (the app keeps working "
                      "without AI).",
                provider="google", model=model,
            )
        except TimeoutError:
            return AIResponse(
                success=False,
                error="The AI request timed out. Try again.",
                provider="google", model=model,
            )
        except Exception as e:
            return AIResponse(success=False, error=str(e), provider="google",
                              model=model)

    def test_connection(self) -> AIResponse:
        """Cheap probe used by the UI 'Test key' button."""
        payload = {
            "contents": [{"role": "user", "parts": [{"text": "Reply with OK"}]}],
            # Reasoning models spend output tokens on their thought trace, so
            # 8 tokens could come back empty and look like a broken key.
            "generationConfig": {"temperature": 0.0, "maxOutputTokens": 64},
        }
        return self._make_request(payload, timeout=30)

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
                # keep the system role - dropping it to "user" weakened the
                # local model's instructions on every turn
                role = msg.role if msg.role in ("system", "user", "assistant") else "user"
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
        self._config = config or AIConfig()
        self._google = GoogleAIAnalyzer(self._config)
        self._gguf = GGUFAnalyzer(self._config)
        self._chat_history: List[ChatMessage] = []

    @property
    def config(self) -> AIConfig:
        return self._config

    @config.setter
    def config(self, value: AIConfig):
        # 1.2 bug: the UI assigned a new AIConfig to this wrapper but both
        # provider clients kept the old (empty) object, so a saved key was
        # never used.  The setter keeps every client on the same instance.
        self._config = value or AIConfig()
        self._google.config = self._config
        self._gguf.config = self._config

    @property
    def google(self) -> GoogleAIAnalyzer:
        return self._google

    @property
    def gguf(self) -> GGUFAnalyzer:
        return self._gguf

    @property
    def active_provider(self) -> str:
        """Get the currently active provider."""
        if getattr(self._config, 'provider', 'google') in ('none', '', None):
            return "none"                      # AI explicitly switched off
        if self._config.provider == "gguf" and self._gguf.model_loaded:
            return "gguf"
        if self._config.provider == "google" and self._google.available:
            return "google"
        if self._gguf.model_loaded:
            return "gguf"
        if self._google.available:
            return "google"
        return "none"

    def test_connection(self) -> AIResponse:
        """Probe the active provider (used by the UI 'Test' button)."""
        provider = self.active_provider
        if provider == "google":
            return self._google.test_connection()
        if provider == "gguf":
            if self._gguf.model_loaded:
                return AIResponse(success=True, provider="gguf",
                                  model=os.path.basename(self._config.gguf_model_path),
                                  content="Local GGUF model is loaded.")
            return AIResponse(success=False, provider="gguf",
                              error="No GGUF model loaded. Choose a .gguf file first.")
        return AIResponse(
            success=False, provider="none",
            error="No AI provider active. Paste a Google API key or load a "
                  "local GGUF model (AI is optional).",
        )

    @property
    def chat_history(self) -> List[ChatMessage]:
        return list(self._chat_history)

    def clear_history(self):
        """Clear chat history."""
        self._chat_history.clear()

    def _trim_history(self, reserve_msgs: int = 0,
                      reserve_chars: int = 0) -> None:
        """Keep the chat window inside the model's input-token budget.

        An unbounded history eventually makes the API reject the request with
        HTTP 400 "input token limit exceeded"; the oldest turns are dropped
        first, the system prompt is never dropped, and the window never
        starts with an assistant turn (models reject that shape).

        ``reserve_msgs`` / ``reserve_chars`` keep room for the turn that is
        about to be appended, so the stored history itself stays in budget.
        """
        hist = self._chat_history
        if not hist:
            return
        start = 1 if hist[0].role == "system" else 0
        sys_chars = len(hist[0].content or "") if start else 0
        body = hist[start:]
        # the system prompt is part of the request too, so it is counted
        total = sys_chars + sum(len(m.content or "") for m in body)
        changed = False
        while body and (start + len(body) + reserve_msgs > MAX_HISTORY_MESSAGES
                        or total + reserve_chars > MAX_HISTORY_CHARS):
            total -= len(body[0].content or "")
            body.pop(0)
            changed = True
        while body and body[0].role == "assistant":
            total -= len(body[0].content or "")
            body.pop(0)
            changed = True
        if changed:
            self._chat_history = hist[:start] + body

    def _request_once(self, prompt: str) -> AIResponse:
        """Stateless one-shot request (never touches the chat history)."""
        provider = self.active_provider
        messages = [
            ChatMessage(role="system", content=GoogleAIAnalyzer.SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt),
        ]
        if provider == "google":
            return self._google.chat(messages)
        if provider == "gguf":
            return self._gguf.chat(messages)
        return AIResponse(
            success=False,
            error="No AI provider available. Paste a Google API key or load "
                  "a local GGUF model, then try again.",
            provider="none",
        )

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
        # Reject a paste that cannot fit the budget even with an empty
        # history - otherwise every provider answers HTTP 400 and the
        # turn is lost with a confusing error.
        if len(message or "") > MAX_HISTORY_CHARS - RESPONSE_RESERVE_CHARS:
            return AIResponse(
                success=False,
                error=(f"Message too long ({len(message)} chars). Keep it "
                       f"under {MAX_HISTORY_CHARS - RESPONSE_RESERVE_CHARS} "
                       "characters, or attach the code as a file instead."),
                provider=self.active_provider,
            )

        # Add system prompt if first message
        if not self._chat_history:
            self._chat_history.append(ChatMessage(
                role="system",
                content=GoogleAIAnalyzer.SYSTEM_PROMPT
            ))

        # Enforce the history window before the new turn is appended, keeping
        # room for this message and the reply it will produce, so the request
        # always fits the model's input token budget.
        self._trim_history(reserve_msgs=2,
                           reserve_chars=len(message) + RESPONSE_RESERVE_CHARS)

        # Add user message
        self._chat_history.append(ChatMessage(role="user", content=message))

        provider = self.active_provider
        if provider == "gguf":
            response = self._gguf.chat(self._chat_history)
        elif provider == "google":
            response = self._google.chat(self._chat_history)
        else:
            # Roll the pending message back so a later retry does not stack
            # duplicate copies in the history.
            if self._chat_history and self._chat_history[-1].role == "user":
                self._chat_history.pop()
            return AIResponse(
                success=False,
                error="No AI provider available. Paste a Google API key or "
                      "load a GGUF model, then try again.",
                provider="none"
            )

        if response.success:
            self._chat_history.append(ChatMessage(
                role="assistant",
                content=response.content
            ))
        elif self._chat_history and self._chat_history[-1].role == "user":
            self._chat_history.pop()

        return response

    def analyze_findings(self, findings: list) -> AIResponse:
        """Analyze scan findings and provide AI-powered insights.

        Stateless on purpose: the answer is *not* appended to the chat
        history, so analyzing a report can no longer pollute (and quickly
        exhaust the context window of) the AI Chat conversation.
        """
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

        return self._request_once(prompt)


# Global singleton
_ai_analyzer: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    """Get or create the global AI analyzer."""
    global _ai_analyzer
    if _ai_analyzer is None:
        _ai_analyzer = AIAnalyzer()
    return _ai_analyzer

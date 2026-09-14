"""OpenAI-compatible provider (Phase 5).

This is the only module in SentinelForge that talks to the internet, and it
does exactly one thing: post two prompts to a chat-completions endpoint and
return the text that comes back.  No tools are declared, no functions are
exposed, and nothing in the response is executed -- it is parsed and validated
like any other untrusted input.

Transport
---------
The official ``openai`` SDK is used when it is installed
(``pip install sentinelforge[llm]``).  SentinelForge otherwise has *no* runtime
dependencies, and refusing to run without an optional SDK would be a poor trade
for a tool that must keep working on a locked-down host, so there is a small
standard-library fallback over ``urllib`` that speaks the same REST API.  The
SDK is preferred whenever it is importable; the fallback exists so the feature
degrades instead of disappearing.

Because the endpoint is configurable, this provider also covers the many
OpenAI-compatible APIs (local servers and gateways) -- point
``SENTINELFORGE_LLM_BASE_URL`` at one.

Configuration comes from the environment (see :mod:`sentinelforge.ai.client`).
The API key is never logged, never written to an incident, and never included
in an error message.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from . import (
    LLMProvider,
    ProviderAuthError,
    ProviderConfigurationError,
    ProviderConnectionError,
    ProviderRateLimitError,
    ProviderResponse,
    ProviderResponseError,
    ProviderTimeoutError,
)
from ..schemas import response_json_schema

LOGGER = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.openai.com/v1"

#: Name of the structured-output schema sent to the API.
SCHEMA_NAME = "sentinelforge_incident_analysis"


def _import_sdk():
    """Return the ``openai`` module, or ``None`` when it is not installed."""
    try:
        import openai  # type: ignore
    except ImportError:
        return None
    return openai


class OpenAIProvider(LLMProvider):
    """Calls an OpenAI-compatible chat-completions endpoint.

    Args:
        model: Model id.  Required, and never defaulted: hard-coding a model
            name guarantees it is wrong eventually, so the user configures it
            through ``SENTINELFORGE_LLM_MODEL``.
        api_key: Credential.  Missing keys raise :class:`ProviderAuthError`
            with a message that names the environment variable, never the key.
        base_url: API root, for OpenAI-compatible endpoints.
        timeout: Per-request timeout in seconds.
        temperature: Kept at 0 so the same incident tends to produce the same
            reading; models are not guaranteed deterministic even so.
        sdk: Injected ``openai`` module (tests).  ``None`` imports the real one.
        transport: Injected callable used by the fallback path (tests). Signature
            ``(url, payload: dict, headers: dict, timeout: float) -> dict``.
    """

    name = "openai"
    is_mock = False

    def __init__(
        self,
        model: str | None,
        api_key: str | None,
        base_url: str | None = None,
        timeout: float = 60.0,
        temperature: float = 0.0,
        sdk=None,
        transport=None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = float(timeout)
        self.temperature = float(temperature)
        self._sdk = sdk
        self._transport = transport

    @classmethod
    def from_config(cls, config) -> "OpenAIProvider":
        return cls(
            model=config.model,
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=config.timeout,
        )

    # -- introspection -----------------------------------------------------
    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    def describe(self) -> dict:
        """Configuration summary.  Reports only *whether* a key is present."""
        return {
            "provider": self.name,
            "model": self.model or "(not configured)",
            "is_mock": False,
            "base_url": self.base_url,
            "api_key": "configured" if self.has_api_key else "MISSING",
            "transport": "openai SDK" if _import_sdk() else "urllib (SDK not installed)",
            "timeout_seconds": self.timeout,
        }

    # -- the one operation -------------------------------------------------
    def analyze(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Send the prompts and return the raw text of the model's reply."""
        self._require_configuration()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        sdk = self._sdk if self._sdk is not None else _import_sdk()
        if sdk is not None:
            text, usage = self._call_sdk(sdk, messages)
        else:
            text, usage = self._call_http(messages)
        if not text or not text.strip():
            raise ProviderResponseError("provider returned an empty message")
        return ProviderResponse(
            text=text, provider=self.name, model=self.model or "", is_mock=False, usage=usage
        )

    def _require_configuration(self) -> None:
        if not self.model:
            raise ProviderConfigurationError(
                "no model configured for the 'openai' provider",
                remedy="Set SENTINELFORGE_LLM_MODEL to a model your account can use, "
                "or pass --model.",
            )
        if not self._api_key:
            raise ProviderAuthError(
                "no API key configured for the 'openai' provider",
                remedy="Set OPENAI_API_KEY (or SENTINELFORGE_LLM_API_KEY) in your "
                "environment. Run with --provider mock to analyze offline instead.",
            )

    def _response_format(self) -> dict:
        """Ask for schema-constrained output where the API supports it."""
        return {
            "type": "json_schema",
            "json_schema": {
                "name": SCHEMA_NAME,
                "strict": True,
                "schema": response_json_schema(),
            },
        }

    # -- SDK path ----------------------------------------------------------
    def _call_sdk(self, sdk, messages: list[dict]) -> tuple[str, dict]:
        client = sdk.OpenAI(
            api_key=self._api_key, base_url=self.base_url, timeout=self.timeout
        )
        try:
            completion = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                response_format=self._response_format(),
            )
        except Exception as exc:  # mapped below; never swallowed
            raise _map_sdk_error(sdk, exc) from exc

        try:
            choice = completion.choices[0]
            refusal = getattr(choice.message, "refusal", None)
            if refusal:
                raise ProviderResponseError(f"model refused to answer: {refusal}")
            text = choice.message.content or ""
        except ProviderResponseError:
            raise
        except (AttributeError, IndexError, TypeError) as exc:
            raise ProviderResponseError(f"unexpected response shape: {exc}") from exc

        usage = {}
        raw_usage = getattr(completion, "usage", None)
        if raw_usage is not None:
            usage = {
                "prompt_tokens": getattr(raw_usage, "prompt_tokens", None),
                "completion_tokens": getattr(raw_usage, "completion_tokens", None),
            }
        return text, {key: value for key, value in usage.items() if value is not None}

    # -- standard-library fallback ----------------------------------------
    def _call_http(self, messages: list[dict]) -> tuple[str, dict]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "response_format": self._response_format(),
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"
        transport = self._transport or _urllib_transport
        data = transport(url, payload, headers, self.timeout)
        return _extract_message(data)


def _urllib_transport(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    """POST JSON and decode the JSON reply, mapping transport failures.

    Errors are re-raised as :class:`ProviderError` subclasses so the retry
    policy in :mod:`sentinelforge.ai.client` can stay provider-agnostic.
    """
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise _map_http_status(exc) from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, TimeoutError):
            raise ProviderTimeoutError(f"request timed out after {timeout}s") from exc
        raise ProviderConnectionError(f"cannot reach the provider: {reason}") from exc
    except TimeoutError as exc:
        raise ProviderTimeoutError(f"request timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProviderConnectionError(f"cannot reach the provider: {exc}") from exc

    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ProviderResponseError(f"provider returned invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ProviderResponseError("provider returned a JSON value that is not an object")
    return data


def _map_http_status(exc: urllib.error.HTTPError):
    """Translate an HTTP status into the matching provider error."""
    status = getattr(exc, "code", 0)
    # The body can echo request content; only the status is reported onwards.
    if status in (401, 403):
        return ProviderAuthError(
            f"provider rejected the API key (HTTP {status})",
            remedy="Check OPENAI_API_KEY / SENTINELFORGE_LLM_API_KEY.",
        )
    if status == 429:
        retry_after = None
        try:
            retry_after = float(exc.headers.get("Retry-After"))  # type: ignore[union-attr]
        except (TypeError, ValueError, AttributeError):
            pass
        return ProviderRateLimitError(f"rate limited by the provider (HTTP {status})", retry_after)
    if status == 408:
        return ProviderTimeoutError(f"provider timed out (HTTP {status})")
    if status >= 500:
        error = ProviderConnectionError(f"provider error (HTTP {status})")
        return error
    return ProviderResponseError(f"provider rejected the request (HTTP {status})")


def _map_sdk_error(sdk, exc: Exception):
    """Translate an ``openai`` SDK exception without importing its classes.

    Looked up by attribute so a newer or older SDK -- which may not define
    every class -- cannot turn an API failure into an ``AttributeError``.
    """
    if isinstance(exc, _sdk_class(sdk, "APITimeoutError")):
        return ProviderTimeoutError(f"request timed out: {exc}")
    if isinstance(exc, _sdk_class(sdk, "RateLimitError")):
        return ProviderRateLimitError(f"rate limited by the provider: {exc}")
    if isinstance(exc, _sdk_class(sdk, "AuthenticationError")):
        return ProviderAuthError(
            "provider rejected the API key",
            remedy="Check OPENAI_API_KEY / SENTINELFORGE_LLM_API_KEY.",
        )
    if isinstance(exc, _sdk_class(sdk, "PermissionDeniedError")):
        return ProviderAuthError("the API key is not permitted to use this model")
    if isinstance(exc, _sdk_class(sdk, "APIConnectionError")):
        return ProviderConnectionError(f"cannot reach the provider: {exc}")
    if isinstance(exc, _sdk_class(sdk, "InternalServerError")):
        return ProviderConnectionError(f"provider error: {exc}")
    if isinstance(exc, _sdk_class(sdk, "BadRequestError")):
        return ProviderResponseError(f"provider rejected the request: {exc}")
    if isinstance(exc, _sdk_class(sdk, "APIStatusError")):
        return ProviderResponseError(f"provider returned an error: {exc}")
    return ProviderResponseError(f"provider call failed: {exc}")


class _Unmatchable(Exception):
    """Stand-in for an SDK exception class this SDK version does not define."""


def _sdk_class(sdk, name: str) -> type:
    candidate = getattr(sdk, name, None)
    return candidate if isinstance(candidate, type) else _Unmatchable


def _extract_message(data: dict) -> tuple[str, dict]:
    """Pull the assistant message out of a chat-completions response body."""
    if "error" in data and isinstance(data["error"], dict):
        message = data["error"].get("message") or "unknown provider error"
        raise ProviderResponseError(f"provider returned an error: {message}")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderResponseError("provider response contained no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        raise ProviderResponseError("provider response contained no message")
    if message.get("refusal"):
        raise ProviderResponseError(f"model refused to answer: {message['refusal']}")
    text = message.get("content") or ""
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    usage = {
        key: usage[key]
        for key in ("prompt_tokens", "completion_tokens")
        if isinstance(usage, dict) and key in usage
    }
    return text, usage

"""LLM configuration and the retry policy around a provider (Phase 5).

:class:`LLMConfig` reads the environment; :class:`LLMClient` wraps one provider
with bounded retries and records what happened.  Neither knows anything about
SOC analysis -- that is :mod:`sentinelforge.ai.analyst` -- and neither can act
on a model's reply, because a reply is just text here.

Defaults are deliberately conservative: with nothing configured, the provider
is the offline mock, so an unconfigured install never sends telemetry anywhere
and never spends money.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

from .providers import (
    LLMProvider,
    ProviderError,
    ProviderRateLimitError,
    ProviderResponse,
    available_providers,
    build_provider,
)

LOGGER = logging.getLogger(__name__)

#: Environment variables that configure the AI layer.
ENV_PROVIDER = "SENTINELFORGE_LLM_PROVIDER"
ENV_MODEL = "SENTINELFORGE_LLM_MODEL"
ENV_API_KEY = "SENTINELFORGE_LLM_API_KEY"
ENV_BASE_URL = "SENTINELFORGE_LLM_BASE_URL"
ENV_TIMEOUT = "SENTINELFORGE_LLM_TIMEOUT"
ENV_MAX_ATTEMPTS = "SENTINELFORGE_LLM_MAX_ATTEMPTS"

#: Provider-native key variables, used when the SentinelForge one is unset.
PROVIDER_KEY_ENV = {"openai": "OPENAI_API_KEY"}

#: The provider used when nothing is configured: offline, free, labelled.
DEFAULT_PROVIDER = "mock"
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_ATTEMPTS = 3


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        LOGGER.warning("%s=%r is not a number; using %s", name, raw, default)
        return default
    return value if value > 0 else default


def _env_int(name: str, default: int) -> int:
    return int(_env_float(name, float(default)))


@dataclass
class LLMConfig:
    """Everything needed to reach a provider.

    ``api_key`` is held in memory only: it is never serialized, logged, printed
    or written into an incident.  :meth:`describe` exists so the CLI can report
    configuration without ever touching the value.
    """

    provider: str = DEFAULT_PROVIDER
    model: str | None = None
    api_key: str | None = field(default=None, repr=False)
    base_url: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    @classmethod
    def from_env(cls, environ: dict | None = None, **overrides) -> "LLMConfig":
        """Build a configuration from environment variables plus CLI overrides.

        Explicit overrides (from CLI flags) win over the environment.
        """
        environ = os.environ if environ is None else environ
        provider = (overrides.get("provider") or environ.get(ENV_PROVIDER) or DEFAULT_PROVIDER)
        provider = provider.strip().lower()
        key = environ.get(ENV_API_KEY) or environ.get(PROVIDER_KEY_ENV.get(provider, ""), None)
        config = cls(
            provider=provider,
            model=overrides.get("model") or environ.get(ENV_MODEL) or None,
            api_key=overrides.get("api_key") or key or None,
            base_url=overrides.get("base_url") or environ.get(ENV_BASE_URL) or None,
            timeout=overrides.get("timeout") or _env_float(ENV_TIMEOUT, DEFAULT_TIMEOUT),
            max_attempts=overrides.get("max_attempts")
            or _env_int(ENV_MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS),
        )
        config.max_attempts = max(1, int(config.max_attempts))
        return config

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def describe(self) -> dict:
        """Configuration summary with no secret in it."""
        return {
            "provider": self.provider,
            "model": self.model or "(not configured)",
            "api_key": "configured" if self.has_api_key else "not set",
            "base_url": self.base_url or "(provider default)",
            "timeout_seconds": self.timeout,
            "max_attempts": self.max_attempts,
            "available_providers": list(available_providers()),
        }


@dataclass
class CallStats:
    """What one :meth:`LLMClient.analyze` call cost, for the audit trail."""

    attempts: int = 0
    retries: int = 0
    last_error: str | None = None
    last_error_kind: str | None = None


class LLMClient:
    """A provider plus a bounded retry policy.

    Retries only what could plausibly succeed unchanged -- a timeout, a rate
    limit, a connection failure, a 5xx.  A missing API key or an unknown model
    is not retried: sending the same broken request again only wastes the
    user's quota.

    Args:
        provider: The provider to call.
        config: Configuration; ``max_attempts`` bounds the retry loop.
        sleep: Injectable sleep, so tests do not wait for backoff.
    """

    #: Base seconds for exponential backoff between retries.
    backoff_base = 0.5
    #: Never wait longer than this between attempts.
    backoff_max = 8.0

    def __init__(
        self,
        provider: LLMProvider,
        config: LLMConfig | None = None,
        sleep=time.sleep,
    ) -> None:
        self.provider = provider
        self.config = config or LLMConfig()
        self._sleep = sleep
        self.stats = CallStats()

    @classmethod
    def from_config(cls, config: LLMConfig, sleep=time.sleep) -> "LLMClient":
        """Build the configured provider and wrap it."""
        return cls(build_provider(config), config, sleep=sleep)

    @property
    def is_mock(self) -> bool:
        return bool(getattr(self.provider, "is_mock", False))

    def analyze(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Call the provider, retrying transient failures up to ``max_attempts``.

        Raises:
            ProviderError: the last error, once the attempts are exhausted or a
                non-retryable failure occurs.  Callers must not let this escape
                to the user as a crash -- see :class:`AISocAnalyst`.
        """
        attempts = max(1, int(self.config.max_attempts))
        self.stats = CallStats()
        last: ProviderError | None = None

        for attempt in range(1, attempts + 1):
            self.stats.attempts = attempt
            try:
                return self.provider.analyze(system_prompt, user_prompt)
            except ProviderError as exc:
                last = exc
                self.stats.last_error = str(exc)
                self.stats.last_error_kind = exc.kind
                if not exc.retryable or attempt == attempts:
                    raise
                delay = self._delay(attempt, exc)
                LOGGER.warning(
                    "LLM provider %s failed (%s); retrying in %.1fs (attempt %d/%d)",
                    self.provider.name,
                    exc.kind,
                    delay,
                    attempt + 1,
                    attempts,
                )
                self.stats.retries += 1
                self._sleep(delay)
        raise last if last else ProviderError("provider call failed")  # pragma: no cover

    def _delay(self, attempt: int, exc: ProviderError) -> float:
        """Exponential backoff, honouring ``Retry-After`` when the provider sends it."""
        if isinstance(exc, ProviderRateLimitError) and exc.retry_after:
            return min(float(exc.retry_after), self.backoff_max)
        return min(self.backoff_base * (2 ** (attempt - 1)), self.backoff_max)

    def describe(self) -> dict:
        """Provider + configuration summary, free of secrets."""
        summary = dict(self.config.describe())
        summary.update(self.provider.describe())
        return summary

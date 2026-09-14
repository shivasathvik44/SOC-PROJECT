"""LLM provider abstraction (Phase 5).

The whole contract is one method::

    class LLMProvider:
        def analyze(self, system_prompt, user_prompt) -> ProviderResponse

Data in, text out.  That narrowness is a security property, not an oversight:
there is no tool registry, no function-calling surface, no callback a model can
reach.  A provider cannot run a command, read a file, or touch an incident,
because nothing in this interface lets it ask for any of that.  See
``tests/test_ai_security.py``, which fails if that ever stops being true.

Adding a provider means implementing this class and registering it; the analyst
(:mod:`sentinelforge.ai.analyst`) never imports a provider module directly.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Callable

#: Every method a provider is allowed to expose to the rest of SentinelForge.
PROVIDER_INTERFACE = ("analyze", "describe")


class ProviderError(RuntimeError):
    """A provider call failed.

    Attributes:
        kind: Short machine-readable label recorded in the audit trail.
        retryable: Whether retrying the identical request could plausibly work.
    """

    kind = "provider_error"
    retryable = False

    def __init__(self, message: str, *, remedy: str | None = None) -> None:
        super().__init__(message)
        self.remedy = remedy


class ProviderConfigurationError(ProviderError):
    """The provider is not configured (missing model, unknown name, ...)."""

    kind = "configuration_error"


class ProviderAuthError(ProviderConfigurationError):
    """No usable API key, or the key was rejected.

    The key itself is never included in the message.
    """

    kind = "missing_api_key"


class ProviderUnavailableError(ProviderError):
    """The provider cannot run here (SDK not installed, no transport)."""

    kind = "provider_unavailable"


class ProviderTimeoutError(ProviderError):
    """The provider did not answer within the configured timeout."""

    kind = "timeout"
    retryable = True


class ProviderRateLimitError(ProviderError):
    """The provider rate-limited this request."""

    kind = "rate_limit"
    retryable = True

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ProviderConnectionError(ProviderError):
    """The provider could not be reached."""

    kind = "connection_error"
    retryable = True


class ProviderResponseError(ProviderError):
    """The provider answered, but not with something usable."""

    kind = "invalid_response"


@dataclass(frozen=True)
class ProviderResponse:
    """What a provider returns: text, plus how it was produced.

    Attributes:
        text: The model's raw answer.  Never trusted; always validated by
            :func:`sentinelforge.ai.schemas.parse_analysis_text`.
        provider / model: Recorded in the audit trail.
        is_mock: ``True`` for synthetic output.  Carried through to the stored
            analysis and printed by the CLI, so mock output is never mistaken
            for a real provider's.
        usage: Token counts when the provider reports them.  No other provider
            metadata is kept.
    """

    text: str
    provider: str
    model: str
    is_mock: bool = False
    usage: dict = field(default_factory=dict)


class LLMProvider(abc.ABC):
    """Interface every provider implements.

    Implementations must not expose anything beyond
    :data:`PROVIDER_INTERFACE`: no command execution, no filesystem access, no
    incident mutation.
    """

    #: Registered name, e.g. ``"openai"``.
    name: str = "unknown"
    #: Whether this provider produces synthetic output.
    is_mock: bool = False

    @abc.abstractmethod
    def analyze(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Send the two prompts and return the model's raw text."""

    def describe(self) -> dict:
        """Configuration summary for ``sentinelforge ai providers``.

        Must never include an API key -- only whether one is present.
        """
        return {"provider": self.name, "is_mock": self.is_mock}


#: name -> factory(config) -> LLMProvider
_REGISTRY: dict[str, Callable] = {}


def register_provider(name: str, factory: Callable) -> None:
    """Register a provider factory under ``name``."""
    _REGISTRY[name] = factory


def available_providers() -> tuple[str, ...]:
    """Names that can be used with ``--provider`` / ``SENTINELFORGE_LLM_PROVIDER``."""
    return tuple(sorted(_REGISTRY))


def build_provider(config) -> LLMProvider:
    """Instantiate the provider named by ``config.provider``.

    Raises:
        ProviderConfigurationError: for an unknown provider name.
    """
    factory = _REGISTRY.get(config.provider)
    if factory is None:
        raise ProviderConfigurationError(
            f"unknown LLM provider {config.provider!r} "
            f"(available: {', '.join(available_providers()) or 'none'})"
        )
    return factory(config)


def _register_builtin_providers() -> None:
    """Register the providers shipped with SentinelForge.

    Imported here rather than at module import time of each provider so that a
    missing optional SDK can never break ``import sentinelforge.ai``.
    """
    from .mock import MockProvider
    from .openai import OpenAIProvider

    register_provider("mock", MockProvider.from_config)
    register_provider("openai", OpenAIProvider.from_config)


_register_builtin_providers()

__all__ = [
    "LLMProvider",
    "PROVIDER_INTERFACE",
    "ProviderAuthError",
    "ProviderConfigurationError",
    "ProviderConnectionError",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderResponse",
    "ProviderResponseError",
    "ProviderTimeoutError",
    "ProviderUnavailableError",
    "available_providers",
    "build_provider",
    "register_provider",
]

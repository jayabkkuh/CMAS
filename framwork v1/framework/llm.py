"""LLM agent utilities using the official OpenAI client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None

from .api import AgentModelConfig, ProviderConfig


@dataclass
class OpenAIClientBundle:
    config: ProviderConfig
    client: OpenAI


class OpenAIResponseAgent:
    """Minimal agent interface compatible with BaseAgent."""

    def __init__(
        self,
        client_bundle: OpenAIClientBundle,
        model_config: AgentModelConfig,
        system_prompt: Optional[str],
    ) -> None:
        self.client_bundle = client_bundle
        self.model_config = model_config
        self.system_prompt = system_prompt or ""

    def step(self, prompt: str, **_: Any) -> str:
        payload = prompt if not self.system_prompt else f"{self.system_prompt}\n\n{prompt}"
        response = self.client_bundle.client.responses.create(
            model=self.model_config.model,
            input=payload,
            **self.model_config.options,
        )
        text = getattr(response, "output_text", None)
        if text:
            return text
        if hasattr(response, "output"):
            chunks = []
            for item in response.output or []:
                if isinstance(item, dict):
                    content = item.get("content")
                    if isinstance(content, list):
                        chunks.extend(c.get("text") for c in content if isinstance(c, dict))
                elif hasattr(item, "content"):
                    for piece in item.content or []:
                        chunks.append(getattr(piece, "text", ""))
            text = "".join(filter(None, chunks))
        return text or ""

    # Compatibility with BaseAgent.call_model fallbacks
    def invoke(self, prompt: str, **kwargs: Any) -> str:  # pragma: no cover - convenience
        return self.step(prompt, **kwargs)

    def __call__(self, prompt: str, **kwargs: Any) -> str:  # pragma: no cover
        return self.step(prompt, **kwargs)


class OpenAIChatAgent:
    """Agent that uses chat.completions endpoint."""

    def __init__(
        self,
        client_bundle: OpenAIClientBundle,
        model_config: AgentModelConfig,
        system_prompt: Optional[str],
    ) -> None:
        self.client_bundle = client_bundle
        self.model_config = model_config
        self.system_prompt = system_prompt or ""

    def step(self, prompt: str, **_: Any) -> str:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = self.client_bundle.client.chat.completions.create(
            model=self.model_config.model,
            messages=messages,
            **self.model_config.options,
        )
        choice = response.choices[0]
        if hasattr(choice, "message"):
            return choice.message.get("content", "")
        return getattr(choice, "text", "")

    def invoke(self, prompt: str, **kwargs: Any) -> str:  # pragma: no cover
        return self.step(prompt, **kwargs)

    def __call__(self, prompt: str, **kwargs: Any) -> str:  # pragma: no cover
        return self.step(prompt, **kwargs)


def build_openai_agent(
    provider: ProviderConfig,
    model_config: AgentModelConfig,
    system_prompt: Optional[str],
) -> Any:
    """Return an agent object following BaseAgent expectations."""

    if OpenAI is None:
        raise RuntimeError("openai package is required but not installed.")

    client = OpenAI(
        base_url=provider.base_url,
        api_key=provider.api_key,
        timeout=provider.timeout or 120,
        default_headers=provider.headers or None,
    )
    bundle = OpenAIClientBundle(provider, client)

    mode = (model_config.mode or "response").lower()
    if mode == "chat":
        return OpenAIChatAgent(bundle, model_config, system_prompt)
    return OpenAIResponseAgent(bundle, model_config, system_prompt)

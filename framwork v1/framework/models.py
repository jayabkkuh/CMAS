"""Model builder utilities for OpenAI-compatible APIs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

try:  # Safe optional import; fall back to mock if unavailable
    from openai import OpenAI  # type: ignore
except Exception:  # pragma: no cover - environments without openai installed
    OpenAI = None  # type: ignore

from .api import AgentModelConfig, ProviderConfig


@dataclass
class BaseModelWrapper:
    system_prompt: Optional[str]

    def _compose_prompt(self, prompt: str) -> str:
        if self.system_prompt:
            return f"{self.system_prompt}\n\n{prompt}"
        return prompt

    def step(self, prompt: str, **kwargs: Any) -> str:
        return self.invoke(prompt, **kwargs)

    def invoke(self, prompt: str, **kwargs: Any) -> str:
        raise NotImplementedError


class OpenAIChatWrapper(BaseModelWrapper):
    def __init__(
        self,
        provider: ProviderConfig,
        spec: AgentModelConfig,
        system_prompt: Optional[str],
    ) -> None:
        super().__init__(system_prompt)
        if OpenAI is None:
            raise RuntimeError("openai client not available")
        self.client = OpenAI(
            base_url=provider.base_url,
            api_key=provider.api_key,
            timeout=provider.timeout or 120,
            default_headers=provider.headers or None,
        )
        self.model = spec.model or provider.default_model or ""
        self.options = dict(spec.options)

    def invoke(self, prompt: str, **_: Any) -> str:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            **self.options,
        )
        if not response.choices:
            return ""
        message = response.choices[0].message
        return getattr(message, "content", "") or ""


class OpenAIResponsesWrapper(BaseModelWrapper):
    def __init__(
        self,
        provider: ProviderConfig,
        spec: AgentModelConfig,
        system_prompt: Optional[str],
    ) -> None:
        super().__init__(system_prompt)
        if OpenAI is None:
            raise RuntimeError("openai client not available")
        self.client = OpenAI(
            base_url=provider.base_url,
            api_key=provider.api_key,
            timeout=provider.timeout or 120,
            default_headers=provider.headers or None,
        )
        self.model = spec.model or provider.default_model or ""
        self.options = dict(spec.options)

    def invoke(self, prompt: str, **_: Any) -> str:
        payload = self._compose_prompt(prompt)
        response = self.client.responses.create(
            model=self.model,
            input=payload,
            **self.options,
        )
        text = getattr(response, "output_text", None)
        if text:
            return text
        content = getattr(response, "output", None)
        if isinstance(content, list):
            parts = []
            for item in content:
                chunk = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
                if isinstance(chunk, list):
                    for piece in chunk:
                        txt = piece.get("text") if isinstance(piece, dict) else getattr(piece, "text", "")
                        if txt:
                            parts.append(txt)
            return "".join(parts)
        return ""


def build_agentscope_model(
    provider: ProviderConfig,
    spec: AgentModelConfig,
    system_prompt: Optional[str],
) -> BaseModelWrapper:
    mode = (spec.mode or provider.model_type or "openai_chat").lower()
    if mode in {"chat", "openai_chat"}:
        return OpenAIChatWrapper(provider, spec, system_prompt)
    return OpenAIResponsesWrapper(provider, spec, system_prompt)

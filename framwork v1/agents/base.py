"""
Shared agent utilities and abstract base class.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import json as _json
import re as _re

try:  # pragma: no cover - optional dependency
    from agentscope import Agent  # type: ignore
except ImportError:  # pragma: no cover
    class Agent:  # type: ignore
        """
        Minimal fallback agent with an echoing step method.
        """

        name: str

        def __init__(self, name: str = "MockAgent") -> None:
            self.name = name

        def step(self, prompt: str, **_) -> str:
            return f"[Mock response for {self.name}] {prompt}"

from framework.context import CaseContext
from framework.logger import ValidatorLogger


class BaseAgent(ABC):
    """
    Wrapper around Agentscope's Agent with shared helper methods.
    """

    role: str

    def __init__(self, agent: Agent) -> None:
        self._agent = agent
        self.logger: Optional[ValidatorLogger] = None
        self._context: Optional[CaseContext] = None

    def bind_logger(self, logger: ValidatorLogger) -> None:
        self.logger = logger

    def bind_context(self, context: CaseContext) -> None:
        self._context = context

    def clear_context(self) -> None:
        self._context = None

    def log(self, event_type: str, payload: Optional[Dict[str, str]] = None) -> None:
        if self.logger:
            self.logger.record_event(self.role, event_type, payload or {})

    def call_model(self, prompt: str, **kwargs: Any) -> Any:
        """
        Dispatch a prompt to the underlying Agentscope agent.

        Different agent classes expose different entrypoints; this helper tries
        a couple of common method names before falling back to attribute access.
        """
        dialogue_id: Optional[str] = None
        if self._context:
            dialogue_id = self._context.record_dialogue(self.role, "prompt", prompt)
        try:
            if hasattr(self._agent, "step"):
                result = self._agent.step(prompt=prompt, **kwargs)
            elif hasattr(self._agent, "invoke"):
                result = self._agent.invoke(prompt=prompt, **kwargs)
            elif callable(self._agent):
                result = self._agent(prompt, **kwargs)
            else:
                raise AttributeError(f"Unsupported agent interface for {self._agent!r}")
            if hasattr(result, "__await__"):
                result = asyncio.run(result)
            if self._context:
                self._context.record_dialogue(
                    self.role,
                    "response",
                    str(result),
                    dialogue_id=dialogue_id,
                )
            return result
        except Exception as exc:  # pragma: no cover - network/runtime handling
            if self.logger:
                self.logger.record_event(
                    self.role,
                    "model_error",
                    {"error": str(exc)},
                )
            if self._context:
                self._context.record_dialogue(
                    self.role,
                    "response",
                    f"[Model error: {exc}]",
                    dialogue_id=dialogue_id,
                )
            return f"[Model error: {exc}]"

    def ask_json(self, prompt: str, schema_hint: Optional[str] = None, max_retries: int = 0, **kwargs: Any) -> Any:
        req = prompt
        if schema_hint:
            req = (
                f"{prompt}\n\nStrictly return JSON only matching this schema (no prose, no markdown):\n{schema_hint}"
            )
        attempt = 0
        while True:
            raw = str(self.call_model(req, **kwargs))
            text = raw.strip()
            text = _re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=_re.IGNORECASE | _re.MULTILINE).strip()
            try:
                return _json.loads(text)
            except Exception:
                pass
            try:
                i = text.find("{")
                j = text.rfind("}")
                if i != -1 and j != -1 and j > i:
                    return _json.loads(text[i : j + 1])
            except Exception:
                pass
            try:
                i = text.find("[")
                j = text.rfind("]")
                if i != -1 and j != -1 and j > i:
                    return _json.loads(text[i : j + 1])
            except Exception:
                pass
            if attempt >= max_retries:
                break
            attempt += 1
            req = (
                f"Your last answer was not valid JSON. Return JSON only. Schema:\n{schema_hint or ''}"
            )
        return None

    @abstractmethod
    def run(self, context: CaseContext, **kwargs: Any) -> Any:
        """
        Execute the agent's round-specific responsibilities.
        """

    @property
    def agent(self) -> Agent:
        return self._agent

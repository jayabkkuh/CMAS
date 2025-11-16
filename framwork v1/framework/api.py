"""
API configuration loader utilities.

Expected JSON structure::

    {
      "providers": {
        "openai": {
          "api_key": "...",
          "base_url": "https://...",
          "headers": {"Custom": "Value"}
        }
      },
      "agents": {
        "Detective": {
          "provider": "openai",
          "model": "gpt-5.1-mini",
          "options": {"temperature": 0.2}
        }
      }
    }

Set the ``CTF_FRAMEWORK_API_CONFIG`` environment variable or pass an explicit path
to ``MissionController``/CLI ``--api-config`` to load credentials at runtime.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class ProviderConfig:
    name: str
    api_key: str
    base_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: Optional[int] = None
    model_type: str = "openai_chat"
    default_model: Optional[str] = None


@dataclass
class AgentModelConfig:
    role: str
    provider: str
    model: str
    options: Dict[str, str] = field(default_factory=dict)
    mode: str = "response"


@dataclass
class ApiConfig:
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    agents: Dict[str, AgentModelConfig] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "ApiConfig":
        if "providers" in payload:
            providers = {}
            for name, provider_data in payload.get("providers", {}).items():
                providers[name] = ProviderConfig(
                    name=name,
                    api_key=provider_data.get("api_key", ""),
                    base_url=provider_data.get("base_url"),
                    headers=provider_data.get("headers", {}),
                    timeout=provider_data.get("timeout"),
                    model_type=provider_data.get("model_type", "openai_chat"),
                    default_model=provider_data.get("model_name"),
                )

            agents = {}
            for role, agent_data in payload.get("agents", {}).items():
                prov_name = agent_data.get("provider", "")
                prov = providers.get(prov_name)
                default_mode = (prov.model_type if prov else None) or "openai_chat"
                agents[role] = AgentModelConfig(
                    role=role,
                    provider=prov_name,
                    model=agent_data.get("model", ""),
                    options=agent_data.get("options", {}),
                    mode=agent_data.get("mode", default_mode),
                )

            return cls(providers=providers, agents=agents)

        if "models" in payload:
            providers: Dict[str, ProviderConfig] = {}
            for entry in payload.get("models", []):
                name = entry.get("config_name") or entry.get("name")
                if not name:
                    raise ValueError("Model entry missing config_name")
                providers[name] = ProviderConfig(
                    name=name,
                    api_key=entry.get("api_key", ""),
                    base_url=entry.get("api_url"),
                    headers=entry.get("headers", {}),
                    timeout=entry.get("timeout"),
                    model_type=entry.get("model_type", "openai_chat"),
                    default_model=entry.get("model_name"),
                )

            agents: Dict[str, AgentModelConfig] = {}
            for role, agent_data in payload.get("agents", {}).items():
                ref = agent_data.get("model_config") or agent_data.get("provider") or agent_data.get("config_name") or agent_data.get("model")
                if not ref:
                    raise ValueError(f"Agent {role} missing model_config/provider")
                if ref not in providers:
                    raise ValueError(f"Agent {role} references unknown model config '{ref}'")
                model_name = agent_data.get("model") or agent_data.get("model_name") or providers[ref].default_model or ""
                default_mode = providers[ref].model_type or "openai_chat"
                agents[role] = AgentModelConfig(
                    role=role,
                    provider=ref,
                    model=model_name,
                    options=agent_data.get("options", {}),
                    mode=agent_data.get("mode", default_mode),
                )

            return cls(providers=providers, agents=agents)

        raise ValueError("Unsupported API config format")

    @classmethod
    def from_file(cls, path: Path) -> "ApiConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def get_agent_spec(self, role: str) -> Optional[AgentModelConfig]:
        return self.agents.get(role)

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        return self.providers.get(name)


def load_api_config(path: Optional[Path] = None) -> Optional[ApiConfig]:
    if path is None:
        env_path = os.getenv("CTF_FRAMEWORK_API_CONFIG")
        if env_path:
            path = Path(env_path).expanduser()
        else:
            default_file = Path("api_config.json").expanduser()
            if default_file.exists():
                path = default_file
    if path and path.exists():
        return ApiConfig.from_file(path)
    return None

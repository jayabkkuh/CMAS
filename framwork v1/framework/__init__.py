"""
Core framework package for the multi-agent CTF analysis system.

Exposes high-level constructs so callers can import the mission controller
and shared dataclasses without diving into submodules.
"""

from .controller import MissionController
from .context import CaseContext
from .plans import TaskPlan, TaskStep
from .evidence import EvidenceCard
from .logger import ValidatorLogger, LogEvent
from .result import MissionResult
from .api import ApiConfig

__all__ = [
    "MissionController",
    "CaseContext",
    "TaskPlan",
    "TaskStep",
    "EvidenceCard",
    "ValidatorLogger",
    "LogEvent",
    "MissionResult",
    "ApiConfig",
]

"""
Strategy planning data structures for Strategist and General agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass
class TaskStep:
    description: str
    objective: str
    tools: List[str]
    validation: str
    status: TaskStatus = TaskStatus.PENDING
    assigned_executor: Optional[str] = None
    step_id: Optional[str] = None


@dataclass
class TaskPlan:
    plan_id: str
    hypothesis: str
    category: str
    steps: List[TaskStep] = field(default_factory=list)
    agree_flag: int = 0
    notes: Optional[str] = None
    version: Optional[str] = None
    status: str = "draft"
    reviewers: List[dict] = field(default_factory=list)

    def set_agree(self, value: bool) -> None:
        self.agree_flag = 1 if value else 0

    def mark_step_status(self, index: int, status: TaskStatus) -> None:
        if 0 <= index < len(self.steps):
            self.steps[index].status = status

    def record_review(self, reviewer: str, decision: str, notes: str) -> None:
        self.reviewers.append(
            {
                "reviewer": reviewer,
                "decision": decision,
                "notes": notes,
            }
        )
        self.status = decision

    def add_step(self, step: TaskStep) -> int:
        self.steps.append(step)
        return len(self.steps) - 1

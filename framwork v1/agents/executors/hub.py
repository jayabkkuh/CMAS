"""
Coordinator for the executor swarm.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.logger import ValidatorLogger
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class ExecutorHub:
    def __init__(self, executors: Iterable[ExecutorAgent]) -> None:
        self.executors: Dict[str, ExecutorAgent] = {
            executor.role: executor for executor in executors
        }
        self.active_context: Optional[CaseContext] = None
        self.pending_steps: List[TaskStep] = []
        self.new_steps_count: int = 0
        for executor in self.executors.values():
            executor.register_hub(self)

    def bind_logger(self, logger: ValidatorLogger) -> None:
        for executor in self.executors.values():
            executor.bind_logger(logger)

    def execute(self, plan: TaskPlan, context: CaseContext) -> List[EvidenceCard]:
        self.active_context = context
        artifacts: List[EvidenceCard] = []
        for step in plan.steps:
            role = step.assigned_executor or ""
            executor = self.executors.get(role)
            if not executor:
                context.log_execution(
                    {
                        "agent": "ExecutorHub",
                        "plan_id": plan.plan_id,
                        "step": step.description,
                        "status": "no_executor",
                    }
                )
                continue
            artifacts.extend(executor.handle_step(context, plan, step))
        return artifacts

    def execute_step(
        self,
        role: str,
        plan: TaskPlan,
        step: TaskStep,
        context: CaseContext,
    ) -> List[EvidenceCard]:
        """
        Execute a single step via the designated executor. Used by General.
        """
        self.active_context = context
        executor = self.executors.get(role)
        if not executor:
            context.log_execution(
                {
                    "agent": "ExecutorHub",
                    "plan_id": plan.plan_id,
                    "step": step.description,
                    "status": "no_executor",
                }
            )
            return []
        return executor.handle_step(context, plan, step)

    def execute_plan(
        self,
        role: str,
        plan: TaskPlan,
        context: CaseContext,
    ) -> List[EvidenceCard]:
        """
        Assign the entire plan to a single executor. The executor may adaptively
        propose additional steps; those assigned back to the same executor are
        executed in the same session.
        """
        self.active_context = context
        executor = self.executors.get(role)
        if not executor:
            context.log_execution(
                {
                    "agent": "ExecutorHub",
                    "plan_id": plan.plan_id,
                    "step": "<bulk>",
                    "status": "no_executor",
                }
            )
            return []
        # Run the full plan via the executor
        return executor.run(context, plan, list(plan.steps))

    def enqueue_step(self, plan: TaskPlan, step: TaskStep, context: CaseContext) -> bool:
        """
        Queue a new step proposed at runtime. Enforces a simple cap from config.
        """
        self.active_context = context
        cap = context.config.adaptive_max_new_steps if context else 5
        if self.new_steps_count >= cap:
            if context and context.logger:
                context.logger.record_event(
                    "ExecutorHub",
                    "adaptive_drop",
                    {"reason": "cap_reached", "cap": str(cap)},
                )
            return False
        self.pending_steps.append(step)
        self.new_steps_count += 1
        if context and context.logger:
            context.logger.record_event(
                "ExecutorHub",
                "adaptive_enqueue",
                {"step": step.description, "executor": step.assigned_executor or ""},
            )
        # Also mirror in plan for traceability
        plan.add_step(step)
        return True

    def has_pending(self) -> bool:
        return len(self.pending_steps) > 0

    def pop_next(self) -> Optional[TaskStep]:
        if not self.pending_steps:
            return None
        return self.pending_steps.pop(0)

    def pop_next_for(self, role: str) -> Optional[TaskStep]:
        for i, s in enumerate(self.pending_steps):
            if (s.assigned_executor or "") == role:
                return self.pending_steps.pop(i)
        return None

    def request_support(
        self,
        from_agent: str,
        target_agent: str,
        payload: str,
    ) -> None:
        """
        Record a support request for coordination; does not auto-execute target.
        """

        if self.active_context:
            self.active_context.add_support_request(
                {
                    "from": from_agent,
                    "to": target_agent,
                    "payload": payload,
                }
            )
        # Do not trigger the target executor automatically; General will decide.

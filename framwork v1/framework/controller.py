"""
Mission controller that orchestrates the five-round workflow.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, Dict, Iterable, Optional

try:  # pragma: no cover - optional dependency
    from agentscope import Agent  # type: ignore
except ImportError:  # pragma: no cover
    from agents.base import Agent  # type: ignore

from agents import (
    DetectiveAgent,
    GeneralAgent,
    StrategistAgent,
    ValidatorAgent,
    InstallerAgent,
)
from agents.executors import (
    CryptoExecutorAgent,
    ExecutorAgent,
    ExecutorHub,
    ForensicsExecutorAgent,
    MiscExecutorAgent,
    PwnExecutorAgent,
    ReverseExecutorAgent,
    WebExecutorAgent,
    SymExecExecutorAgent,
)
from framework.api import ApiConfig, load_api_config
from framework.context import CaseContext
from framework.logger import ValidatorLogger
from framework.logger import ConsoleSink
from framework.plans import TaskPlan
from framework.prompts import PROMPTS
from framework.result import MissionResult
from framework.knowledge import SkillEntry
from framework.models import build_agentscope_model


AgentBuilder = Callable[[str, str], Agent]


class MissionController:
    """
    High-level coordinator that drives the multi-agent workflow.
    """

    def __init__(
        self,
        agent_builders: Optional[Dict[str, AgentBuilder]] = None,
        executor_toolkits: Optional[Dict[str, Iterable[str]]] = None,
        api_config: Optional[ApiConfig] = None,
        api_config_path: Optional[Path] = None,
    ) -> None:
        self.agent_builders = agent_builders or {}
        self.executor_toolkits = executor_toolkits or self._default_toolkits()
        self.logger = ValidatorLogger()
        self.api_config = api_config or load_api_config(api_config_path)
        if self.api_config is None:
            raise RuntimeError("API config is required. Provide --api-config or set CTF_FRAMEWORK_API_CONFIG.")

        self.detective = DetectiveAgent(self._build_agent("Detective"))
        self.strategist = StrategistAgent(self._build_agent("Strategist"))
        self.general = GeneralAgent(self._build_agent("General"))
        self.validator = ValidatorAgent(self._build_agent("Validator"))
        self.installer = InstallerAgent(self._build_agent("Installer"))

        executors: Dict[str, ExecutorAgent] = {
            "ReverseExecutorAgent": ReverseExecutorAgent(
                self._build_agent("ReverseExecutorAgent"),
                self.executor_toolkits["ReverseExecutorAgent"],
            ),
            "PwnExecutorAgent": PwnExecutorAgent(
                self._build_agent("PwnExecutorAgent"),
                self.executor_toolkits["PwnExecutorAgent"],
            ),
            "CryptoExecutorAgent": CryptoExecutorAgent(
                self._build_agent("CryptoExecutorAgent"),
                self.executor_toolkits["CryptoExecutorAgent"],
            ),
            "ForensicsExecutorAgent": ForensicsExecutorAgent(
                self._build_agent("ForensicsExecutorAgent"),
                self.executor_toolkits["ForensicsExecutorAgent"],
            ),
            "MiscExecutorAgent": MiscExecutorAgent(
                self._build_agent("MiscExecutorAgent"),
                self.executor_toolkits["MiscExecutorAgent"],
            ),
            "WebExecutorAgent": WebExecutorAgent(
                self._build_agent("WebExecutorAgent"),
                self.executor_toolkits["WebExecutorAgent"],
            ),
        }

        # Optional: attach symbolic executor if angr available and enabled
        try:
            import angr  # type: ignore
            angr_ok = True
        except Exception:
            angr_ok = False
        if angr_ok and getattr(self.api_config, "enable_angr", None) is None:
            # prefer runtime config on context; defer enabling in Strategist
            pass
        if angr_ok:
            # Always register, execution depends on assigned steps
            executors["SymExecExecutorAgent"] = SymExecExecutorAgent(
                self._build_agent("SymExecExecutorAgent"),
                ["angr"],
            )

        self.executor_hub = ExecutorHub(executors.values())

        self._attach_logger()

    def run(self, context: CaseContext) -> MissionResult:
        context.register_logger(self.logger)
        # Attach live console sink if enabled
        if getattr(context.config, "live_console", False):
            sink = ConsoleSink(
                getattr(context.config, "live_events", None),
                maxlen=getattr(context.config, "live_maxlen", 1000),
                style=getattr(context.config, "live_style", "simple"),
                color=bool(getattr(context.config, "live_color", False)),
                lang=getattr(context.config, "live_lang", "en"),
                verbosity=getattr(context.config, "live_verbosity", "normal"),
            )
            self.logger.add_listener(sink.on_event)
        # Always add a JSONL file sink for real-time event streaming
        try:
            from framework.logger import FileSink
            if context.logs_dir:
                self.logger.add_listener(FileSink(context.logs_dir / "events.jsonl").on_event)
        except Exception:
            pass

        validation_report = {"verified": [], "needs_followup": [], "rejected": []}  # type: ignore[assignment]
        retrospective = {"summary": ""}
        try:
            max_rounds = max(1, int(getattr(context.config, "max_rounds", 1)))
            for round_idx in range(1, max_rounds + 1):
                try:
                    context.current_round = round_idx
                except Exception:
                    pass
                # Round banner
                if self.logger:
                    self.logger.record_event("MissionController", "round_start", {"round": str(round_idx)})
                # Update Terminal title at round start if configured
                try:
                    if getattr(context.config, "macos_terminal_title_on_round_only", True):
                        context.set_terminal_title(agent="Team", description=f"Round {round_idx}")
                except Exception:
                    pass
                # 1) Recon (Detective)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_detective_start", {"round": str(round_idx)})
                self.detective.run(context)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_detective_end", {"round": str(round_idx)})
                # Handoff note: Detective -> Strategist summarizing initial findings
                try:
                    ev_count = len(context.evidence)
                    sample_titles = ", ".join(card.title for card in context.evidence[:3])
                    payload = f"Recon complete. Evidence={ev_count}. Samples: {sample_titles}. Full report attached in evidence."
                    context.add_support_request({"from": "Detective", "to": "Strategist", "payload": payload})
                except Exception:
                    pass
                # 2) Plan & review (Strategist + General)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_planning_start", {"round": str(round_idx)})
                plan = self._strategy_round(context)
                # Installer task: install → health check → capability card
                try:
                    self.installer.run(context, plan)
                except Exception as exc:
                    if self.logger:
                        self.logger.record_event("Installer", "fatal_error", {"error": str(exc)})
                context.set_active_plan(plan)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_planning_end", {"round": str(round_idx)})
                # Guard: warn if any step lacks assigned executor
                for step in plan.steps:
                    if not step.assigned_executor:
                        context.log_execution(
                            {
                                "agent": "General",
                                "plan_id": plan.plan_id,
                                "step": step.description,
                                "status": "no_executor_assigned",
                                "step_id": step.step_id or "",
                            }
                        )
                # 3) Execute plan (Executors)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_execution_start", {"round": str(round_idx)})
                # Hard gate: ensure Capability Card exists and is fresh before dispatch
                try:
                    self.installer.run(context, plan)
                except Exception as exc:
                    if self.logger:
                        self.logger.record_event("Installer", "fatal_error", {"error": str(exc)})
                # Re-assert capability gating after Installer. This enforces a hard constraint:
                # if dynamic tools (qemu/angr/readelf) are missing, rewrite steps to static-first
                # routes before any dispatch (covers both bulk and stepwise modes).
                try:
                    # Call the General's capability gate again to rewrite in-place as needed
                    self.general._hard_gate_capabilities(context, plan)  # type: ignore[attr-defined]
                except Exception:
                    pass
                self.general.dispatch(context, plan, self.executor_hub)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_execution_end", {"round": str(round_idx)})
                # 4) Validate (Validator)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_validation_start", {"round": str(round_idx)})
                validation_report = self.validator.run(context)
                # Apply route policy based on collected metrics for next-round planning
                self._apply_route_policy(context)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_validation_end", {"round": str(round_idx)})
                # 5) Summarize (Validator)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_summary_start", {"round": str(round_idx)})
                retrospective = self.validator.retrospective(context)
                if getattr(context.config, "emit_phase_events", True) and self.logger:
                    self.logger.record_event("MissionController", "phase_summary_end", {"round": str(round_idx)})
                # Write experiences to skillbook after each round
                self._update_skillbook(context)
                self._update_agent_experiences(context)
                # Early stop if solved
                if getattr(context, "mission_status", "").lower() == "success":
                    if self.logger:
                        self.logger.record_event("MissionController", "round_complete", {"round": str(round_idx), "status": "success"})
                    break
                if self.logger:
                    self.logger.record_event("MissionController", "round_complete", {"round": str(round_idx), "status": "continue" if round_idx < max_rounds else "complete"})
                # Loop continues to next round, starting again at Detective
        except Exception as exc:  # pragma: no cover - top-level safety
            if self.logger:
                self.logger.record_event("MissionController", "fatal_error", {"error": str(exc)})
            context.mark_mission_complete("failed", notes=str(exc))
            # fallbacks
            validation_report = getattr(context, "validation_report", {}) or {"verified": [], "needs_followup": [], "rejected": []}
            retrospective = getattr(context, "retrospective", {}) or {"summary": f"Mission failed due to error: {exc}"}

        logs_path = context.persist_logs()
        evidence_path = context.persist_evidence()
        report_path = context.persist_report(retrospective, validation_report)
        transcript_path = context.persist_transcript()
        return MissionResult(
            retrospective=retrospective,
            validation_report=validation_report,
            logs_path=logs_path,
            evidence_path=evidence_path,
            dry_run=context.config.dry_run,
            report_path=report_path,
            transcript_path=transcript_path,
        )

    def _strategy_round(self, context: CaseContext) -> TaskPlan:
        feedback: Optional[str] = None
        last_plan: Optional[TaskPlan] = None
        for _ in range(3):
            plan = self.strategist.run(context, feedback=feedback)
            # Hard-precheck: run Installer before General so Capability Card exists
            try:
                self.installer.run(context, plan)
            except Exception as exc:
                if self.logger:
                    self.logger.record_event("Installer", "fatal_error", {"error": str(exc)})
            reviewed = self.general.run(context, plan)
            last_plan = reviewed
            if reviewed.agree_flag == 1:
                return reviewed
            feedback = self.general.last_feedback
        assert last_plan is not None
        return last_plan

    def _apply_route_policy(self, context: CaseContext) -> None:
        """
        Evaluate route metrics and update routing state (stop-loss / preferred route).
        Policies:
        - If no_growth_streak >= 2 → force_static_template and prefer static_flow
        - If missing_tools/declared_tools >= 0.3 → force_static_template
        - If consecutive_verified >= 2 → lock preferred_route if already set
        Emits a route_policy_update event for transparency.
        """
        try:
            rt = context.route_tracker.setdefault("route_stats", {})  # type: ignore[assignment]
            if not isinstance(rt, dict):
                return
            total = int(rt.get("total_steps", 0) or 0)
            triad_verified = int(rt.get("triad_verified", 0) or 0)
            first_try_verified = int(rt.get("first_try_verified", 0) or 0)
            no_growth = int(rt.get("no_growth_streak", 0) or 0)
            declared = int(rt.get("declared_tools", 0) or 0)
            missing = int(rt.get("missing_tools", 0) or 0)
            miss_ratio = (missing / declared) if declared else 0.0

            # Stop-loss triggers
            force_static = False
            reason: list[str] = []
            if no_growth >= 2:
                force_static = True
                reason.append(f"no_growth_streak={no_growth}")
            if miss_ratio >= 0.3:
                force_static = True
                reason.append(f"missing_tools_ratio={missing}/{declared}")

            if force_static:
                context.route_tracker["force_static_template"] = True
                context.route_tracker["preferred_route"] = "static_flow"
            # Mild positive reinforcement: if we see consecutive verified keep preferred_route
            if triad_verified >= 2 and not force_static:
                context.route_tracker.setdefault("preferred_route", "static_flow")

            if context.logger:
                payload = {
                    "total_steps": str(total),
                    "triad_verified": str(triad_verified),
                    "first_try_verified": str(first_try_verified),
                    "no_growth_streak": str(no_growth),
                    "missing_tools_ratio": f"{missing}/{declared}",
                    "force_static": str(bool(context.route_tracker.get("force_static_template", False))),
                    "preferred_route": str(context.route_tracker.get("preferred_route", "")),
                    "reason": ",".join(reason),
                }
                context.logger.record_event("MissionController", "route_policy_update", payload)
        except Exception:
            pass

    def _build_agent(self, role: str) -> Agent:
        if role in self.agent_builders:
            return self.agent_builders[role](role, PROMPTS.get(role, role))

        spec = self.api_config.get_agent_spec(role) if self.api_config else None
        if not spec:
            raise RuntimeError(f"Missing agent model spec for role '{role}' in API config.")
        provider = self.api_config.get_provider(spec.provider) if self.api_config else None
        if not provider:
            raise RuntimeError(f"Unknown provider/model config '{spec.provider}' for role '{role}'.")
        try:
            return build_agentscope_model(provider, spec, PROMPTS.get(role, role))
        except Exception as exc:  # pragma: no cover
            if self.logger:
                self.logger.record_event(
                    "MissionController",
                    "agent_build_failure",
                    {"role": role, "error": str(exc)},
                )
            raise

    def _attach_logger(self) -> None:
        agents = [
            self.detective,
            self.strategist,
            self.general,
            self.validator,
        ]
        agents.extend(self.executor_hub.executors.values())
        for agent in agents:
            agent.bind_logger(self.logger)
        self.executor_hub.bind_logger(self.logger)

    def _default_toolkits(self) -> Dict[str, Iterable[str]]:
        darwin = sys.platform == "darwin"
        return {
            "ReverseExecutorAgent": [
                "r2",
                "ghidra",
                "strings",
                *(("otool", "llvm-objdump", "llvm-readobj", "nm") if darwin else ()),
            ],
            "PwnExecutorAgent": [
                "pwntools",
                *(("lldb",) if darwin else ("gdb", "gef")),
            ],
            "CryptoExecutorAgent": ["sage", "pycryptodome"],
            "ForensicsExecutorAgent": ["binwalk", "volatility"],
            "MiscExecutorAgent": ["python"],
            "WebExecutorAgent": ["burp", "requests"],
        }

    def _update_skillbook(self, context: CaseContext) -> None:
        category = context.active_plan.category if context.active_plan else "Misc"
        for card in context.evidence:
            if not card.verified:
                continue
            tools = [card.tool] if card.tool else []
            entry = SkillEntry(
                category=category,
                pattern=card.title,
                takeaway=card.summary[:180],
                tools=tools,
                role=card.created_by or card.source_agent,
            )
            context.add_skill_entry(entry)

    def _update_agent_experiences(self, context: CaseContext) -> None:
        category = context.active_plan.category if context.active_plan else "Misc"
        reviews = (context.retrospective or {}).get("agent_reviews", {}) if context.retrospective else {}
        self_notes = (context.retrospective or {}).get("self_summaries", {}) if context.retrospective else {}
        if not isinstance(reviews, dict):
            return
        for agent, rev in reviews.items():
            advice = str(rev.get("advice", "")).strip()
            notes = str(rev.get("notes", "")).strip()
            tools = rev.get("tools", []) or []
            takeaway = advice or notes or "Focus on traceable artifacts and verification."
            try:
                # Record per-agent score for category (persisted to skillbook)
                score = int(rev.get("score", 0) or 0)
                if context.skillbook:
                    context.skillbook.record_score(agent, category, score)
                    context.skillbook.save()
            except Exception:
                pass
            # Self-summary (if provided) takes precedence as learning takeaway
            if isinstance(self_notes, dict) and self_notes.get(agent):
                takeaway = str(self_notes.get(agent) or "").strip()[:400] or takeaway
            entry = SkillEntry(
                category=category,
                pattern=f"Mission {context.mission_id}: {agent} lessons",
                takeaway=takeaway[:400],
                tools=list(tools) if isinstance(tools, list) else [],
                role=agent,
            )
            context.add_skill_entry(entry)

"""
Shared functionality for executor agents.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, TYPE_CHECKING

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.logger import ValidatorLogger
from framework.plans import TaskPlan, TaskStep, TaskStatus

from ..base import BaseAgent

if TYPE_CHECKING:  # pragma: no cover
    from .hub import ExecutorHub


class ExecutorAgent(BaseAgent):
    category: str

    def __init__(self, agent, toolkit: Iterable[str]) -> None:
        super().__init__(agent)
        self.toolkit = list(toolkit)
        self.hub: Optional["ExecutorHub"] = None

    def run(
        self,
        context: CaseContext,
        plan: TaskPlan,
        steps: List[TaskStep],
        **kwargs: Any,
    ) -> List[EvidenceCard]:
        """
        Execute a batch of steps. In bulk-dispatch mode, this method will also
        drain newly proposed steps that are assigned back to this executor.
        """
        self.bind_context(context)
        evidence: List[EvidenceCard] = []
        # Mandatory LLM call: quick reasoning before executing assigned steps
        try:
            lines = []
            for i, s in enumerate(steps[:5], 1):
                tools = ",".join(s.tools or [])
                lines.append(f"{i}. {s.description} (tools={tools})")
            prompt = (
                f"You are {self.role}. Given toolkit={','.join(self.toolkit)}, outline key actions for the next steps (bullet list, concise).\n"
                + "\n".join(lines) + "\nEnvironment: macOS Terminal (zsh)."
            )
            resp = str(self.call_model(prompt))
            llm_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title=f"{self.role} LLM plan",
                summary=resp[:400],
                tool="LLM",
                command=f"{self.role}_preflight",
                context=resp,
                tags=["executor", "info"],
                created_by=self.role,
            )
            context.add_evidence(llm_card)
            evidence.append(llm_card)
        except Exception:
            pass
        steps_to_run: List[TaskStep] = list(steps)
        idx = 0
        while idx < len(steps_to_run):
            step = steps_to_run[idx]
            evidence.extend(self.handle_step(context, plan, step, **kwargs))
            idx += 1
            # If hub has pending steps for this executor, take and append
            try:
                if self.hub:
                    while True:
                        nxt = self.hub.pop_next_for(self.role)
                        if not nxt:
                            break
                        steps_to_run.append(nxt)
            except Exception:
                pass
        self.clear_context()
        return evidence

    def handle_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **kwargs: Any,
    ) -> List[EvidenceCard]:
        # Proactive macOS normalization: prefer LLVM/otool family over GNU tools
        try:
            if context.is_macos():
                tools = list(step.tools or [])
                replaced = False
                if "readelf" in tools:
                    tools = [t for t in tools if t != "readelf"]
                    for t in ("llvm-readobj", "otool"):
                        if t not in tools:
                            tools.append(t)
                    replaced = True
                if "objdump" in tools:
                    tools = [t for t in tools if t != "objdump"]
                    if "llvm-objdump" not in tools:
                        tools.append("llvm-objdump")
                    replaced = True
                if replaced:
                    step.tools = tools
                    self.log("tool_normalize", {"step": step.description, "tools": ",".join(tools)})
        except Exception:
            pass
        # Adaptive pre-check: detect missing key tools and notify General
        try:
            tool_bins = {
                "r2": ["r2"],
                "radare2": ["r2"],
                "rabin2": ["rabin2"],
                "strings": ["strings"],
                "readelf": ["readelf", "greadelf"],
                "objdump": ["objdump", "gobjdump", "llvm-objdump"],
                "otool": ["otool"],
                "llvm-objdump": ["llvm-objdump"],
                "llvm-readobj": ["llvm-readobj"],
                "qemu-x86_64": ["qemu-x86_64"],
            }
            tool_alternatives = {
                "readelf": ["llvm-readobj", "otool"],
                "objdump": ["llvm-objdump"],
                "otool": ["llvm-readobj", "llvm-objdump"],
                "qemu": ["radare2", "strings", "readelf", "objdump"],
                "qemu-x86_64": ["radare2", "strings", "readelf", "objdump"],
                "angr": ["radare2", "strings", "readelf", "objdump"],
            }
            missing: List[str] = []
            for t in (step.tools or []):
                bins = tool_bins.get(t, [])
                if not bins:
                    continue
                if not any(context.which(b) for b in bins):
                    missing.append(t)
            if missing:
                # If capability hard gate active, do not attempt fallbacks; block and escalate
                if bool(context.route_tracker.get("capability_hard_gate", False)):
                    self.request_support(
                        "General",
                        f"Capability gate: missing tools for step '{step.description}': {', '.join(missing)}. Step will not execute.",
                    )
                    if not step.step_id:
                        step.step_id = context.next_id("step")
                    step.status = TaskStatus.BLOCKED
                    execution_id = context.next_id("exec")
                    context.log_execution(
                        {
                            "agent": self.role,
                            "plan_id": plan.plan_id,
                            "step": step.description,
                            "status": "blocked_missing_tool",
                            "step_id": step.step_id or "",
                            "execution_id": execution_id,
                        }
                    )
                    return []
                else:
                    # Attempt auto-rewrite of missing tools to available alternatives
                    adapted = False
                    tools = list(step.tools or [])
                    for m in list(missing):
                        alts = tool_alternatives.get(m, [])
                        if m == "qemu" and not alts:
                            alts = tool_alternatives.get("qemu-x86_64", [])
                        usable: List[str] = []
                        for a in alts:
                            bins = tool_bins.get(a, [])
                            if not bins or any(context.which(b) for b in bins):
                                if a not in tools:
                                    usable.append(a)
                        if usable:
                            tools = [t for t in tools if t != m]
                            tools.extend(usable)
                            adapted = True
                    if adapted:
                        step.tools = tools
                        self.log("tool_adapt", {"step": step.description, "tools": ",".join(tools)})
                    else:
                        self.request_support(
                            "General",
                            f"Missing tools for step '{step.description}': {', '.join(missing)}.",
                        )
        except Exception:
            pass
        if not step.step_id:
            step.step_id = context.next_id("step")
        step.status = TaskStatus.IN_PROGRESS
        self.log(
            "step_start",
            {
                "plan_id": plan.plan_id,
                "step": step.description,
                "step_id": step.step_id,
            },
        )
        # Record mac-friendly tool versions for reproducibility if we normalized/adapted
        try:
            def _v(tool: str) -> Optional[EvidenceCard]:
                if tool == "radare2":
                    res = context.run_command(self.role, "r2 version", "r2 -v", artifact_name=f"{step.step_id}_r2_version.txt")
                    return EvidenceCard(id="", source_agent=self.role, title="radare2 version", summary=(res.get("stdout") or "")[:200] or "r2 present", tool="r2", command="r2 -v", context=str(res.get("stdout", "")), tags=["env","tool"])  # type: ignore
                if tool == "llvm-objdump":
                    res = context.run_command(self.role, "llvm-objdump version", "llvm-objdump --version", artifact_name=f"{step.step_id}_llvm_objdump_version.txt")
                    return EvidenceCard(id="", source_agent=self.role, title="llvm-objdump version", summary=(res.get("stdout") or "")[:200] or "llvm-objdump present", tool="llvm-objdump", command="llvm-objdump --version", context=str(res.get("stdout", "")), tags=["env","tool"])  # type: ignore
                if tool == "llvm-readobj":
                    res = context.run_command(self.role, "llvm-readobj version", "llvm-readobj --version", artifact_name=f"{step.step_id}_llvm_readobj_version.txt")
                    return EvidenceCard(id="", source_agent=self.role, title="llvm-readobj version", summary=(res.get("stdout") or "")[:200] or "llvm-readobj present", tool="llvm-readobj", command="llvm-readobj --version", context=str(res.get("stdout", "")), tags=["env","tool"])  # type: ignore
                if tool == "otool":
                    ip = context.input_path.as_posix()
                    res = context.run_command(self.role, "otool header", f"otool -h {ip}", artifact_name=f"{step.step_id}_otool_h.txt")
                    return EvidenceCard(id="", source_agent=self.role, title="otool header (h)", summary=(res.get("stdout") or "")[:200] or "otool present", tool="otool", command=f"otool -h {context.input_path.name}", context=str(res.get("stdout", "")), tags=["env","tool"])  # type: ignore
                return None
            if context.is_macos():
                for t in (step.tools or []):
                    if t in ("radare2", "llvm-objdump", "llvm-readobj", "otool"):
                        card = _v(t)
                        if card:
                            context.add_evidence(card)
                # Emit/update a lightweight capability card summary from the executor side
                try:
                    import json as _json
                    def check_ok(cmd: str) -> tuple[bool, str]:
                        res = context.run_command(self.role, cmd, cmd, use_shell=False)
                        ok = (res.get("returncode") == 0)
                        out = (res.get("stdout") or "").strip()
                        return ok, out
                    cap = {}
                    ok_r2 = bool(context.which("r2"))
                    r2_ok, r2_v = (True, "present")
                    if ok_r2:
                        vres = context.run_command(self.role, "r2 -v", "r2 -v")
                        r2_ok = (vres.get("returncode") == 0)
                        r2_v = (vres.get("stdout") or "").strip() or "r2 present"
                    cap["radare2"] = {"ok": ok_r2 and r2_ok, "info": r2_v}
                    for tool, cmd in ("llvm-objdump", "llvm-objdump --version"), ("llvm-readobj", "llvm-readobj --version"):
                        ok = bool(context.which(tool))
                        ver = ""
                        if ok:
                            res = context.run_command(self.role, f"{tool} version", cmd)
                            ver = (res.get("stdout") or "").strip()
                        cap[tool] = {"ok": ok, "info": ver or ("present" if ok else "missing")}
                    ok_otool = bool(context.which("otool"))
                    ot_info = ""
                    if ok_otool:
                        ip = context.input_path.as_posix()
                        r = context.run_command(self.role, "otool -h", f"otool -h {ip}")
                        ot_info = (r.get("stdout") or "").splitlines()[0] if (r.get("stdout") or "") else "present"
                    cap["otool"] = {"ok": ok_otool, "info": ot_info or ("present" if ok_otool else "missing")}
                    art = context.create_artifact_path(f"{plan.plan_id}_capability_exec.json")
                    art.write_text(_json.dumps(cap, indent=2), encoding="utf-8")
                    context.add_evidence(EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Capability Card (executor update)",
                        summary=f"radare2={'yes' if cap['radare2']['ok'] else 'no'}; llvm-objdump={'yes' if cap['llvm-objdump']['ok'] else 'no'}; llvm-readobj={'yes' if cap['llvm-readobj']['ok'] else 'no'}; otool={'yes' if cap['otool']['ok'] else 'no'}",
                        tool="env",
                        command="executor capability update",
                        context=_json.dumps(cap),
                        tags=["env", "capability"],
                        created_by=self.role,
                    ))
                except Exception:
                    pass
        except Exception:
            pass
        result = self._execute_step(context, plan, step, **kwargs)
        if result:
            # Persist artifacts for any context-only card
            for card in result:
                if card.context and not card.artifact_path:
                    artifact = context.create_artifact_path(f"{step.step_id}_{self.role}.txt")
                    artifact.write_text(card.context, encoding="utf-8")
                    card.attach_artifact(artifact)
                # Enrich evidence with reproducibility metadata
                try:
                    sha = context.metadata.get("input_sha256") if hasattr(context, "metadata") else None
                    if sha:
                        card.metadata.setdefault("input_sha256", sha)
                except Exception:
                    pass
                card.plan_step_id = step.step_id
                card.created_by = self.role
                context.add_evidence(card, linked_event_id=step.step_id)
            # Strict completion policy: a step is completed only if the strict triad is satisfied:
            # 1) Coordinate card that references the Address Mapping (mapping_card_id)
            #    and includes section + (vaddr or offset)
            # 2) Neighborhood artifact: hex/disasm with artifact+hash and hex bytes in [64,128]
            # 3) Target product: validated replay/flag, or table JSON, or candidate with length assertion
            # Planning/INFO-only cards never complete a step.
            try:
                cards_for_step = [e for e in context.evidence if e.plan_step_id == step.step_id]
                # Ensure artifacts have hashes for reproducibility
                try:
                    from pathlib import Path as _P
                    import hashlib as _H
                    for c in cards_for_step:
                        if c.artifact_path and not c.artifact_hash and _P(c.artifact_path).exists():
                            h = _H.sha256()
                            with _P(c.artifact_path).open('rb') as f:
                                for chunk in iter(lambda: f.read(8192), b""):
                                    h.update(chunk)
                            c.artifact_hash = h.hexdigest()
                except Exception:
                    pass
                def _triad_ok(cards):
                    # Enforce strict triad as a hard gate
                    def _is_info(c):
                        tg = set(c.tags or [])
                        return bool(tg & {"info", "env", "capability"}) or (isinstance(c.title, str) and any(k in c.title.lower() for k in ("llm", "advice", "summary")))
                    def _has_coord_strict(c):
                        if _is_info(c):
                            return False
                        sec = bool(c.section or (c.metadata and c.metadata.get("section")))
                        off = c.offset is not None or (c.metadata and c.metadata.get("offset"))
                        v = bool(c.metadata and c.metadata.get("vaddr"))
                        mapped = bool(c.metadata and c.metadata.get("mapping_card_id"))
                        return mapped and ((sec and off) or (sec and v))
                    strict_has_coord = any(_has_coord_strict(c) for c in cards)
                    def _hex_bytes_count(text: str) -> int:
                        return sum(len([p for p in line.split() if len(p)==2 and all(ch in '0123456789abcdefABCDEF' for ch in p)]) for line in (text or '').splitlines())
                    strict_has_neigh = False
                    for c in cards:
                        if _is_info(c):
                            continue
                        if not (c.artifact_path and c.artifact_hash):
                            continue
                        title = (c.title or "").lower()
                        tg = set(c.tags or [])
                        if (tg & {"neighborhood", "disasm", "hex"}) or any(k in title for k in ("disassembly", "hex", "neighborhood")):
                            ok = True
                            try:
                                if ("hex" in tg) or ("hex" in title):
                                    txt = c.context or ""
                                    if txt:
                                        cnt = _hex_bytes_count(txt)
                                        ok = (cnt >= 64 and cnt <= 128)
                            except Exception:
                                ok = True
                            if ok:
                                strict_has_neigh = True
                                break
                    # Final acceptance must be forward replay validated/Good! (or explicit flag evidence)
                    strict_target = False
                    for c in cards:
                        if _is_info(c):
                            continue
                        tg = set(c.tags or [])
                        s2 = (c.context or c.summary or "").lower()
                        if ("validated" in tg) or ("good!" in s2) or ("flag" in (c.tags or [])) or ("flag{" in s2) or ("d3ctf{" in s2 and "good!" in s2):
                            strict_target = True
                            break
                    return strict_has_coord and strict_has_neigh and strict_target
                step.status = TaskStatus.COMPLETED if _triad_ok(cards_for_step) else TaskStatus.IN_PROGRESS
            except Exception:
                step.status = TaskStatus.IN_PROGRESS
        else:
            step.status = TaskStatus.BLOCKED
            # Adaptive: notify General that step is blocked and request guidance
            try:
                self.request_support(
                    "General",
                    f"Step blocked: '{step.description}'. No usable artifacts produced. Recommend alternative path or tool install.",
                )
            except Exception:
                pass

        # If not completed, ask LLM for 1-2 adaptive follow-up steps and enqueue
        try:
            if step.status != TaskStatus.COMPLETED and self.hub:
                recent = []
                for e in reversed(context.evidence[-8:]):
                    recent.append(f"- {e.title}: {(e.summary or '')[:120]}")
                schema = '{"steps":[{"description":"string","executor":"ReverseExecutorAgent|PwnExecutorAgent|CryptoExecutorAgent|ForensicsExecutorAgent|MiscExecutorAgent|WebExecutorAgent|SymExecExecutorAgent","tools":["string"]}]}'
                q = (
                    f"You are {self.role}. The current step is stalled/incomplete: '{step.description}'. "
                    "Propose up to 2 concrete next steps to maximize progress. Return JSON only.\n"
                    f"Context:\n{chr(10).join(recent)}\nEnvironment: macOS Terminal (zsh)."
                )
                data = self.ask_json(q, schema_hint=schema)  # type: ignore[attr-defined]
                items = (data or {}).get("steps", []) if isinstance(data, dict) else []
                cnt = 0
                for itm in items:
                    if cnt >= 2:
                        break
                    desc = str(itm.get("description") or "").strip()
                    ex = str(itm.get("executor") or self.role).strip() or self.role
                    tlist = [str(t) for t in (itm.get("tools") or []) if t]
                    if not desc:
                        continue
                    if self.propose_step(context, plan, desc, ex, tools=tlist):
                        cnt += 1
        except Exception:
            pass
        execution_id = context.next_id("exec")
        context.log_execution(
            {
                "agent": self.role,
                "plan_id": plan.plan_id,
                "step": step.description,
                "status": step.status.value,
                "step_id": step.step_id or "",
                "execution_id": execution_id,
            }
        )
        try:
            self.after_step(context, plan, step)
        except Exception:
            pass
        return result or []

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **kwargs: Any,
    ) -> List[EvidenceCard]:
        """
        Hook to be implemented by subclasses.
        """

        raise NotImplementedError

    # Optional hook for route adaptation after a step is executed
    def after_step(self, context: CaseContext, plan: TaskPlan, step: TaskStep) -> None:
        try:
            # Stats counters
            rt = context.route_tracker.setdefault("route_stats", {})  # type: ignore[assignment]
            if not isinstance(rt, dict):
                return
            attempts = context.route_tracker.setdefault("step_attempts", {})  # type: ignore[assignment]
            if not isinstance(attempts, dict):
                attempts = {}
                context.route_tracker["step_attempts"] = attempts
            sid = step.step_id or context.next_id("step")
            step.step_id = sid
            attempts[sid] = int(attempts.get(sid, 0) or 0) + 1

            # Triad detection for this step
            cards = [e for e in context.evidence if e.plan_step_id == sid]
            def _triad_ok(cards):
                has_coord = any((c.offset is not None) or bool(c.section) or (c.metadata and (c.metadata.get("vaddr") or c.metadata.get("function"))) for c in cards)
                has_neigh = any(c.artifact_path and c.artifact_hash and (('neighborhood' in (c.tags or [])) or ('disasm' in (c.tags or [])) or ('hex' in (c.tags or [])) or ('disassembly' in (c.title or '').lower())) for c in cards)
                target = False
                for c in cards:
                    if c.tags and any(t in c.tags for t in ("flag", "auto-decode", "rule")):
                        target = True
                        break
                    s = (c.context or c.summary or "")
                    if isinstance(s, str) and ("flag{" in s.lower() or "d3ctf{" in s.lower() or "good!" in s.lower()):
                        target = True
                        break
                return has_coord and has_neigh and target
            triad = _triad_ok(cards)

            rt["total_steps"] = int(rt.get("total_steps", 0) or 0) + 1
            verified_set = context.route_tracker.setdefault("verified_steps", set())  # type: ignore[assignment]
            if not isinstance(verified_set, set):
                verified_set = set()
                context.route_tracker["verified_steps"] = verified_set
            if triad and sid not in verified_set:
                verified_set.add(sid)
                rt["triad_verified"] = int(rt.get("triad_verified", 0) or 0) + 1
                if attempts.get(sid, 0) == 1:
                    rt["first_try_verified"] = int(rt.get("first_try_verified", 0) or 0) + 1
                # Consecutive verified streak
                rt["consecutive_verified"] = int(rt.get("consecutive_verified", 0) or 0) + 1
                # Reset no-growth streak on success
                rt["no_growth_streak"] = 0
            else:
                # Zero-increment and reset streak when not triad
                if not triad:
                    rt["zero_growth"] = int(rt.get("zero_growth", 0) or 0) + 1
                rt["consecutive_verified"] = 0
                # Increment no-growth streak
                rt["no_growth_streak"] = int(rt.get("no_growth_streak", 0) or 0) + 1

            if context.logger:
                payload = {
                    "total_steps": str(int(rt.get("total_steps", 0) or 0)),
                    "triad_verified": str(int(rt.get("triad_verified", 0) or 0)),
                    "verified_over_all": f"{int(rt.get('triad_verified',0) or 0)}/{int(rt.get('total_steps',0) or 0)}",
                    "first_try_rate": f"{int(rt.get('first_try_verified',0) or 0)}/{int(rt.get('total_steps',0) or 0)}",
                    "zero_growth": str(int(rt.get("zero_growth", 0) or 0)),
                    "no_growth_streak": str(int(rt.get("no_growth_streak", 0) or 0)),
                    "tool_missing_ratio": f"{int(rt.get('missing_tools',0) or 0)}/{int(rt.get('declared_tools',0) or 0)}",
                }
                context.logger.record_event("MissionController", "stats_update", payload)

            # Stop-loss in bulk mode: if streak>=2, enqueue pivot steps for this executor
            try:
                ng = int(rt.get("no_growth_streak", 0) or 0)
                if ng >= 2 and self.hub:
                    if not bool(context.route_tracker.get("static_template_enqueued", False)):
                        self.propose_step(
                            context,
                            plan,
                            "Static table-driven route (extract→infer→replay)",
                            self.role,
                            tools=["radare2", "strings", "otool", "llvm-readobj", "llvm-objdump"],
                            validation="coordinate+neighborhood(>=64B)+target(replay Good!/validated)",
                        )
                        context.route_tracker["static_template_enqueued"] = True
                    elif not bool(context.route_tracker.get("data_plane_enqueued", False)):
                        self.propose_step(
                            context,
                            plan,
                            "Data-plane fallback: scan .rodata printable sequences and apply prefix filters",
                            self.role,
                            tools=["radare2", "strings", "otool", "llvm-readobj"],
                            validation="coordinate+neighborhood(>=64B)+target(candidate length=36 or validated)",
                        )
                        context.route_tracker["data_plane_enqueued"] = True
            except Exception:
                pass
        except Exception:
            return

    def bind_logger(self, logger: ValidatorLogger) -> None:
        super().bind_logger(logger)

    def register_hub(self, hub: "ExecutorHub") -> None:
        self.hub = hub

    def request_support(self, target: str, payload: str) -> None:
        if self.hub:
            self.hub.request_support(self.role, target, payload)

    def skillbook_snippet(self, context: CaseContext, limit: int = 3) -> str:
        entries = context.suggest_from_skillbook(self.category, role=self.role)
        if not entries:
            return ""
        lines = [f"* {entry.pattern} -> {entry.takeaway}" for entry in entries[:limit]]
        return "\n".join(lines)

    def propose_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        description: str,
        executor_role: str,
        tools: Optional[List[str]] = None,
        validation: str = "Cross-check via artifact or terminal output.",
    ) -> bool:
        if not self.hub:
            return False
        tools = tools or ["LLM"]
        step = TaskStep(
            description=description,
            objective=description,
            tools=tools,
            validation=validation,
            assigned_executor=executor_role,
        )
        ok = self.hub.enqueue_step(plan, step, context)
        if ok:
            self.log("propose_step", {"description": description, "executor": executor_role})
        return ok

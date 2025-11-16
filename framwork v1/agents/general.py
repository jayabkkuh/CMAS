"""
General agent: evaluates and refines the Strategist's plan.
"""

from __future__ import annotations

from typing import Optional

from framework.context import CaseContext
from framework.plans import TaskPlan

from .base import BaseAgent


APPROVAL_KEYWORDS = ("approve", "solid", "execute", "ready", "ship")
REVISION_KEYWORDS = ("revise", "adjust", "missing", "block", "unclear")


class GeneralAgent(BaseAgent):
    role = "General"
    last_feedback: Optional[str] = None

    def run(self, context: CaseContext, plan: TaskPlan, **_) -> TaskPlan:
        self.bind_context(context)
        self.log("round_start", {"plan_id": plan.plan_id})
        # Hard capability gate: enforce static rewrites if capabilities missing
        try:
            self._hard_gate_capabilities(context, plan)
        except Exception:
            pass
        # Mandatory LLM call: attempt JSON agree/feedback first; fallback to prose
        try:
            steps_lines = []
            try:
                for i, s in enumerate(plan.steps, 1):
                    tools = ",".join(s.tools or [])
                    steps_lines.append(f"{i}. {s.description} (executor={s.assigned_executor}; tools={tools})")
            except Exception:
                steps_lines = []
            schema = '{"agree": true, "feedback": "string"}'
            prompt = (
                "You are the General reviewing a CTF execution plan. "
                "Decide agree=true|false and give concise feedback. Return JSON only.\n"
                f"Plan ID: {plan.plan_id}\nCategory: {plan.category}\nHypothesis: {plan.hypothesis}\n"
                "Steps:\n" + "\n".join(steps_lines) + "\nEnvironment: macOS Terminal (zsh)."
            )
            data = self.ask_json(prompt, schema_hint=schema)  # type: ignore[attr-defined]
            resp_txt = None
            if isinstance(data, dict) and ("agree" in data or "feedback" in data):
                try:
                    ok_json = bool(data.get("agree", False))
                    fb = str(data.get("feedback", ""))
                    plan.notes = (plan.notes or "") + "\n[LLM Review]\n" + fb[:800]
                    self.last_feedback = fb
                    plan.set_agree(1 if ok_json else 0)
                except Exception:
                    pass
            else:
                free_prompt = (
                    "You are the General reviewing a CTF execution plan. Provide concise critique and explicit improvement suggestions (numbered). "
                    "Environment: macOS Terminal (zsh)."
                )
                resp_txt = str(self.call_model(free_prompt + "\n\n" + "\n".join(steps_lines)))
                plan.notes = (plan.notes or "") + "\n[LLM Review]\n" + resp_txt[:800]
            from framework.evidence import EvidenceCard
            card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="General LLM review",
                summary=(resp_txt or str(data))[:400],
                tool="LLM",
                command="general_review",
                context=resp_txt or (str(data) if data is not None else ""),
                tags=["review", "info"],
                created_by=self.role,
            )
            context.add_evidence(card)
        except Exception:
            pass
        # Evaluate plan completeness and provide actionable feedback.
        ok, critique = self._evaluate_plan(plan)
        self.last_feedback = critique
        plan.notes = (plan.notes or "") + "\n[General Review]\n" + critique
        plan.set_agree(ok)
        # Update AGREE token in notes for transparency
        plan.notes += f"\nAGREE={'1' if ok else '0'}"
        try:
            context.record_dialogue(self.role, "response", f"Reviewed plan {plan.plan_id}. AGREE={'1' if ok else '0'}\n{critique}")
        except Exception:
            pass
        decision = "approved" if plan.agree_flag == 1 else "changes_requested"
        plan.status = decision
        context.mark_plan_status(plan, decision, self.role, critique)
        context.add_strategy_revision(plan)
        self.log(
            "plan_reviewed",
            {"plan_id": plan.plan_id, "agree": str(plan.agree_flag)},
        )
        self.clear_context()
        return plan

    def _hard_gate_capabilities(self, context: CaseContext, plan: TaskPlan) -> None:
        """
        Hard capability gate enforced before dispatch:
        - Parse the latest Installer "Capability Card" from evidence
        - If any step requires qemu/angr/readelf but capability=false (or card missing),
          rewrite that step into a static table-driven template so the very first
          dispatch goes to a productive static route instead of attempting tools
          that are unavailable on this host.

        This makes the capability gate a pre-dispatch hard constraint, eliminating
        wasted attempts observed in logs.
        """
        # Parse Capability Card emitted by Installer (prefer JSON context)
        caps = {
            "qemu": False,
            "angr": False,
            "readelf": False,
            "otool": False,
            "objdump": False,
            "llvm-objdump": False,
            "llvm-readobj": False,
        }
        try:
            for e in reversed(context.evidence):
                if isinstance(e.title, str) and e.title.lower() == "capability card":
                    import json as _json
                    try:
                        data = _json.loads(e.context or "{}")
                        for k in list(caps.keys()):
                            if k in data:
                                caps[k] = bool((data[k] or {}).get("ok", False))
                    except Exception:
                        txt = str(e.summary or "")
                        caps["qemu"] = ("qemu-x86_64=yes" in txt)
                        caps["angr"] = ("angr=yes" in txt)
                        caps["readelf"] = ("readelf=yes" in txt)
                    break
        except Exception:
            pass
        # If no capability info found at all, prefer static and request Installer
        if not caps.get("qemu", False) and not caps.get("angr", False):
            try:
                context.add_support_request({
                    "from": self.role,
                    "to": "Installer",
                    "payload": "Capability Card not found or capabilities missing; enforcing static-only route.",
                })
            except Exception:
                pass
        # Dynamic static defaults based on platform/capability
        is_macos = context.is_macos()
        static_defaults = ["radare2", "strings"]
        if is_macos:
            if caps.get("otool", False):
                static_defaults.append("otool")
            elif caps.get("llvm-readobj", False):
                static_defaults.append("llvm-readobj")
            if caps.get("llvm-objdump", False):
                static_defaults.append("llvm-objdump")
        else:
            if caps.get("readelf", False):
                static_defaults.append("readelf")
            if caps.get("objdump", False) or caps.get("llvm-objdump", False):
                static_defaults.append("objdump" if caps.get("objdump", False) else "llvm-objdump")
        changed = False
        # Enable capability hard gate flag so executors avoid fallback attempts
        try:
            context.route_tracker["capability_hard_gate"] = True
        except Exception:
            pass
        # quick flags derived from caps for readability
        qemu_ok = bool(caps.get("qemu", False))
        angr_ok = bool(caps.get("angr", False))
        for s in plan.steps:
            tools = list(s.tools or [])
            tset = set(tools)
            # Gate qemu
            if ("qemu" in tset or "qemu-x86_64" in tset) and not qemu_ok:
                # Rewrite step into static table-driven template
                self._rewrite_to_static_template(context, s, static_defaults)
                changed = True
                plan.notes = (plan.notes or "") + "\n[Gate] qemu missing → static table-driven template"
            # Gate angr / SymExec
            needs_angr = (s.assigned_executor == "SymExecExecutorAgent") or ("angr" in tset)
            if needs_angr and not angr_ok:
                # Rewrite step into static table-driven template
                self._rewrite_to_static_template(context, s, static_defaults)
                changed = True
                plan.notes = (plan.notes or "") + "\n[Gate] angr missing → static table-driven template"
            # Gate readelf/objdump families on macOS; prefer otool/LLVM
            if is_macos:
                if ("readelf" in tset) and not caps.get("readelf", False):
                    # On macOS without readelf, move to static template backed by
                    # llvm-readobj/otool/llvm-objdump per availability.
                    self._rewrite_to_static_template(context, s, static_defaults)
                    changed = True
                    plan.notes = (plan.notes or "") + "\n[Gate] readelf missing → static table-driven template"
                if ("objdump" in tset) and not (caps.get("objdump", False) or caps.get("llvm-objdump", False)):
                    self._rewrite_to_static_template(context, s, static_defaults)
                    changed = True
                    plan.notes = (plan.notes or "") + "\n[Gate] objdump missing → static table-driven template"
            else:
                # Non-macOS: treat missing readelf as a hard gate to the same static template
                if ("readelf" in tset) and not caps.get("readelf", False):
                    self._rewrite_to_static_template(context, s, static_defaults)
                    changed = True
                    plan.notes = (plan.notes or "") + "\n[Gate] readelf missing → static table-driven template"
        if changed:
            try:
                context.add_support_request({
                    "from": self.role,
                    "to": "Team",
                    "payload": "Hard gate applied: dynamic/symexec steps rewritten to static template based on Capability Card.",
                })
            except Exception:
                pass

    def _rewrite_to_static_template(self, context: CaseContext, step: "TaskStep", static_defaults: list[str]) -> None:
        """
        Convert a step that requires unavailable dynamic/symbolic tools into a
        static table-driven template in-place, so dispatch can proceed productively.
        """
        from framework.plans import TaskStep  # type: ignore
        # Choose platform-friendly defaults
        tools: list[str] = []
        tools.extend([t for t in static_defaults if t])
        # Ensure core tools present
        for t in ("radare2", "strings"):
            if t not in tools:
                tools.append(t)
        # macOS preference: include otool/LLVM family if available in caps via route_tracker hint
        try:
            # Try to infer from latest Capability Card again for tool normalization
            caps = {"otool": False, "llvm-readobj": False, "llvm-objdump": False}
            for e in reversed(context.evidence):
                if isinstance(e.title, str) and e.title.lower() == "capability card":
                    import json as _json
                    try:
                        data = _json.loads(e.context or "{}")
                        for k in list(caps.keys()):
                            if k in data:
                                caps[k] = bool((data[k] or {}).get("ok", False))
                    except Exception:
                        txt = str(e.summary or "")
                        caps["otool"] = ("otool=yes" in txt)
                        caps["llvm-readobj"] = ("llvm-readobj=yes" in txt)
                        caps["llvm-objdump"] = ("llvm-objdump=yes" in txt)
                    break
            if context.is_macos():
                # Prefer otool/LLVM if present
                for t in ("otool", "llvm-readobj", "llvm-objdump"):
                    if caps.get(t, False) and t not in tools:
                        tools.append(t)
        except Exception:
            pass
        # Rewrite fields in place
        step.assigned_executor = "ReverseExecutorAgent"
        step.tools = tools
        # Preserve existing step_id, but update text/objective/validation to template
        step.description = "静态表驱动模板 (extract→infer→replay)"
        step.objective = "Static template"
        step.validation = "coordinate+neighborhood(>=64B)+target(replay Good!/validated)"

    def dispatch(self, context: CaseContext, plan: TaskPlan, hub: "ExecutorHub") -> None:
        """
        Issue step-by-step orders to executor agents based on the finalized plan.

        The General actively controls which executor handles each step and logs
        every dispatch for Validator traceability.
        """
        # Late import to avoid circular deps
        from agents.executors.hub import ExecutorHub  # type: ignore

        assert isinstance(hub, ExecutorHub)
        self.bind_context(context)
        # Enforce a hard capability gate just before dispatch (post-Installer),
        # so missing qemu/readelf/angr are rewritten to static-first routes even
        # when using bulk dispatch mode.
        try:
            self._hard_gate_capabilities(context, plan)
        except Exception:
            pass
        # Preflight: ensure plan-required tools are available (no installs here; Installer handles installs)
        try:
            self._ensure_tools_for_plan(context, plan)
        except Exception:
            pass

        mode = getattr(context.config, "dispatch_mode", "stepwise").lower()
        # If running in bulk mode, perform a final bulk gating: drop any steps that
        # still require missing capabilities (qemu/angr/readelf family) after Installer
        # and capability rewrite. This prevents bulk dispatch from blindly executing
        # unsupported routes and causing empty churn.
        if mode == "bulk":
            # Build capability snapshot (same logic as stepwise path)
            cap = {"qemu": False, "angr": False, "readelf": False, "objdump": False, "llvm-objdump": False, "llvm-readobj": False, "otool": False, "radare2": False, "strings": False}
            try:
                for e in reversed(context.evidence):
                    if isinstance(e.title, str) and e.title.lower() == "capability card":
                        import json as _json
                        data = None
                        try:
                            data = _json.loads(e.context or "{}")
                        except Exception:
                            data = None
                        if isinstance(data, dict) and data:
                            for k in list(cap.keys()):
                                try:
                                    cap[k] = bool((data.get(k) or {}).get("ok", False))
                                except Exception:
                                    pass
                        else:
                            txt = str(e.summary or "")
                            cap["qemu"] = ("qemu-x86_64=yes" in txt)
                            cap["angr"] = ("angr=yes" in txt)
                            cap["readelf"] = ("readelf=yes" in txt)
                            cap["objdump"] = ("objdump=yes" in txt)
                            cap["llvm-objdump"] = ("llvm-objdump=yes" in txt)
                            cap["llvm-readobj"] = ("llvm-readobj=yes" in txt)
                            cap["otool"] = ("otool=yes" in txt)
                            cap["radare2"] = ("radare2=yes" in txt)
                            cap["strings"] = ("strings=yes" in txt)
                        break
            except Exception:
                pass
            # Filter steps that still require missing capabilities
            kept = []
            dropped = []
            for s in list(plan.steps):
                tset = set(s.tools or [])
                role = s.assigned_executor or ""
                needs_qemu = ("qemu" in tset or "qemu-x86_64" in tset)
                needs_readelf = ("readelf" in tset)
                needs_objdump = ("objdump" in tset)
                needs_angr = (role == "SymExecExecutorAgent") or ("angr" in tset)
                def _cap(tool: str) -> bool:
                    return bool(cap.get(tool, False))
                blocked = (
                    (needs_qemu and not _cap("qemu")) or
                    (needs_readelf and not (_cap("readelf") or _cap("llvm-readobj") or _cap("otool"))) or
                    (needs_objdump and not (_cap("objdump") or _cap("llvm-objdump") or _cap("otool"))) or
                    (needs_angr and not _cap("angr"))
                )
                if blocked:
                    dropped.append(s)
                else:
                    kept.append(s)
            if dropped:
                # Log and drop blocked steps
                try:
                    for s in dropped:
                        context.log_execution({
                            "agent": self.role,
                            "plan_id": plan.plan_id,
                            "step": s.description,
                            "status": "blocked_missing_capability",
                            "step_id": s.step_id or "",
                        })
                except Exception:
                    pass
                plan.steps = kept
                # If everything is dropped, nothing to dispatch
                if not plan.steps:
                    self.log("dispatch_complete", {"plan_id": plan.plan_id, "mode": "bulk", "executor": "(none)", "note": "all steps gated"})
                    self.clear_context()
                    return
        # Stop-loss: if engaged, avoid dispatching dynamic/symbolic routes and pivot to static template
        force_static = False
        try:
            force_static = bool(context.route_tracker.get("force_static_template", False))
        except Exception:
            force_static = False
        if mode == "bulk":
            # Determine a single primary executor for the entire plan
            target = self._select_primary_executor(plan)
            self.log("dispatch_plan", {"plan_id": plan.plan_id, "category": plan.category, "executor": target, "steps": str(len(plan.steps))})
            hub.execute_plan(target, plan, context)
            self.log("dispatch_complete", {"plan_id": plan.plan_id, "mode": "bulk", "executor": target})
        else:
            self.log("dispatch_start", {"plan_id": plan.plan_id, "category": plan.category})
            # Only dispatch the executor explicitly assigned on each step.
            steps_to_run = list(plan.steps)
            static_enqueued = bool(context.route_tracker.get("static_template_enqueued", False))
            # Capability snapshot from Capability Card (prefer JSON context; fallback to summary tokens)
            cap = {"qemu": False, "angr": False, "readelf": False, "objdump": False, "llvm-objdump": False, "llvm-readobj": False, "otool": False, "radare2": False, "strings": False}
            try:
                for e in reversed(context.evidence):
                    if isinstance(e.title, str) and e.title.lower() == "capability card":
                        import json as _json
                        data = None
                        try:
                            data = _json.loads(e.context or "{}")
                        except Exception:
                            data = None
                        if isinstance(data, dict) and data:
                            for k in list(cap.keys()):
                                try:
                                    cap[k] = bool((data.get(k) or {}).get("ok", False))
                                except Exception:
                                    pass
                        else:
                            txt = str(e.summary or "")
                            cap["qemu"] = ("qemu-x86_64=yes" in txt)
                            cap["angr"] = ("angr=yes" in txt)
                            cap["readelf"] = ("readelf=yes" in txt)
                            cap["objdump"] = ("objdump=yes" in txt)
                            cap["llvm-objdump"] = ("llvm-objdump=yes" in txt)
                            cap["llvm-readobj"] = ("llvm-readobj=yes" in txt)
                            cap["otool"] = ("otool=yes" in txt)
                            cap["radare2"] = ("radare2=yes" in txt)
                            cap["strings"] = ("strings=yes" in txt)
                        break
            except Exception:
                pass
            # Ensure executors honor capability gating
            try:
                context.route_tracker["capability_hard_gate"] = True
            except Exception:
                pass

            # Deduplicate ineffective steps across rounds when stop-loss engaged
            executed: set[str] = set()
            try:
                executed = set(context.route_tracker.get("executed_fingerprints", set()) or [])  # type: ignore[arg-type]
            except Exception:
                executed = set()
            def _fp(s: "TaskStep") -> str:
                return f"{s.assigned_executor}|{s.description}|{','.join(sorted(s.tools or []))}"

            # Helper: classify route similar to Reverse executor
            def _route_of(s: "TaskStep") -> str:
                try:
                    tset = set(s.tools or [])
                    if (s.assigned_executor == "SymExecExecutorAgent") or ("angr" in tset) or ("qemu" in tset) or ("qemu-x86_64" in tset):
                        return "dynsym"
                    if any(t in tset for t in ("radare2", "readelf", "objdump", "llvm-objdump", "llvm-readobj", "otool")):
                        return "static_flow"
                    d = (s.description or "").lower()
                    if any(k in d for k in ("table", "jump table", "constant", "template")):
                        return "const_template"
                    if "data-plane" in d or "printable" in d:
                        return "data_plane"
                except Exception:
                    pass
                return "other"

            for step in steps_to_run:
                role = step.assigned_executor or ""
                if not role:
                    # No executor specified; skip with a log entry.
                    self.log(
                        "dispatch_step",
                        {"plan_id": plan.plan_id, "step": step.description, "executor": "(none)"},
                    )
                    context.log_execution(
                        {
                            "agent": "General",
                            "plan_id": plan.plan_id,
                            "step": step.description,
                            "status": "no_executor_assigned",
                            "step_id": step.step_id or "",
                        }
                    )
                    continue
                # macOS normalization: prefer LLVM/otool family over GNU tools for static analysis
                try:
                    if context.is_macos():
                        tools = list(step.tools or [])
                        changed = False
                        if "readelf" in tools:
                            tools = [t for t in tools if t != "readelf"]
                            for t in ("llvm-readobj", "otool"):
                                if t not in tools:
                                    tools.append(t)
                            changed = True
                        if "objdump" in tools:
                            tools = [t for t in tools if t != "objdump"]
                            if "llvm-objdump" not in tools:
                                tools.append("llvm-objdump")
                            changed = True
                        if changed:
                            step.tools = tools
                            self.log("tool_normalize", {"step": step.description, "tools": ",".join(tools)})
                except Exception:
                    pass

                # Stop-loss deduplication: skip repeated ineffective steps after two no-growth
                try:
                    rt = context.route_tracker.get("route_stats", {}) or {}
                    if int(rt.get("no_growth_streak", 0) or 0) >= 2:
                        fp = _fp(step)
                        if fp in executed:
                            context.log_execution({
                                "agent": self.role,
                                "plan_id": plan.plan_id,
                                "step": step.description,
                                "status": "skipped_duplicate",
                                "step_id": step.step_id or "",
                            })
                            continue
                except Exception:
                    pass
                # Capability hard gate: if a step needs qemu/readelf/objdump/angr but capability false, do not dispatch it
                tset = set(step.tools or [])
                needs_qemu = ("qemu" in tset or "qemu-x86_64" in tset)
                needs_readelf = ("readelf" in tset)
                needs_objdump = ("objdump" in tset)
                needs_angr = (role == "SymExecExecutorAgent") or ("angr" in tset)
                needs_r2 = ("radare2" in tset or "r2" in tset or "rabin2" in tset)
                needs_strings = ("strings" in tset)
                def _cap(tool: str) -> bool:
                    return bool(cap.get(tool, False))
                if (
                    (needs_qemu and not _cap("qemu")) or
                    (needs_readelf and not (_cap("readelf") or _cap("llvm-readobj") or _cap("otool"))) or
                    (needs_objdump and not (_cap("objdump") or _cap("llvm-objdump") or _cap("otool"))) or
                    (needs_angr and not _cap("angr")) or
                    (needs_r2 and not (_cap("radare2") or _cap("rabin2"))) or
                    (needs_strings and not _cap("strings"))
                ):
                    context.log_execution({
                        "agent": self.role,
                        "plan_id": plan.plan_id,
                        "step": step.description,
                        "status": "blocked_missing_capability",
                        "step_id": step.step_id or "",
                    })
                    # Prefer enqueuing static template
                    if not static_enqueued:
                        try:
                            from framework.plans import TaskStep
                            s = TaskStep(
                                description="Constant/jumptable template: detect and reproduce decoding rule",
                                assigned_executor="ReverseExecutorAgent",
                                tools=["python", "radare2", "strings"],
                                validation=(
                                    "Detect small-int/jump tables; emit reproducible rule/script and neighborhood artifacts "
                                    "with hashes; include coordinates; target hit via decoded flag or verified rule."
                                ),
                            )
                            ok = hub.enqueue_step(plan, s, context)
                            if ok:
                                context.route_tracker["static_template_enqueued"] = True
                                static_enqueued = True
                                context.add_support_request({
                                    "from": self.role,
                                    "to": "ReverseExecutorAgent",
                                    "payload": "Capability gate: dynamic/symexec step blocked; static table-driven template enqueued.",
                                })
                        except Exception:
                            pass
                    continue

                # (removed: legacy inline stop-loss guard – handled after execution below)
                # Record executed fingerprint for dedup in subsequent rounds
                try:
                    executed.add(_fp(step))
                    context.route_tracker["executed_fingerprints"] = executed
                except Exception:
                    pass
                self.log(
                    "dispatch_step",
                    {"plan_id": plan.plan_id, "step": step.description, "executor": role},
                )
                hub.execute_step(role, plan, step, context)
                # Stop-loss routing: same-route two-step no-growth -> force route switch
                try:
                    # Read per-route progress maintained by executors
                    prog = context.route_tracker.get("route_progress", {}) or {}
                    route = _route_of(step)
                    state = prog.get(route, {}) if isinstance(prog, dict) else {}
                    ng = int((state or {}).get("no_growth", 0) or 0)
                    if ng >= 2:
                        if route in ("dynsym", "static_flow") and not bool(context.route_tracker.get("static_template_enqueued", False)):
                            from framework.plans import TaskStep
                            s = TaskStep(
                                description="Static table-driven route (extract→infer→replay)",
                                objective="Static template",
                                tools=["radare2", "strings", "otool", "llvm-readobj", "llvm-objdump"],
                                validation="coordinate+neighborhood(>=64B)+target(replay Good!/validated)",
                                assigned_executor="ReverseExecutorAgent",
                            )
                            if hub.enqueue_step(plan, s, context):
                                context.route_tracker["static_template_enqueued"] = True
                                context.route_tracker["force_static_template"] = True
                                context.add_support_request({
                                    "from": self.role,
                                    "to": "ReverseExecutorAgent",
                                    "payload": "Stop-loss: same-route two steps without verified growth; pivot to static table-driven template.",
                                })
                        elif route in ("const_template",) and not bool(context.route_tracker.get("data_plane_enqueued", False)):
                            from framework.plans import TaskStep
                            s2 = TaskStep(
                                description="Data-plane fallback: scan .rodata printable sequences and apply prefix filters",
                                objective="Data-plane fallback",
                                tools=["radare2", "strings", "otool", "llvm-readobj"],
                                validation="coordinate+neighborhood(>=64B)+target(candidate length=36 or validated)",
                                assigned_executor="ReverseExecutorAgent",
                            )
                            if hub.enqueue_step(plan, s2, context):
                                context.route_tracker["data_plane_enqueued"] = True
                                context.add_support_request({
                                    "from": self.role,
                                    "to": "ReverseExecutorAgent",
                                    "payload": "Stop-loss: template route two steps without verified growth; pivot to data-plane fallback (.rodata printable + prefix).",
                                })
                except Exception:
                    pass

                # Immediately drain adaptively enqueued steps (e.g., stop-loss route switches)
                try:
                    # Capability snapshot
                    cap = {"qemu": False, "angr": False, "readelf": False, "objdump": False, "llvm-objdump": False, "llvm-readobj": False, "otool": False, "radare2": False, "strings": False}
                    for e in reversed(context.evidence):
                        if isinstance(e.title, str) and e.title.lower() == "capability card":
                            import json as _json
                            try:
                                data = _json.loads(e.context or "{}")
                                for k in cap.keys():
                                    cap[k] = bool((data.get(k) or {}).get("ok", False))
                            except Exception:
                                txt = str(e.summary or "")
                                cap["qemu"] = ("qemu-x86_64=yes" in txt)
                                cap["angr"] = ("angr=yes" in txt)
                                cap["readelf"] = ("readelf=yes" in txt)
                            break
                    while hub.has_pending():
                        nxt = hub.pop_next()
                        if not nxt:
                            break
                        r = nxt.assigned_executor or ""
                        tset2 = set(nxt.tools or [])
                        # Stop-loss dedup for pending steps as well
                        try:
                            rt = context.route_tracker.get("route_stats", {}) or {}
                            if int(rt.get("no_growth_streak", 0) or 0) >= 2:
                                fp2 = _fp(nxt)
                                if fp2 in executed:
                                    context.log_execution({
                                        "agent": self.role,
                                        "plan_id": plan.plan_id,
                                        "step": nxt.description,
                                        "status": "skipped_duplicate",
                                        "step_id": nxt.step_id or "",
                                    })
                                    continue
                        except Exception:
                            pass
                        needs_qemu2 = ("qemu" in tset2 or "qemu-x86_64" in tset2)
                        needs_readelf2 = ("readelf" in tset2)
                        needs_objdump2 = ("objdump" in tset2)
                        needs_angr2 = (r == "SymExecExecutorAgent") or ("angr" in tset2)
                        needs_r22 = ("radare2" in tset2 or "r2" in tset2 or "rabin2" in tset2)
                        needs_strings2 = ("strings" in tset2)
                        def _cap(tool: str) -> bool:
                            return bool(cap.get(tool, False))
                        if (
                            (needs_qemu2 and not _cap("qemu")) or
                            (needs_readelf2 and not (_cap("readelf") or _cap("llvm-readobj") or _cap("otool"))) or
                            (needs_objdump2 and not (_cap("objdump") or _cap("llvm-objdump") or _cap("otool"))) or
                            (needs_angr2 and not _cap("angr")) or
                            (needs_r22 and not (_cap("radare2") or _cap("rabin2"))) or
                            (needs_strings2 and not _cap("strings"))
                        ):
                            context.log_execution({
                                "agent": self.role,
                                "plan_id": plan.plan_id,
                                "step": nxt.description,
                                "status": "blocked_missing_capability",
                                "step_id": nxt.step_id or "",
                            })
                            continue
                        try:
                            executed.add(_fp(nxt))
                            context.route_tracker["executed_fingerprints"] = executed
                        except Exception:
                            pass
                        self.log(
                            "dispatch_step",
                            {"plan_id": plan.plan_id, "step": nxt.description, "executor": r},
                        )
                        hub.execute_step(r, plan, nxt, context)
                except Exception:
                    pass

            # If we enqueued a static template step due to stop-loss, dispatch it immediately
            if force_static and static_enqueued:
                try:
                    # drain any enqueued steps for ReverseExecutorAgent
                    while True:
                        s = hub.pop_next_for("ReverseExecutorAgent")
                        if not s:
                            break
                        self.log(
                            "dispatch_step",
                            {"plan_id": plan.plan_id, "step": s.description, "executor": "ReverseExecutorAgent"},
                        )
                        hub.execute_step("ReverseExecutorAgent", plan, s, context)
                except Exception:
                    pass
            self.log("dispatch_complete", {"plan_id": plan.plan_id, "mode": "stepwise"})
        self.clear_context()

    def _build_prompt(self, plan: TaskPlan) -> str:
        bullet_steps = "\n".join(
            f"- {step.description} (executor: {step.assigned_executor})"
            for step in plan.steps
        )
        return (
            "You are the General coordinating a CTF operation.\n"
            "Evaluate the Strategist's plan. Highlight strengths, missing checks, "
            "resource conflicts, and add actionable adjustments. "
            "Write in concise bullet style and end with APPROVE or REVISE.\n"
            f"Plan hypothesis: {plan.hypothesis}\n"
            f"Category: {plan.category}\n"
            f"Steps:\n{bullet_steps}\n"
        )

    def _should_approve(self, critique: str) -> bool:
        normalized = critique.lower()
        if "approve" in normalized and "revise" not in normalized:
            return True
        if any(keyword in normalized for keyword in REVISION_KEYWORDS):
            return False
        return any(keyword in normalized for keyword in APPROVAL_KEYWORDS)

    def _evaluate_plan(self, plan: TaskPlan) -> tuple[bool, str]:
        missing: list[str] = []
        if not plan.steps or len(plan.steps) < 3:
            missing.append("不足三步的原子化任务")
        for idx, step in enumerate(plan.steps, 1):
            if not step.assigned_executor:
                missing.append(f"第{idx}步未指定执行者")
            if not step.validation or not step.validation.strip():
                missing.append(f"第{idx}步未定义验证方式")
            if not step.tools:
                missing.append(f"第{idx}步未列出工具")
            # Triad acceptance must be explicitly declared
            vtxt = (step.validation or "").lower()
            triad_keys = ["coordinate", "neighborhood", "target"]
            if not all(k in vtxt for k in triad_keys):
                missing.append(f"第{idx}步未声明三件套验收（coordinate/neighborhood/target）")
            # Target prefix normalization to d3ctf{}
            if "d3ctf{" not in vtxt and "prefix" not in vtxt:
                missing.append(f"第{idx}步未声明目标前缀校正为 d3ctf{{}}")
        # Gate: disallow qemu/angr routes when unavailable
        try:
            # Gate based on Capability Card only
            qemu_ok = False
            angr_ok = False
            if hasattr(self, "_context") and self._context:
                for e in reversed(self._context.evidence):
                    if isinstance(e.title, str) and e.title.lower() == "capability card":
                        txt = str(e.summary or "")
                        qemu_ok = ("qemu-x86_64=yes" in txt)
                        angr_ok = ("angr=yes" in txt)
                        break
            for idx, step in enumerate(plan.steps, 1):
                tset = set(step.tools or [])
                if ("qemu" in tset or "qemu-x86_64" in tset) and not qemu_ok:
                    missing.append(f"第{idx}步需要 qemu，但当前不可用；请先安装或改为静态路线")
                if (step.assigned_executor == "SymExecExecutorAgent" or "angr" in tset) and not angr_ok:
                    missing.append(f"第{idx}步需要 angr，但当前不可用或未启用；请先安装/启用或改为静态路线")
        except Exception:
            pass
        # Stop-loss route switch policy must be present at plan level
        notes = (plan.notes or "").lower()
        if not ("routepolicy" in notes or "stop-loss" in notes or "no_growth" in notes):
            missing.append("未声明止损切线策略（无增长两步自动换线）")
        if missing:
            critique = "REVISE: 需要完善以下问题:\n- " + "\n- ".join(missing)
            return False, critique
        return True, "APPROVE: 计划完整、可执行，进入执行阶段。"

    def _select_primary_executor(self, plan: TaskPlan) -> str:
        # If all steps specify the same executor, honor it
        roles = {s.assigned_executor for s in plan.steps if s.assigned_executor}
        if len(roles) == 1:
            return next(iter(roles)) or "MiscExecutorAgent"
        # Prefer highest-scoring executor for this category when available
        try:
            from framework.knowledge import SkillBook  # local to avoid import loops
            sb = getattr(self, "_context").skillbook if hasattr(self, "_context") and getattr(self, "_context") else None
            if sb and getattr(sb, "scores", None):
                cat = (plan.category or "Misc").title()
                candidates = [
                    "ReverseExecutorAgent",
                    "PwnExecutorAgent",
                    "CryptoExecutorAgent",
                    "ForensicsExecutorAgent",
                    "WebExecutorAgent",
                    "MiscExecutorAgent",
                ]
                best = None
                best_score = -1.0
                for r in candidates:
                    info = (sb.scores.get(r, {}) or {}).get(cat, {}) or {}
                    ema = float(info.get("ema", 0.0) or 0.0)
                    if ema > best_score:
                        best = r
                        best_score = ema
                if best:
                    return best
        except Exception:
            pass
        # Fallback map by category
        cat = (plan.category or "").lower()
        mapping = {
            "reverse": "ReverseExecutorAgent",
            "pwn": "PwnExecutorAgent",
            "crypto": "CryptoExecutorAgent",
            "forensics": "ForensicsExecutorAgent",
            "web": "WebExecutorAgent",
            "misc": "MiscExecutorAgent",
        }
        return mapping.get(cat, "MiscExecutorAgent")

    def _ensure_tools_for_plan(self, context: CaseContext, plan: TaskPlan) -> None:
        """
        Verify required tools from plan steps are present; install via Homebrew/pip when
        configured. Skips non-macOS brew installs. Records evidence and support requests.
        """
        # Aggregate declared tools from plan
        declared: list[str] = []
        for s in plan.steps:
            for t in (s.tools or []):
                if t and t not in declared:
                    declared.append(t)

        # Map tool -> binaries to check
        check_bin_map = {
            "r2": ["r2"],
            "radare2": ["r2"],
            "rabin2": ["rabin2"],
            "binwalk": ["binwalk"],
            "qemu": ["qemu-x86_64"],
            "qemu-x86_64": ["qemu-x86_64"],
            "ghidra": ["ghidra"],
            "strings": ["strings"],
            "otool": ["otool"],
            "nm": ["nm"],
            "readelf": ["readelf"],
            "objdump": ["objdump"],
            "llvm-objdump": ["llvm-objdump"],
            "llvm-readobj": ["llvm-readobj"],
        }
        missing: list[str] = []
        for tool in declared:
            bins = check_bin_map.get(tool, [])
            if not bins:
                continue
            if not any(context.which(b) for b in bins):
                missing.append(tool)

        # Record environment check
        if missing:
            summary = f"Missing tools: {', '.join(missing)}"
            try:
                from framework.evidence import EvidenceCard
                context.add_evidence(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Tool availability (preflight)",
                        summary=summary,
                        tool="shell",
                        command="which <tool>",
                        context=summary,
                        tags=["env", "tools"],
                        created_by=self.role,
                    )
                )
            except Exception:
                pass

        # Stop-loss counters for repeated missing tools (readelf/qemu)
        try:
            rt = context.route_tracker
            miss_set = set(missing)
            if "readelf" in miss_set:
                rt["missing_readelf_count"] = int(rt.get("missing_readelf_count", 0) or 0) + 1
            if "qemu-x86_64" in miss_set or "qemu" in miss_set:
                rt["missing_qemu_count"] = int(rt.get("missing_qemu_count", 0) or 0) + 1
            # Engage stop-loss if repeated
            if int(rt.get("missing_readelf_count", 0) or 0) >= 2 or int(rt.get("missing_qemu_count", 0) or 0) >= 2:
                if not rt.get("force_static_template"):
                    rt["force_static_template"] = True
                    try:
                        context.add_support_request({
                            "from": self.role,
                            "to": "Team",
                            "payload": "Stop-loss engaged: repeated readelf/qemu missing; switching to static table-driven template and halting dynamic/symexec dispatch.",
                        })
                    except Exception:
                        pass
        except Exception:
            pass

        # Auto-install is now handled exclusively by Installer before dispatch.

        # Update declared/missing tool stats for adaptive weighting
        try:
            rt = context.route_tracker.setdefault("route_stats", {})  # type: ignore[assignment]
            if isinstance(rt, dict):
                rt["declared_tools"] = int(rt.get("declared_tools", 0) or 0) + len(declared)
                rt["missing_tools"] = int(rt.get("missing_tools", 0) or 0) + len(missing)
                if context.logger:
                    payload = {
                        "total_steps": str(int(rt.get("total_steps", 0) or 0)),
                        "triad_verified": str(int(rt.get("triad_verified", 0) or 0)),
                        "verified_over_all": f"{int(rt.get('triad_verified',0) or 0)}/{int(rt.get('total_steps',0) or 0)}",
                        "first_try_rate": f"{int(rt.get('first_try_verified',0) or 0)}/{int(rt.get('total_steps',0) or 0)}",
                        "zero_growth": str(int(rt.get("zero_growth", 0) or 0)),
                        "tool_missing_ratio": f"{int(rt.get('missing_tools',0) or 0)}/{int(rt.get('declared_tools',0) or 0)}",
                    }
                    context.logger.record_event("MissionController", "stats_update", payload)
        except Exception:
            pass

        # If still missing, mark steps that depend on missing tools as blocked in execution log
        if missing:
            missing_set = set(missing)
            for s in plan.steps:
                tset = set(s.tools or [])
                if tset & missing_set:
                    try:
                        context.log_execution({
                            "agent": self.role,
                            "plan_id": plan.plan_id,
                            "step": s.description,
                            "status": "blocked_missing_tool",
                            "step_id": s.step_id or "",
                        })
                        context.add_support_request({
                            "from": self.role,
                            "to": s.assigned_executor or "General",
                            "payload": f"Missing tools for step '{s.description}': {', '.join(sorted(tset & missing_set))}",
                        })
                    except Exception:
                        pass

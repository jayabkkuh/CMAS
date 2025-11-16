"""
Strategist agent: turn evidence into candidate plans.
"""

from __future__ import annotations

from typing import List

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import BaseAgent


CATEGORY_KEYWORDS = {
    "Reverse": ["ELF", "PE", "disasm", "function", "r2", "radare2"],
    "Pwn": ["stack", "overflow", "ptr", "printf"],
    "Crypto": ["encrypt", "cipher", "key", "rsa", "xor"],
    "Forensics": ["disk", "image", "filesystem", "binwalk"],
    "Misc": ["note", "puzzle", "text"],
    "Web": ["http", "request", "cookie", "csrf"],
}


class StrategistAgent(BaseAgent):
    role = "Strategist"

    def run(self, context: CaseContext, **kwargs) -> TaskPlan:
        self.bind_context(context)
        self.log("round_start", {"evidence": str(len(context.evidence))})
        category = self._infer_category(context.evidence)
        feedback = kwargs.get("feedback")
        # Offline-friendly deterministic analysis (no network calls)
        facts = "\n".join(
            f"- [{card.id}] {card.title}: {card.summary[:120]}" for card in context.evidence
        )
        analysis = (
            f"Strategist auto-plan (category={category}).\n"
            f"Evidence summary:\n{facts}\n"
            + (f"General notes: {feedback}\n" if feedback else "")
        )
        # Inject global priors (flag patterns) for downstream executors and Validator
        try:
            pats = list(getattr(context.config, "flag_patterns", []) or [])
            if pats:
                analysis += "\n[Priors] flag_patterns active:\n" + "\n".join(f"- {p}" for p in pats[:5])
        except Exception:
            pass
        skill_suggestions = context.suggest_from_skillbook(category, role=self.role)
        if skill_suggestions:
            playbook = "\n".join(
                f"* {entry.pattern} -> {entry.takeaway}" for entry in skill_suggestions
            )
            analysis = f"{analysis}\n[SkillBook]\n{playbook}"
        try:
            if getattr(context.config, "include_scoreboard_in_planning", True) and context.skillbook:
                board = context.skillbook.format_scoreboard()
                if isinstance(board, str) and board.strip():
                    analysis = f"{analysis}\n[Scores]\n{board}"
        except Exception:
            pass

        # Call LLM for planning suggestions (mandatory model usage) with JSON plan attempt
        try:
            prompt = self._build_prompt(context.evidence, category, feedback=feedback, dry_run=bool(getattr(context.config, "dry_run", False)))
            schema = (
                '{"category":"Reverse|Pwn|Crypto|Forensics|Misc|Web","steps":[{"description":"string","executor":"ReverseExecutorAgent|PwnExecutorAgent|CryptoExecutorAgent|ForensicsExecutorAgent|MiscExecutorAgent|WebExecutorAgent|SymExecExecutorAgent","tools":["string"],"validation":"string"}]}'
            )
            data = self.ask_json(prompt, schema_hint=schema)  # type: ignore[attr-defined]
            resp_text = None
            if isinstance(data, dict) and data.get("steps"):
                try:
                    cat = str(data.get("category") or "").strip()
                    if cat:
                        category = cat
                    steps_json = data.get("steps") or []
                    new_steps: List[TaskStep] = []
                    for s in steps_json:
                        desc = str(s.get("description") or "").strip()
                        ex = str(s.get("executor") or "").strip() or "MiscExecutorAgent"
                        tools = [str(t) for t in (s.get("tools") or []) if t]
                        val = str(s.get("validation") or "").strip()
                        if desc:
                            new_steps.append(
                                TaskStep(description=desc, objective=desc, tools=tools, validation=val, assigned_executor=ex)
                            )
                    if new_steps:
                        steps = new_steps
                except Exception:
                    pass
            else:
                resp_text = str(self.call_model(prompt))
            from framework.evidence import EvidenceCard
            card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Strategist LLM reasoning",
                summary=(resp_text or str(data))[:400],
                tool="LLM",
                command="strategist_planning",
                context=resp_text or (str(data) if data is not None else ""),
                tags=["planning", "info"],
                created_by=self.role,
            )
            context.add_evidence(card)
            analysis = f"{analysis}\n[LLM]\n{(resp_text or str(data))[:800]}"
        except Exception:
            pass

        plan = TaskPlan(
            plan_id=context.next_id("plan"),
            hypothesis=f"Primary direction: {category}",
            category=category,
            notes=str(analysis),
            steps=locals().get("steps") if locals().get("steps") else self._build_steps(category, context=context),
            agree_flag=0,
            status="proposed",
            version=context.next_id("planv"),
        )
        # Reorder step tools by past success for the assigned executor (if any)
        try:
            if context.skillbook:
                for s in plan.steps:
                    role = s.assigned_executor or ""
                    if not role or not s.tools:
                        continue
                    prefs = context.skillbook.get_tool_preference(role)
                    if prefs:
                        # stable sort tools by preference score
                        s.tools.sort(key=lambda t: (prefs.index(t) if t in prefs else 1e9))
        except Exception:
            pass
        # Embed an AGREE token in notes for auditability (initially disagree) and stop-loss policy
        plan.notes = (
            (plan.notes or "")
            + "\nAGREE=0"
            + "\n[RoutePolicy] 默认：静态优先 · 表驱动模板（收割 .rodata 表 → 抽逐字节规则（逆/正）→ 正向回放验证）。"
            + "\n[RoutePolicy] 动态/符号：仅用于加速与交叉验证，绝不作硬依赖。"
            + "\n[Constraints] 全局前置：prefix=d3ctf{} 且长度=36；终审：必须通过正向回放 Good!/validated（候选串不含回放不计分）。"
            + "\n[RoutePolicy] stop-loss: if no new verified for 2 steps on a route, auto-switch with new acceptance + artifacts."
        )
        try:
            context.record_dialogue(self.role, "response", f"Proposed plan {plan.plan_id} (category={category}).\nAGREE=0")
        except Exception:
            pass
        # Capability-aware precheck and route rewrite before proposal, prefer
        # consuming existing capability card (emitted by Installer). If absent,
        # treat as unavailable and rewrite to static-first route.
        try:
            self._capability_precheck_and_rewrite(context, plan)
        except Exception as exc:
            self.log("precheck_error", {"error": str(exc)})
        context.add_strategy_revision(plan)
        try:
            steps_payload = [
                {
                    "description": s.description,
                    "executor": s.assigned_executor or "",
                    "tools": list(s.tools or []),
                    "validation": s.validation,
                }
                for s in plan.steps
            ]
        except Exception:
            steps_payload = []
        self.log(
            "plan_proposed",
            {
                "plan_id": plan.plan_id,
                "category": category,
                "hypothesis": plan.hypothesis,
                "version": plan.version or "",
                "status": plan.status,
                "agree": str(plan.agree_flag),
                "notes": plan.notes or "",
                "steps": steps_payload,
            },
        )
        self.clear_context()
        return plan

    def _infer_category(self, evidence_list: List[EvidenceCard]) -> str:
        scores = {category: 0 for category in CATEGORY_KEYWORDS}
        for card in evidence_list:
            haystack = f"{card.title} {card.summary} {card.context or ''}".lower()
            for category, keywords in CATEGORY_KEYWORDS.items():
                for keyword in keywords:
                    if keyword.lower() in haystack:
                        scores[category] += 1
        best_category = max(scores, key=scores.get)
        if scores[best_category] == 0:
            return "Misc"
        return best_category

    def _build_prompt(
        self,
        evidence_list: List[EvidenceCard],
        category: str,
        feedback: str | None = None,
        dry_run: bool = False,
    ) -> str:
        facts = "\n".join(
            f"- [{card.id}] {card.title}: {card.summary}" for card in evidence_list
        )
        revision_clause = ""
        if feedback:
            revision_clause = (
                "\nThe General provided revision notes:\n"
                f"{feedback}\n"
                "Address these points explicitly."
            )
        dry_clause = (
            "\nNote: Dry-run mode is active. Focus on planning and tool selection;"
            " do not assume commands have been executed."
            if dry_run
            else ""
        )
        prompt = (
            "You are the Strategist in a CTF multi-agent team.\n"
            f"Likely category: {category}.\n"
            "Given the evidence, outline high-level reasoning themes and potential attack paths.\n"
            f"Evidence summary:\n{facts}\n"
            f"{revision_clause}{dry_clause}"
        )
        prompt += "\nEnvironment: macOS Terminal (zsh). Prefer macOS-compatible toolchain (otool, llvm-objdump, llvm-readobj)."
        return prompt

    def _build_steps(self, category: str, context: CaseContext | None = None) -> List[TaskStep]:
        default_steps = {
            "Reverse": [
                ("Generate Address Mapping (baddr/sections) for coordinate normalization", "ReverseExecutorAgent"),
                ("Harvest .rodata tables/constants (RIP-relative, indirect jumps) and locate hotspots", "ReverseExecutorAgent"),
                ("Infer per-byte decoding rule (inverse + forward) from harvested tables; emit reproducible rule JSON", "ReverseExecutorAgent"),
                ("Forward replay using inferred rule to verify expected output (Good!/flag)", "ReverseExecutorAgent"),
            ],
            "Pwn": [
                ("Map binary protections", "PwnExecutorAgent"),
                ("Locate overflow primitives", "PwnExecutorAgent"),
                ("Craft exploit payload", "PwnExecutorAgent"),
            ],
            "Crypto": [
                ("Characterize algorithm family", "CryptoExecutorAgent"),
                ("Recover key or weakness", "CryptoExecutorAgent"),
                ("Validate decryption yields flag", "CryptoExecutorAgent"),
            ],
            "Forensics": [
                ("Extract embedded artifacts", "ForensicsExecutorAgent"),
                ("Inspect recovered files for clues", "ForensicsExecutorAgent"),
                ("Correlate timestamps with story", "ForensicsExecutorAgent"),
            ],
            "Web": [
                ("Enumerate routes and params", "WebExecutorAgent"),
                ("Test auth/session handling", "WebExecutorAgent"),
                ("Exploit vulnerability to leak flag", "WebExecutorAgent"),
            ],
            "Misc": [
                ("Break down puzzle constraints", "MiscExecutorAgent"),
                ("Prototype solver", "MiscExecutorAgent"),
                ("Confirm solution matches flag format", "MiscExecutorAgent"),
            ],
        }

        steps: List[TaskStep] = []
        steps_src = list(default_steps.get(category, default_steps["Misc"]))
        # Optionally add symbolic execution step for Reverse/Pwn
        if category in ("Reverse", "Pwn") and (context and getattr(context.config, "enable_angr", False)):
            steps_src.append(("(Optional) Symbolically explore key checks (cross-check)", "SymExecExecutorAgent"))
        for description, executor in steps_src:
            tools: List[str] = []
            if category == "Reverse":
                # Static-first, table-driven template toolchain
                tools.extend(["radare2", "strings"])
                if context and context.is_macos():
                    for t in ("otool", "llvm-readobj", "llvm-objdump"):
                        if t not in tools:
                            tools.append(t)
                else:
                    for t in ("readelf", "objdump"):
                        if t not in tools:
                            tools.append(t)
            elif category == "Pwn":
                tools.extend(["pwntools"]) 
            else:
                tools.append("python")
            # Specialized validation text for the mapping step; otherwise use triad guidance
            if "Address Mapping" in description:
                validation = (
                    "Emit Address Mapping card (JSON) with baddr (default 0x400000) and sections array; "
                    "artifact saved and referenced by subsequent evidence (mapping_card_id)."
                )
            else:
                validation = (
                    "Static-first · table-driven: harvest .rodata tables/constants (RIP-relative/indirect jump) → infer per-byte inverse+forward transform. "
                    "Prefilter: prefix d3ctf{} and body length=36. Final acceptance: forward replay Good!/validated (candidate-only does not count). "
                    "Triad: coordinate (paddr/vaddr/section) + neighborhood (hex/disasm, 64–128B, SHA-256) + target (forward replay Good!/flag)."
                )
            steps.append(
                TaskStep(
                    description=description,
                    objective=description,
                    tools=tools,
                    validation=validation,
                    assigned_executor=executor,
                )
            )
        return steps

    def _capability_precheck_and_rewrite(self, context: CaseContext, plan: TaskPlan) -> None:
        """
        For steps requiring qemu/angr, only allow if capability is present; otherwise
        rewrite to static-first route (r2/objdump/readelf/strings) or mark for installation.
        Also emit a Capability Card evidence with current availability snapshot.
        """
        # Prefer capability card from Installer; if not present, assume unavailable
        def _cap_card() -> dict:
            for e in reversed(context.evidence):
                if isinstance(e.title, str) and e.title.lower() == "capability card":
                    return {"summary": e.summary or ""}
            return {}
        card = _cap_card()
        text = str(card.get("summary", ""))
        qemu_ok = ("qemu-x86_64=yes" in text)
        angr_ok = ("angr=yes" in text)
        # capability card
        from framework.evidence import EvidenceCard
        summary = f"Capabilities: qemu-x86_64={'yes' if qemu_ok else 'no'}, angr={'yes' if angr_ok else 'no'}, enable_angr={'yes' if getattr(context.config, 'enable_angr', False) else 'no'}"
        context.add_evidence(
            EvidenceCard(
                id="",
                source_agent=self.role,
                title="Capability Card",
                summary=summary,
                tool="env",
                command="which qemu-x86_64; python -c 'import angr'",
                context=summary,
                tags=["env", "capability"],
                created_by=self.role,
            )
        )
        # Adjust route weights based on capability and runtime stats
        weights = context.route_tracker.setdefault("route_weights", {})  # type: ignore[assignment]
        if not isinstance(weights, dict):
            weights = {}
            context.route_tracker["route_weights"] = weights
        # Default policy: static-first regardless of dynamic capability; dynsym
        # is only an accelerator/cross-check.
        weights.update({"dynsym": 0.3, "static_flow": 1.2, "const_template": 1.15})
        # Metrics: missing tool ratio and zero-growth ratio
        try:
            rt = context.route_tracker.get("route_stats", {}) or {}
            miss = int(rt.get("missing_tools", 0) or 0)
            decl = int(rt.get("declared_tools", 0) or 0)
            zg = int(rt.get("zero_growth", 0) or 0)
            tot = int(rt.get("total_steps", 0) or 0)
            miss_ratio = (miss / decl) if decl else 0.0
            zg_ratio = (zg / tot) if tot else 0.0
        except Exception:
            miss_ratio = 0.0
            zg_ratio = 0.0
        if miss_ratio >= 0.3 or zg_ratio >= 0.5:
            weights["dynsym"] = min(weights.get("dynsym", 1.0), 0.2)
            weights["static_flow"] = max(weights.get("static_flow", 1.0), 1.1)
            weights["const_template"] = max(weights.get("const_template", 0.9), 1.0)
            plan.notes = (plan.notes or "") + f"\n[RoutePolicy] metrics: missing={miss}/{decl}, zero_growth={zg}/{tot} → prefer static/data-plane"
        # Stabilize preferred route on consecutive verified
        try:
            pref = str(context.route_tracker.get("preferred_route", "") or "")
            if pref:
                plan.notes = (plan.notes or "") + f"\n[RoutePolicy] prefer route={pref} (consecutive growth)"
                if pref == "static_flow":
                    weights["static_flow"] = max(weights.get("static_flow", 1.0), 1.2)
                    weights["dynsym"] = min(weights.get("dynsym", 1.0), 0.2)
                elif pref == "const_template":
                    weights["const_template"] = max(weights.get("const_template", 0.9), 1.1)
                    weights["dynsym"] = min(weights.get("dynsym", 1.0), 0.2)
        except Exception:
            pass

        # Rewrite rules
        # Prefer macOS-friendly static toolchain by default; only fall back to
        # GNU readelf/objdump on non-macOS. This ensures downstream evidence can
        # be normalized into structured artifacts consistently.
        static_defaults = ["radare2", "strings"]
        try:
            if context and context.is_macos():
                for t in ("otool", "llvm-readobj", "llvm-objdump"):
                    if t not in static_defaults:
                        static_defaults.append(t)
            else:
                for t in ("readelf", "objdump"):
                    if t not in static_defaults:
                        static_defaults.append(t)
        except Exception:
            # Fallback if context is unavailable
            static_defaults.extend(["readelf", "objdump"])
        for s in plan.steps:
            tools = list(s.tools or [])
            needs_qemu = any(t in ("qemu", "qemu-x86_64") for t in tools)
            needs_angr = (s.assigned_executor == "SymExecExecutorAgent") or ("angr" in tools)
            if needs_qemu and not qemu_ok:
                # rewrite to static-first route; strip qemu tools
                tools = [t for t in tools if t not in ("qemu", "qemu-x86_64")]
                for t in static_defaults:
                    if t not in tools:
                        tools.append(t)
                s.tools = tools
                plan.notes = (plan.notes or "") + "\n[Rewrite] qemu missing → static-first route"  
            if needs_angr and (not getattr(context.config, "enable_angr", False) or not angr_ok):
                # prefer downgrading symexec step into reverse static analysis
                if s.assigned_executor == "SymExecExecutorAgent":
                    s.assigned_executor = "ReverseExecutorAgent"
                if "angr" in tools:
                    tools = [t for t in tools if t != "angr"]
                for t in static_defaults:
                    if t not in tools:
                        tools.append(t)
                s.tools = tools
                plan.notes = (plan.notes or "") + "\n[Rewrite] angr unavailable → static-first route"
        # Demote or remove SymExec step if dynsym weight low
        try:
            if float(weights.get("dynsym", 1.0)) < 0.6:
                plan.steps = [s for s in plan.steps if s.assigned_executor != "SymExecExecutorAgent"]
                plan.notes = (plan.notes or "") + "\n[Rewrite] dynsym weight low → remove symexec step"
        except Exception:
            pass

    def _ensure_tools(self, context: CaseContext, plan: TaskPlan) -> None:
        # Only act on macOS
        if not context.is_macos():
            return
        # Collect tools declared by planned steps
        declared: List[str] = []
        for s in plan.steps:
            for t in (s.tools or []):
                if t and t not in declared:
                    declared.append(t)
        # Map known tool aliases to binaries to check
        check_bin_map = {
            "r2": ["r2"],
            "radare2": ["r2"],
            "rabin2": ["rabin2"],
            "binwalk": ["binwalk"],
            # macOS distributes qemu-system-x86_64 instead of qemu-x86_64 (Linux user-mode).
            "qemu": ["qemu-system-x86_64", "qemu-x86_64"],
            "qemu-x86_64": ["qemu-system-x86_64", "qemu-x86_64"],
            # Homebrew installs Ghidra as ghidraRun; include both names.
            "ghidra": ["ghidraRun", "ghidra"],
            "strings": ["strings"],
            "otool": ["otool"],
            "nm": ["nm"],
        }
        install_map = dict(getattr(context.config, "tool_install_map", {}))
        casks = set(getattr(context.config, "tool_install_casks", []))
        auto_install = bool(getattr(context.config, "auto_install_tools", False))
        brew_bin = getattr(context.config, "brew_bin", "brew")

        missing: List[str] = []
        for tool in declared:
            bins = check_bin_map.get(tool, [])
            if not bins:
                continue
            found = any(context.which(b) for b in bins)
            if not found:
                missing.append(tool)

        if not missing:
            return

        # Record a summary evidence about missing tools
        summary = f"Missing tools on macOS: {', '.join(missing)}"
        context.add_evidence(
            EvidenceCard(
                id="",
                source_agent=self.role,
                title="Tool availability check",
                summary=summary,
                tool="shell",
                command="which <tool>",
                context=summary,
                tags=["env", "tools"],
                created_by=self.role,
            )
        )

        if not auto_install:
            # Only report; do not install
            return

        # Ensure Homebrew present if allowed
        if not context.which(brew_bin):
            if not getattr(context.config, "brew_install_allowed", False):
                self.log("brew_missing", {"hint": "brew not found and auto install disabled"})
                return
            # Attempt brew installation via official script
            install_cmd = (
                '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            )
            res = context.run_command(
                self.role,
                "install homebrew",
                install_cmd,
                artifact_name=f"{plan.plan_id}_install_brew.txt",
                use_shell=True,
                timeout_secs=1800,
            )
            # Try common brew locations
            for candidate in ("brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
                if context.which(candidate):
                    brew_bin = candidate
                    break

        # Install each missing tool using brew (or cask)
        for tool in missing:
            pkg = install_map.get(tool)
            if not pkg:
                continue
            is_cask = pkg in casks
            cmd = f"{brew_bin} install {'--cask ' if is_cask else ''}{pkg}"
            res = context.run_command(
                self.role,
                f"install {pkg}",
                cmd,
                artifact_name=f"{plan.plan_id}_install_{pkg}.txt",
                use_shell=True,
                timeout_secs=1800,
            )
            # Attach as evidence entry per tool
            out = str(res.get("stdout", "")) or str(res.get("stderr", ""))
            context.add_evidence(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title=f"Tool installation attempt: {pkg}",
                    summary=(out[:400] if out else "(no output)"),
                    tool="brew",
                    command=cmd,
                    context=out,
                    tags=["env", "install"],
                    created_by=self.role,
                )
            )

        # Python packages check/install (cross-platform)
        auto_py = bool(getattr(context.config, 'auto_install_python_tools', False))
        pip_allowed = bool(getattr(context.config, 'pip_install_allowed', False))
        if auto_py and pip_allowed:
            py_tool_map = dict(getattr(context.config, 'python_tool_map', {}))
            import_map = dict(getattr(context.config, 'python_import_map', {}))
            py = getattr(context.config, 'python_bin', 'python3')
            pip = getattr(context.config, 'pip_bin', 'pip3')
            # derive declared python tools
            py_needed: List[str] = []
            for s in plan.steps:
                for t in (s.tools or []):
                    if t in py_tool_map and t not in py_needed:
                        py_needed.append(t)
            for t in py_needed:
                mod = import_map.get(t)
                if not mod:
                    continue
                chk = context.run_command(
                    self.role,
                    f"check python module {mod}",
                    f"{py} -c 'import {mod}; print(\"ok\")'",
                    use_shell=True,
                    artifact_name=f"{plan.plan_id}_pycheck_{mod}.txt",
                )
                if chk.get('returncode') == 0:
                    continue
                pkg = py_tool_map.get(t)
                if not pkg:
                    continue
                inst = context.run_command(
                    self.role,
                    f"pip install {pkg}",
                    f"{pip} install {pkg}",
                    use_shell=True,
                    artifact_name=f"{plan.plan_id}_pip_{pkg}.txt",
                    timeout_secs=1800,
                )
                # evidence record
                out = str(inst.get('stdout', '')) or str(inst.get('stderr', ''))
                context.add_evidence(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title=f"Python package installation: {pkg}",
                        summary=(out[:400] if out else "(no output)"),
                        tool="pip",
                        command=f"{pip} install {pkg}",
                        context=out,
                        tags=["env", "install", "python"],
                        created_by=self.role,
                    )
                )

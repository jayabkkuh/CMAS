"""
Symbolic execution executor (optional, via angr).
"""

from __future__ import annotations

from typing import List, Optional
import json
import logging

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class SymExecExecutorAgent(ExecutorAgent):
    role = "SymExecExecutorAgent"
    category = "Reverse"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        cards: List[EvidenceCard] = []
        if not getattr(context.config, "enable_angr", False):
            note = "angr disabled in config.enable_angr"
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Symbolic execution skipped",
                    summary=note,
                    tool="angr",
                    command="n/a",
                    context=note,
                    tags=["symexec", "disabled"],
                    created_by=self.role,
                )
            )
            return cards
        try:
            import angr  # type: ignore
            import claripy  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            msg = f"angr not available: {exc}"
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Symbolic execution unavailable",
                    summary=msg,
                    tool="angr",
                    command="import angr",
                    context=msg,
                    tags=["symexec", "unavailable"],
                    created_by=self.role,
                )
            )
            return cards

        target = context.input_path.as_posix()
        timeout = getattr(context.config, "angr_timeout_secs", 300)
        find_rx = getattr(context.config, "angr_find_regex", [r"d3ctf{", r"flag{", r"ctf{"])
        summary_lines: List[str] = []

        # Try to discover success/failure addresses via r2 strings/xrefs
        def _find_code_xref_for(text: str) -> Optional[int]:
            try:
                sj = context.run_command(
                    self.role,
                    f"r2 strings json",
                    f"r2 -2qc 'aa; izj' {target}",
                    artifact_name=None,
                )
                arr = json.loads(sj.get("stdout") or "[]")
                vaddrs = [item.get("vaddr") for item in arr if text in (item.get("string") or "")]
                if not vaddrs:
                    return None
                xv = context.run_command(
                    self.role,
                    f"r2 xrefs {text}",
                    f"r2 -2qc 'axt {vaddrs[0]}' {target}",
                    artifact_name=None,
                )
                import re as _re
                for line in (xv.get("stdout") or "").splitlines():
                    m = _re.search(r"(0x[0-9a-fA-F]+)", line)
                    if m:
                        return int(m.group(1), 16)
            except Exception:
                return None
            return None
        try:
            # Quiet down angr/claripy WARN logs (e.g., default_filler_mixin warnings)
            for _name in (
                "angr",
                "claripy",
                "angr.storage.memory_mixins.default_filler_mixin",
            ):
                logging.getLogger(_name).setLevel(logging.ERROR)

            proj = angr.Project(target, auto_load_libs=False)
            # Hook the scanf-like wrapper at 0x40a3b0 to write symbolic input into [rsi]
            SCANF_ADDR = 0x40A3B0

            class FillInput(angr.SimProcedure):
                def run(self):  # type: ignore[override]
                    rsi = self.state.regs.rsi
                    ptr = self.state.solver.eval(rsi)
                    n = 36  # from main uses 0x24
                    sym = self.state.solver.BVS("stdin_sym", n * 8)
                    # Constrain printable and d3ctf{...} shape
                    for i in range(n):
                        b = sym.get_byte(i)
                        self.state.add_constraints(b >= 0x20, b <= 0x7e)
                    # Prefix/suffix if space allows
                    prefix = b"d3ctf{"
                    suffix = b"}"
                    for i, ch in enumerate(prefix):
                        self.state.add_constraints(sym.get_byte(i) == ch)
                    self.state.add_constraints(sym.get_byte(n - 1) == suffix[0])
                    self.state.memory.store(ptr, sym)
                    self.state.globals["input_ptr"] = ptr
                    self.state.globals["input_len"] = n
                    return self.state.solver.BVV(1, self.state.arch.bits)  # success

            proj.hook(SCANF_ADDR, FillInput())

            # Set up state at main (0x40197c)
            MAIN_ADDR = 0x40197C
            opts = {
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
            state = proj.factory.blank_state(addr=MAIN_ADDR, add_options=opts)
            simgr = proj.factory.simgr(state)

            # Discover success/failure addresses via strings/xrefs or fallback
            success = _find_code_xref_for("Good!") or 0x401A4F
            fail1 = _find_code_xref_for("Sorry.") or 0x4019D5
            fail2 = 0x401A39

            simgr.explore(find=success, avoid=[fail1, fail2])
            if simgr.found:
                st = simgr.found[0]
                ptr = st.globals.get("input_ptr", None)
                ln = st.globals.get("input_len", 0)
                candidate = None
                if ptr and ln:
                    data = st.memory.load(ptr, ln)
                    candidate = st.solver.eval(data, cast_to=bytes)
                if candidate:
                    candidate_txt = candidate.decode("utf-8", errors="ignore")
                    summary_lines.append("Recovered candidate input via angr:")
                    summary_lines.append(candidate_txt)
                    # Persist artifact
                    art = context.create_artifact_path(f"{step.step_id or 'step'}_angr_candidate.txt")
                    art.write_text(candidate_txt, encoding="utf-8")
                    cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="Recovered candidate via symbolic execution",
                            summary=candidate_txt[:160],
                            tool="angr",
                            command=f"angr explore find=0x{success:x}",
                            context=candidate_txt,
                            artifact_path=art,
                            tags=["flag", "angr"],
                            created_by=self.role,
                        )
                    )
                else:
                    summary_lines.append("Found path but failed to extract candidate input.")
            else:
                summary_lines.append("No path to success within exploration bounds.")
        except Exception as exc:  # pragma: no cover
            summary_lines.append(f"angr execution error: {exc}")

        content = "\n".join(summary_lines)
        cards.append(
            EvidenceCard(
                id="",
                source_agent=self.role,
                title="Symbolic execution summary",
                summary=content[:400],
                tool="angr",
                command=f"angr explore {context.input_path.name}",
                context=content,
                tags=["symexec", "analysis"],
                created_by=self.role,
            )
        )
        return cards

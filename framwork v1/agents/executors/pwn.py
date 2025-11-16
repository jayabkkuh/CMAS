"""
Exploitation executor.
"""

from __future__ import annotations

from typing import List
from uuid import uuid4

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class PwnExecutorAgent(ExecutorAgent):
    role = "PwnExecutorAgent"
    category = "Pwn"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        prompt = (
            "You are the exploitation executor handling binary pwn challenges.\n"
            f"Mission: {context.mission_id}\n"
            f"Current objective: {step.description}\n"
            f"Toolkit: {', '.join(self.toolkit)}\n"
            "Outline exploitation strategy, required primitives, and validation checks.\n"
        )
        if context.config.dry_run:
            prompt += "Dry-run is active; focus on reasoning about exploits without executing them.\n"
        snippet = self.skillbook_snippet(context)
        if snippet:
            prompt += f"Known patterns:\n{snippet}\n"
        analysis = f"Pwn step plan: {step.description}. Toolkit: {', '.join(self.toolkit)}."
        lowered = analysis.lower()
        if "http" in lowered or "request" in lowered:
            self.request_support(
                "WebExecutorAgent",
                "Exploit strategy touches HTTP stack; need coordinated web testing.",
            )
        cards: List[EvidenceCard] = []
        card = EvidenceCard(
            id=f"pwn-{uuid4().hex[:8]}",
            source_agent=self.role,
            title=f"Pwn step: {step.description}",
            summary=analysis[:400],
            tool="LLM",
            command=step.description,
            context=analysis,
            tags=["pwn", "exploit"],
        )
        cards.append(card)

        ipath = context.input_path.as_posix()
        ffmt = context.detect_format()
        # Basic security features via rabin2 if present
        if context.which("rabin2"):
            sec = context.run_command(
                self.role,
                "binary protections",
                f"rabin2 -I {ipath}",
                artifact_name=f"{step.step_id}_rabin2_sec.txt",
            )
            sec_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Binary protections (rabin2 -I)",
                summary=(sec.get("stdout") or "")[:400],
                tool="rabin2",
                command=f"rabin2 -I {context.input_path.name}",
                context=str(sec.get("stdout", "")),
                tags=["pwn", "protections"],
            )
            if sec.get("artifact_path"):
                sec_card.attach_artifact(sec["artifact_path"])  # type: ignore[index]
            cards.append(sec_card)
        elif ffmt == "MACHO" and context.which("otool"):
            # macOS Mach-O headers and linked libs
            hdr = context.run_command(
                self.role,
                "macho headers",
                f"otool -hv {ipath}",
                artifact_name=f"{step.step_id}_otool_hv.txt",
            )
            hdr_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Mach-O headers (otool -hv)",
                summary=(hdr.get("stdout") or "")[:400],
                tool="otool",
                command=f"otool -hv {context.input_path.name}",
                context=str(hdr.get("stdout", "")),
                tags=["pwn", "headers"],
            )
            if hdr.get("artifact_path"):
                hdr_card.attach_artifact(hdr["artifact_path"])  # type: ignore[index]
            cards.append(hdr_card)

            libs = context.run_command(
                self.role,
                "linked libraries",
                f"otool -L {ipath}",
                artifact_name=f"{step.step_id}_otool_L.txt",
            )
            libs_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Linked libraries (otool -L)",
                summary=(libs.get("stdout") or "")[:400],
                tool="otool",
                command=f"otool -L {context.input_path.name}",
                context=str(libs.get("stdout", "")),
                tags=["pwn", "libs"],
            )
            if libs.get("artifact_path"):
                libs_card.attach_artifact(libs["artifact_path"])  # type: ignore[index]
            cards.append(libs_card)
        elif ffmt == "ELF":
            # Prefer llvm-readobj on macOS or when available; fallback to readelf
            if context.is_macos() and context.which("llvm-readobj"):
                elf = context.run_command(
                    self.role,
                    "elf headers",
                    f"llvm-readobj -h {ipath}",
                    artifact_name=f"{step.step_id}_llvm_readobj_h.txt",
                )
                elf_card = EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="ELF headers (llvm-readobj -h)",
                    summary=(elf.get("stdout") or "")[:400],
                    tool="llvm-readobj",
                    command=f"llvm-readobj -h {context.input_path.name}",
                    context=str(elf.get("stdout", "")),
                    tags=["pwn", "headers"],
                )
                if elf.get("artifact_path"):
                    elf_card.attach_artifact(elf["artifact_path"])  # type: ignore[index]
                cards.append(elf_card)
            else:
                elf = context.run_command(
                    self.role,
                    "elf headers",
                    f"readelf -h {ipath}",
                    artifact_name=f"{step.step_id}_readelf_h.txt",
                )
                elf_card = EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="ELF headers (readelf -h)",
                    summary=(elf.get("stdout") or "")[:400],
                    tool="readelf",
                    command=f"readelf -h {context.input_path.name}",
                    context=str(elf.get("stdout", "")),
                    tags=["pwn", "headers"],
                )
                if elf.get("artifact_path"):
                    elf_card.attach_artifact(elf["artifact_path"])  # type: ignore[index]
                cards.append(elf_card)
        else:
            # Unknown format: rely on file(1)
            info = context.run_command(
                self.role,
                "file identification",
                f"file {ipath}",
                artifact_name=f"{step.step_id}_file.txt",
            )
            info_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="File identification (file)",
                summary=(info.get("stdout") or "")[:400],
                tool="file",
                command=f"file {context.input_path.name}",
                context=str(info.get("stdout", "")),
                tags=["pwn", "artifact"],
            )
            if info.get("artifact_path"):
                info_card.attach_artifact(info["artifact_path"])  # type: ignore[index]
            cards.append(info_card)

        # Debugger adaptability: prefer gdb, fallback to lldb on macOS
        try:
            dbg = None
            if context.which("gdb"):
                dbg = "gdb"
            elif context.is_macos() and context.which("lldb"):
                self.request_support("General", "gdb not available; using lldb for lightweight probing.")
                dbg = "lldb"
            else:
                self.request_support("General", "No debugger available (gdb/lldb missing); focusing on static patterns and io-driven probes.")
            if dbg == "gdb":
                ver = context.run_command(
                    self.role,
                    "gdb version",
                    "gdb --version | head -n 1",
                    artifact_name=f"{step.step_id}_gdb_version.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Debugger availability (gdb)",
                        summary=(ver.get("stdout") or "")[:200] or "gdb present",
                        tool="gdb",
                        command="gdb --version",
                        context=str(ver.get("stdout", "")),
                        tags=["pwn", "debugger"],
                    )
                )
            elif dbg == "lldb":
                ver = context.run_command(
                    self.role,
                    "lldb version",
                    "lldb --version",
                    artifact_name=f"{step.step_id}_lldb_version.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Debugger availability (lldb fallback)",
                        summary=(ver.get("stdout") or "")[:200] or "lldb present (fallback)",
                        tool="lldb",
                        command="lldb --version",
                        context=str(ver.get("stdout", "")),
                        tags=["pwn", "debugger", "fallback"],
                    )
                )
        except Exception:
            pass
        # Adaptive branching heuristics to enhance solving ability
        combined = "\n".join([
            str(locals().get("sec", {}).get("stdout", "")),
            str(locals().get("hdr", {}).get("stdout", "")),
            str(locals().get("libs", {}).get("stdout", "")),
            str(locals().get("elf", {}).get("stdout", "")),
            str(locals().get("info", {}).get("stdout", "")),
        ]).lower()
        if any(k in combined for k in ("encrypt", "cipher", "aes", "rsa")):
            self.propose_step(
                context,
                plan,
                "Perform cryptanalysis on suspected routines",
                "CryptoExecutorAgent",
                tools=["strings", "sage"],
            )
        if any(k in combined for k in ("http", "request", "cookie", "csrf")):
            self.propose_step(
                context,
                plan,
                "Coordinate web exploitation related to service",
                "WebExecutorAgent",
                tools=["curl", "requests"],
            )
        if ("symbols" in combined or "stripped" in combined) and context.which("r2"):
            self.propose_step(
                context,
                plan,
                "Reverse engineer stripped binary regions",
                "ReverseExecutorAgent",
                tools=["r2", "ghidra"],
            )
        # Additional quick probe: section layout via debugger/tool when available
        try:
            if context.which("gdb"):
                probe = context.run_command(
                    self.role,
                    "gdb info files",
                    f"gdb -q -nx -batch -ex 'info files' {ipath}",
                    artifact_name=f"{step.step_id}_gdb_info_files.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="GDB info files",
                        summary=(probe.get("stdout") or "")[:400],
                        tool="gdb",
                        command="gdb -q -nx -batch -ex 'info files' input",
                        context=str(probe.get("stdout", "")),
                        tags=["pwn", "sections"],
                    )
                )
            elif context.is_macos() and context.which("otool") and context.detect_format() == "MACHO":
                sec = context.run_command(
                    self.role,
                    "otool sections",
                    f"otool -l {ipath} | head -n 200",
                    artifact_name=f"{step.step_id}_otool_l.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Mach-O load commands (otool -l)",
                        summary=(sec.get("stdout") or "")[:400],
                        tool="otool",
                        command=f"otool -l {context.input_path.name}",
                        context=str(sec.get("stdout", "")),
                        tags=["pwn", "macho"],
                    )
                )
        except Exception:
            pass

        # Planned debugger scripts (templates only, no execution)
        try:
            # Generic breakpoints: main + common libc sinks (user to adjust)
            bp_names = ["main", "__libc_start_main", "puts", "gets"]
            gdb_lines = [
                "# GDB planned script (do not execute automatically)",
                "set pagination off",
                "set disassembly-flavor intel",
                "handle SIGALRM pass nostop noprint",
                "set follow-fork-mode parent",
            ]
            for n in bp_names:
                gdb_lines.append(f"break {n}")
            gdb_lines += [
                "# run < input (edit as needed)",
                "# ni / si",
                "# x/20i $rip",
            ]
            gdb_text = "\n".join(gdb_lines) + "\n"
            gdb_art = context.create_artifact_path(f"{step.step_id}_gdb_plan.txt")
            gdb_art.write_text(gdb_text, encoding="utf-8")
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Planned debugger script (gdb)",
                    summary=("; ".join(gdb_lines[:4]))[:200],
                    tool="planning",
                    command="gdb planned script",
                    context=gdb_text,
                    artifact_path=gdb_art,
                    tags=["pwn", "debug-plan"],
                )
            )

            lldb_lines = [
                "# LLDB planned script (do not execute automatically)",
                "settings set stop-line-count-before 5",
                "settings set stop-line-count-after 5",
            ]
            for n in bp_names:
                lldb_lines.append(f"breakpoint set --name {n}")
            lldb_lines += [
                "# process launch -- <args> (edit as needed)",
                "# thread step-in / thread step-over",
                "# disassemble --frame --count 20",
            ]
            lldb_text = "\n".join(lldb_lines) + "\n"
            lldb_art = context.create_artifact_path(f"{step.step_id}_lldb_plan.txt")
            lldb_art.write_text(lldb_text, encoding="utf-8")
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Planned debugger script (lldb)",
                    summary=("; ".join(lldb_lines[:4]))[:200],
                    tool="planning",
                    command="lldb planned script",
                    context=lldb_text,
                    artifact_path=lldb_art,
                    tags=["pwn", "debug-plan"],
                )
            )
        except Exception:
            pass

        return cards

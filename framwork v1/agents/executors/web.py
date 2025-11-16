"""
Web exploitation executor.
"""

from __future__ import annotations

from typing import List
from uuid import uuid4

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class WebExecutorAgent(ExecutorAgent):
    role = "WebExecutorAgent"
    category = "Web"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        prompt = (
            "You are the web executor targeting web challenge services.\n"
            f"Mission: {context.mission_id}\n"
            f"Objective: {step.description}\n"
            f"Toolkit: {', '.join(self.toolkit)}\n"
            "Lay out HTTP requests, payload concepts, and verification.\n"
        )
        if context.config.dry_run:
            prompt += "Dry-run is active; reason about requests without sending them.\n"
        snippet = self.skillbook_snippet(context)
        if snippet:
            prompt += f"Known patterns:\n{snippet}\n"
        analysis = f"Web step plan: {step.description}. Toolkit: {', '.join(self.toolkit)}."
        lowered = analysis.lower()
        if "binary" in lowered or "rop" in lowered:
            self.request_support(
                "PwnExecutorAgent",
                "Web exploitation requires binary payload coordination.",
            )
        cards: List[EvidenceCard] = []
        card = EvidenceCard(
            id=f"web-{uuid4().hex[:8]}",
            source_agent=self.role,
            title=f"Web step: {step.description}",
            summary=analysis[:400],
            tool="LLM",
            command=step.description,
            context=analysis,
            tags=["web"],
        )
        cards.append(card)

        # Even for web tasks, inspect local artifacts
        res = context.run_command(
            self.role,
            "file identification",
            f"file {context.input_path.as_posix()}",
            artifact_name=f"{step.step_id}_file.txt",
        )
        info_card = EvidenceCard(
            id="",
            source_agent=self.role,
            title="Artifact identification (file)",
            summary=(res.get("stdout") or "")[:400],
            tool="file",
            command=f"file {context.input_path.name}",
            context=str(res.get("stdout", "")),
            tags=["web", "artifact"],
        )
        if res.get("artifact_path"):
            info_card.attach_artifact(res["artifact_path"])  # type: ignore[index]
        cards.append(info_card)
        # Extract candidate URLs from strings and propose test flows (no live net)
        try:
            sscan = context.run_command(
                self.role,
                "strings url scan",
                f"strings -n 6 {context.input_path.as_posix()} | grep -E 'https?://' | head -n 10",
                artifact_name=f"{step.step_id}_strings_urls.txt",
            )
            urls = []
            for line in (sscan.get("stdout") or "").splitlines():
                ln = line.strip()
                if ln.startswith("http://") or ln.startswith("https://"):
                    urls.append(ln)
            if urls:
                plan_text = "\n".join([f"curl -I '{u}'" for u in urls[:5]])
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Candidate endpoints (planned HEAD requests)",
                        summary=("\n".join(urls[:5]))[:400],
                        tool="planning",
                        command="curl -I <endpoint> (planned)",
                        context=plan_text,
                        tags=["web", "endpoints"],
                    )
                )
        except Exception:
            pass

        # Adaptive HTTP tooling: prefer curl; fallback to python requests
        try:
            if context.which("curl"):
                ver = context.run_command(
                    self.role,
                    "curl version",
                    "curl --version | head -n 1",
                    artifact_name=f"{step.step_id}_curl_version.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="HTTP client (curl)",
                        summary=(ver.get("stdout") or "")[:200] or "curl present",
                        tool="curl",
                        command="curl --version",
                        context=str(ver.get("stdout", "")),
                        tags=["web", "http"],
                    )
                )
            else:
                # Try requests
                py = context.run_command(
                    self.role,
                    "requests probe",
                    f"{context.config.python_bin} -c 'import requests; print(requests.__version__)'",
                    artifact_name=f"{step.step_id}_requests_probe.txt",
                )
                if py.get("returncode", 1) == 0:
                    self.request_support("General", "curl not available; falling back to python-requests for HTTP flows.")
                    cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="HTTP client (requests fallback)",
                            summary=(py.get("stdout") or "")[:200] or "requests present",
                            tool="python-requests",
                            command="python -c 'import requests'",
                            context=str(py.get("stdout", "")),
                            tags=["web", "http", "fallback"],
                        )
                    )
                else:
                    self.request_support("General", "Neither curl nor python-requests available; recommend install before active HTTP testing.")
        except Exception:
            pass

        return cards

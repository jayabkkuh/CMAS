"""
Cryptography executor.
"""

from __future__ import annotations

from typing import List
from uuid import uuid4

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class CryptoExecutorAgent(ExecutorAgent):
    role = "CryptoExecutorAgent"
    category = "Crypto"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        prompt = (
            "You are the cryptography executor for a CTF team.\n"
            f"Mission: {context.mission_id}\n"
            f"Objective: {step.description}\n"
            f"Toolkit: {', '.join(self.toolkit)}\n"
            "Detail the crypto analysis path, equations, and verification approach."
        )
        if context.config.dry_run:
            prompt += " Dry-run is active; emphasize math reasoning and simulated verification."
        snippet = self.skillbook_snippet(context)
        if snippet:
            prompt += f"\nKnown patterns:\n{snippet}\n"
        analysis = f"Crypto step plan: {step.description}. Toolkit: {', '.join(self.toolkit)}."
        lowered = analysis.lower()
        if "binary" in lowered or "reverse" in lowered:
            self.request_support(
                "ReverseExecutorAgent",
                "Crypto solution depends on reversing binary routines for constants.",
            )
        cards: List[EvidenceCard] = []
        card = EvidenceCard(
            id=f"crypto-{uuid4().hex[:8]}",
            source_agent=self.role,
            title=f"Crypto step: {step.description}",
            summary=analysis[:400],
            tool="LLM",
            command=step.description,
            context=analysis,
            tags=["crypto"],
        )
        cards.append(card)

        # Terminal reconnaissance for crypto hints via strings/grep
        ipath = context.input_path.as_posix()
        res = context.run_command(
            self.role,
            "crypto keyword grep",
            f"strings -n 4 {ipath} | grep -i -E 'flag|key|rsa|aes|cipher|base64|md5|sha' | head -n 50",
            artifact_name=f"{step.step_id}_crypto_strings.txt",
        )
        kw_card = EvidenceCard(
            id="",
            source_agent=self.role,
            title="Keyword scan (strings/grep)",
            summary=(res.get("stdout") or "")[:400],
            tool="strings|grep",
            command="strings | grep -i -E 'flag|key|rsa|aes|cipher|base64|md5|sha'",
            context=str(res.get("stdout", "")),
            tags=["crypto", "recon"],
        )
        if res.get("artifact_path"):
            kw_card.attach_artifact(res["artifact_path"])  # type: ignore[index]
        cards.append(kw_card)
        # Adaptive toolkit fallback: prefer sage; fallback to pycryptodome
        try:
            has_sage = bool(context.which("sage"))
        except Exception:
            has_sage = False
        has_pycryptodome = False
        try:
            # Try a lightweight import check
            py = context.run_command(
                self.role,
                "pycryptodome probe",
                f"{context.config.python_bin} -c 'import Crypto, sys; print(getattr(Crypto, \"__version__\", \"ok\"))'",
                artifact_name=f"{step.step_id}_pycryptodome_probe.txt",
            )
            has_pycryptodome = py.get("returncode", 1) == 0 and (py.get("stdout") or "").strip() != ""
        except Exception:
            has_pycryptodome = False

        if not has_sage and has_pycryptodome:
            self.request_support("General", "sage not available; falling back to PyCryptodome-based analysis where applicable.")
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Crypto fallback plan (PyCryptodome)",
                    summary="Using PyCryptodome primitives as a fallback for math-heavy steps.",
                    tool="pycryptodome",
                    command="python -c 'import Crypto'",
                    context=str(py.get("stdout", "")),
                    tags=["crypto", "fallback"],
                )
            )
        elif not has_sage and not has_pycryptodome:
            self.request_support("General", "Neither sage nor PyCryptodome available; recommend install or switch to structural attacks.")

        # Auto: attempt base64 decode if obvious
        try:
            import re, base64
            for line in (res.get("stdout") or "").splitlines():
                s = line.strip()
                if len(s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", s) and (len(s) % 4 == 0):
                    try:
                        decoded = base64.b64decode(s, validate=True)
                        text = decoded.decode("utf-8", errors="ignore")
                        art = context.create_artifact_path(f"{step.step_id}_crypto_b64.txt")
                        art.write_text(text, encoding="utf-8")
                        cards.append(
                            EvidenceCard(
                                id="",
                                source_agent=self.role,
                                title="Auto-decoder: base64 (crypto)",
                                summary=text[:200],
                                tool="python",
                                command="base64.b64decode",
                                context=text,
                                artifact_path=art,
                                tags=["crypto", "auto", "base64"],
                            )
                        )
                        break
                    except Exception:
                        pass
        except Exception:
            pass

        return cards

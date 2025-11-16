"""
Miscellaneous executor for puzzle-style challenges.
"""

from __future__ import annotations

from typing import List
from uuid import uuid4

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class MiscExecutorAgent(ExecutorAgent):
    role = "MiscExecutorAgent"
    category = "Misc"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        prompt = (
            "You are the miscellaneous executor focusing on logic and oddball tasks.\n"
            f"Mission: {context.mission_id}\n"
            f"Objective: {step.description}\n"
            f"Toolkit: {', '.join(self.toolkit)}\n"
            "Provide the reasoning plan, partial solutions, and verification hooks."
        )
        if context.config.dry_run:
            prompt += " Dry-run is active; sketch solution logic without executing tools."
        snippet = self.skillbook_snippet(context)
        if snippet:
            prompt += f"\nKnown patterns:\n{snippet}\n"
        analysis = f"Misc step plan: {step.description}. Toolkit: {', '.join(self.toolkit)}."
        lowered = analysis.lower()
        if "cipher" in lowered or "encrypt" in lowered:
            self.request_support(
                "CryptoExecutorAgent",
                "Misc challenge revealed cipher hints; need cryptanalysis.",
            )
        cards: List[EvidenceCard] = []
        card = EvidenceCard(
            id=f"misc-{uuid4().hex[:8]}",
            source_agent=self.role,
            title=f"Misc step: {step.description}",
            summary=analysis[:400],
            tool="LLM",
            command=step.description,
            context=analysis,
            tags=["misc"],
        )
        cards.append(card)
        ipath = context.input_path.as_posix()
        # Hexdump sample with fallback to xxd
        if context.which("hexdump"):
            cmd = f"hexdump -C -n 512 {ipath}"
            res = context.run_command(
                self.role,
                "hexdump sample",
                cmd,
                artifact_name=f"{step.step_id}_hexdump.txt",
            )
            hex_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Hexdump sample",
                summary=(res.get("stdout") or "")[:400],
                tool="hexdump",
                command=cmd.replace(ipath, context.input_path.name),
                context=str(res.get("stdout", "")),
                tags=["misc", "hexdump"],
            )
            if res.get("artifact_path"):
                hex_card.attach_artifact(res["artifact_path"])  # type: ignore[index]
            cards.append(hex_card)
        elif context.which("xxd"):
            self.request_support("General", "hexdump not available; falling back to xxd for hex view.")
            cmd = f"xxd -l 512 -g 1 {ipath}"
            res = context.run_command(
                self.role,
                "xxd sample",
                cmd,
                artifact_name=f"{step.step_id}_xxd.txt",
            )
            xx_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Hexdump sample (xxd)",
                summary=(res.get("stdout") or "")[:400],
                tool="xxd",
                command=cmd.replace(ipath, context.input_path.name),
                context=str(res.get("stdout", "")),
                tags=["misc", "hexdump", "fallback"],
            )
            if res.get("artifact_path"):
                xx_card.attach_artifact(res["artifact_path"])  # type: ignore[index]
            cards.append(xx_card)
        else:
            self.request_support("General", "Neither hexdump nor xxd available; limited visibility.")

        # Quick textual scan to adapt follow-ups
        sres = context.run_command(
            self.role,
            "strings sample",
            f"strings -n 4 {ipath} | head -n 80",
            artifact_name=f"{step.step_id}_strings.txt",
        )
        cards.append(
            EvidenceCard(
                id="",
                source_agent=self.role,
                title="Strings sample",
                summary=(sres.get("stdout") or "")[:400],
                tool="strings",
                command=f"strings -n 4 {context.input_path.name}",
                context=str(sres.get("stdout", "")),
                tags=["misc", "strings"],
            )
        )

        # If looks like common encodings/ciphers, propose decode path
        try:
            txt = (sres.get("stdout") or "")
            low = txt.lower()
            # base64 clues
            if any(k in low for k in ("base64", "begin rsa", "==\n")):
                self.propose_step(
                    context,
                    plan,
                    "Attempt base64/key material decoding and format normalization",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # hex dump-like (pairs)
            import re
            if re.search(r"(?:[0-9a-fA-F]{2}\s+){8,}", txt):
                self.propose_step(
                    context,
                    plan,
                    "Hex bytes to ASCII/bytes conversion and structure probing",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # rot13 hint
            if "rot13" in low or "caesar" in low:
                self.propose_step(
                    context,
                    plan,
                    "Try ROT/caesar shifts with frequency analysis",
                    "CryptoExecutorAgent",
                    tools=["python"],
                )
            # vigenere hint
            if "vigenere" in low or "kasiski" in low:
                self.propose_step(
                    context,
                    plan,
                    "Vigenere analysis (Kasiski/IC) and key search",
                    "CryptoExecutorAgent",
                    tools=["python"],
                )
            # Morse code
            if re.search(r"^[\.\-\s/]{10,}$", txt, re.MULTILINE):
                self.propose_step(
                    context,
                    plan,
                    "Morse decode and timing normalization",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # Binary ASCII
            if re.search(r"(?:[01]{8}\s+){8,}", txt):
                self.propose_step(
                    context,
                    plan,
                    "Binary ASCII to text conversion",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # URL encoding
            if re.search(r"%[0-9A-Fa-f]{2}", txt):
                self.propose_step(
                    context,
                    plan,
                    "URL percent-decoding and normalization",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # UUEncode
            if low.startswith("begin "):
                self.propose_step(
                    context,
                    plan,
                    "UUDecode payload and validate checksum",
                    "MiscExecutorAgent",
                    tools=["python"],
                )
            # QR code hints
            if "qr" in low or "qrcode" in low:
                self.request_support("ForensicsExecutorAgent", "Image/QR hinted; coordinate QR decode via zbarimg.")
        except Exception:
            pass

        # Lightweight automatic decoders (non-destructive)
        try:
            auto_cards: List[EvidenceCard] = []
            sample = (sres.get("stdout") or "").strip()
            # base64 decode attempt on first plausible line
            import re, base64, urllib.parse, codecs
            for line in sample.splitlines():
                s = line.strip()
                if len(s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", s) and (len(s) % 4 == 0):
                    try:
                        decoded = base64.b64decode(s, validate=True)
                        text = decoded.decode("utf-8", errors="ignore")
                        art = context.create_artifact_path(f"{step.step_id}_auto_b64.txt")
                        art.write_text(text, encoding="utf-8")
                        auto_cards.append(
                            EvidenceCard(
                                id="",
                                source_agent=self.role,
                                title="Auto-decoder: base64",
                                summary=text[:200],
                                tool="python",
                                command="base64.b64decode",
                                context=text,
                                artifact_path=art,
                                tags=["misc", "auto", "base64"],
                            )
                        )
                        break
                    except Exception:
                        pass
            # rot13 try on a short line
            for line in sample.splitlines():
                if len(line) >= 10 and all(ch.isalpha() or ch.isspace() for ch in line):
                    try:
                        rot = codecs.decode(line, 'rot_13')
                        if rot and rot != line:
                            auto_cards.append(
                                EvidenceCard(
                                    id="",
                                    source_agent=self.role,
                                    title="Auto-decoder: ROT13 sample",
                                    summary=rot[:200],
                                    tool="python",
                                    command="codecs.decode(rot_13)",
                                    context=rot,
                                    tags=["misc", "auto", "rot13"],
                                )
                            )
                            break
                    except Exception:
                        pass
            # URL percent-decoding sample
            if re.search(r"%[0-9A-Fa-f]{2}", sample):
                try:
                    dec = urllib.parse.unquote(sample)
                    auto_cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="Auto-decoder: URL percent-decoding",
                            summary=dec[:200],
                            tool="python",
                            command="urllib.parse.unquote",
                            context=dec,
                            tags=["misc", "auto", "url"],
                        )
                    )
                except Exception:
                    pass
            for c in auto_cards:
                cards.append(c)
        except Exception:
            pass

        return cards

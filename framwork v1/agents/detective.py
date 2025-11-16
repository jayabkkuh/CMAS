"""
Detective agent responsible for initial reconnaissance.
"""

from __future__ import annotations

import shlex
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple
from uuid import uuid4

from xml.etree import ElementTree as ET

from framework.context import CaseContext
from framework.evidence import EvidenceCard

from .base import BaseAgent


class DetectiveAgent(BaseAgent):
    role = "Detective"

    def run(self, context: CaseContext, **_) -> List[EvidenceCard]:
        self.bind_context(context)
        self.log("round_start", {"mission": context.mission_id})
        evidence_cards: List[EvidenceCard] = []
        commands = context.config.detective_commands.items()
        dry_run = context.config.dry_run
        mapping_card_id: str | None = None
        mapping_baddr_txt: str | None = None
        for tag, template in commands:
            command = template.format(input=context.input_path.as_posix())
            result = context.run_command(
                self.role,
                f"{tag} scan",
                command,
                artifact_name=f"{tag}_scan.txt",
            )
            command_id = str(result.get("command_id", ""))
            card = EvidenceCard(
                id="",
                source_agent=self.role,
                title=f"{tag} scan",
                summary=self._summarize_output(str(result.get("stdout", ""))),
                offset=None,
                section=None,
                tool=tag,
                command=command,
                context=str(result.get("stdout", "")),
                metadata=self._build_metadata({
                    "stdout": str(result.get("stdout", "")),
                    "stderr": str(result.get("stderr", "")),
                    "returncode": result.get("returncode", 0),
                }),
                created_by=self.role,
                command_id=command_id,
            )
            derived = self._derive_evidence_details(tag, str(result.get("stdout", "")))
            card.metadata.update(derived.get("metadata", {}))
            card.offset = derived.get("offset")
            card.section = derived.get("section")
            if result.get("artifact_path"):
                card.attach_artifact(result["artifact_path"])  # type: ignore[index]
            context.add_evidence(card, linked_event_id=command_id)
            evidence_cards.append(card)

            # Build Address Mapping card early from rabin2 -I output (baddr)
            try:
                if tag == "rabin2":
                    txt = str(result.get("stdout", ""))
                    import re as _re
                    m = _re.search(r"\bbaddr\s+0x([0-9a-fA-F]+)", txt)
                    if m:
                        baddr = int(m.group(1), 16)
                        mapping_baddr_txt = f"0x{baddr:x}"
                        try:
                            context.route_tracker["baddr"] = mapping_baddr_txt
                        except Exception:
                            pass
            except Exception:
                pass

        # Build Address Mapping card (baddr + sections) for downstream coordinate normalization
        try:
            ipath = context.input_path.as_posix()
            sections: List[Dict[str, object]] = []
            # Prefer radare2 JSON sections
            if context.which("r2"):
                r2s = context.run_command(
                    self.role,
                    "sections (r2 iSj)",
                    f"r2 -2qc 'iSj' {ipath}",
                    artifact_name=f"detective_sections.json",
                )
                import json as _json
                try:
                    arr = _json.loads(r2s.get("stdout") or "[]")
                    for sec in arr or []:
                        try:
                            name = str(sec.get("name") or "")
                            vaddr = int(sec.get("vaddr") or 0)
                            paddr = int(sec.get("paddr") or 0)
                            size = int(sec.get("size") or 0)
                            sections.append(
                                {
                                    "name": name,
                                    "vaddr": vaddr,
                                    "paddr": paddr,
                                    "size": size,
                                    "vaddr_end": vaddr + size,
                                    "paddr_end": paddr + size,
                                }
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            # Fallback: rabin2 -S (best-effort parsing)
            if not sections and context.which("rabin2"):
                rs = context.run_command(
                    self.role,
                    "sections (rabin2 -S)",
                    f"rabin2 -S {ipath}",
                    artifact_name=f"detective_sections_rabin2.txt",
                )
                import re as _re
                for line in (rs.get("stdout") or "").splitlines():
                    # heuristic parse for lines with both vaddr and name
                    m = _re.search(r"vaddr[:=]\s*0x([0-9a-fA-F]+).*?paddr[:=]\s*0x([0-9a-fA-F]+).*?size[:=]\s*0x([0-9a-fA-F]+).*?name[:=]\s*([^\s]+)", line)
                    if m:
                        vaddr = int(m.group(1), 16)
                        paddr = int(m.group(2), 16)
                        size = int(m.group(3), 16)
                        name = m.group(4)
                        sections.append(
                            {
                                "name": name,
                                "vaddr": vaddr,
                                "paddr": paddr,
                                "size": size,
                                "vaddr_end": vaddr + size,
                                "paddr_end": paddr + size,
                            }
                        )
            # macOS Mach-O fallback: parse otool -l for segments/sections
            try:
                if not sections and context.is_macos() and context.which("otool"):
                    ol = context.run_command(
                        self.role,
                        "otool load commands",
                        f"otool -l {ipath}",
                        artifact_name="detective_otool_l.txt",
                    )
                    txt = str(ol.get("stdout") or "")
                    sec = None
                    for line in txt.splitlines():
                        line = line.strip()
                        if line.startswith("Section"):
                            sec = {"name": "", "vaddr": 0, "paddr": 0, "size": 0}
                        elif sec is not None and line.startswith("sectname"):
                            sec["name"] = line.split()[-1]
                        elif sec is not None and line.startswith("addr"):
                            try:
                                sec["vaddr"] = int(line.split()[-1], 16)
                            except Exception:
                                pass
                        elif sec is not None and line.startswith("size"):
                            try:
                                sec["size"] = int(line.split()[-1], 16)
                            except Exception:
                                pass
                        elif sec is not None and line.startswith("offset"):
                            try:
                                sec["paddr"] = int(line.split()[-1])
                            except Exception:
                                pass
                        elif sec is not None and line == "}":
                            try:
                                v = int(sec.get("vaddr") or 0)
                                p = int(sec.get("paddr") or 0)
                                sz = int(sec.get("size") or 0)
                                sections.append({
                                    "name": sec.get("name") or "",
                                    "vaddr": v,
                                    "paddr": p,
                                    "size": sz,
                                    "vaddr_end": v + sz,
                                    "paddr_end": p + sz,
                                })
                            except Exception:
                                pass
                            sec = None
            except Exception:
                pass
            # Base address (default if missing)
            try:
                baddr_int = int((mapping_baddr_txt or "0x400000"), 16)
            except Exception:
                baddr_int = 0x400000
            mapping = {"baddr": baddr_int, "sections": sections}
            # Persist mapping as artifact
            mjson = context.create_artifact_path("address_map.json")
            import json as _json
            mjson.write_text(_json.dumps(mapping, indent=2), encoding="utf-8")
            mcard = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Address Mapping",
                summary=f"baddr=0x{baddr_int:x}; sections={len(sections)}",
                tool="radare2" if sections else "rabin2",
                command="iSj" if sections else "rabin2 -S",
                context=_json.dumps(mapping),
                created_by=self.role,
                tags=["mapping", "reverse"],
                metadata={"baddr": f"0x{baddr_int:x}"},
            )
            mcard.attach_artifact(mjson)
            context.add_evidence(mcard)
            mapping_card_id = mcard.id
            try:
                context.route_tracker["mapping_card_id"] = mapping_card_id
                context.route_tracker["address_map"] = mapping
                # Retroactively normalize existing evidence coordinates
                try:
                    for ec in context.evidence:
                        context._normalize_card_coordinates(ec)  # type: ignore[attr-defined]
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

        # associated docx with same stem
        suffix = context.input_path.suffix.lower()
        if suffix == ".docx":
            docx_card = self._analyze_docx(context, context.input_path)
            if docx_card:
                docx_card.created_by = self.role
                context.add_evidence(docx_card)
                evidence_cards.append(docx_card)
        else:
            related_doc = context.input_path.with_suffix(".docx")
            if related_doc.exists():
                doc_card = self._analyze_docx(context, related_doc)
                if doc_card:
                    doc_card.created_by = self.role
                    context.add_evidence(doc_card)
                    evidence_cards.append(doc_card)

        # Add post-format extras (Mach-O/ELF specific)
        extras = self._post_format_extras(context)
        for ec in extras:
            context.add_evidence(ec)
            evidence_cards.append(ec)

        # Mandatory LLM call: summarize recon and suggest next probes
        try:
            facts = "\n".join(
                f"- {c.title}: {(c.summary or '')[:120]}" for c in evidence_cards[:12]
            )
            prompt = (
                "You are the Detective summarizing initial reconnaissance. "
                "Provide a brief summary and the top 3 concrete next actions.\n"
                f"Evidence so far:\n{facts}\n"
                "Environment: macOS Terminal (zsh)."
            )
            resp = str(self.call_model(prompt))
            llm_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Detective LLM recap",
                summary=resp[:400],
                tool="LLM",
                command="detective_recap",
                context=resp,
                tags=["recon", "info"],
                created_by=self.role,
            )
            context.add_evidence(llm_card)
            evidence_cards.append(llm_card)
        except Exception:
            pass

        self.log("round_complete", {"count": str(len(evidence_cards))})
        self.clear_context()
        return evidence_cards

    def _post_format_extras(self, context: CaseContext) -> List[EvidenceCard]:
        cards: List[EvidenceCard] = []
        fmt = context.detect_format()
        ipath = context.input_path.as_posix()
        if fmt == "MACHO" and context.is_macos():
            # Mach-O headers and linked libs via otool
            hv = context.run_command(
                self.role,
                "otool headers",
                f"otool -hv {ipath}",
                artifact_name=f"detective_otool_hv.txt",
            )
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Mach-O headers (otool -hv)",
                    summary=(hv.get("stdout") or "")[:400],
                    tool="otool",
                    command=f"otool -hv {context.input_path.name}",
                    context=str(hv.get("stdout", "")),
                    tags=["mach-o", "headers"],
                    created_by=self.role,
                )
            )
            if hv.get("artifact_path"):
                cards[-1].attach_artifact(hv["artifact_path"])  # type: ignore[index]
            libs = context.run_command(
                self.role,
                "otool linked libs",
                f"otool -L {ipath}",
                artifact_name=f"detective_otool_L.txt",
            )
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Linked libraries (otool -L)",
                    summary=(libs.get("stdout") or "")[:400],
                    tool="otool",
                    command=f"otool -L {context.input_path.name}",
                    context=str(libs.get("stdout", "")),
                    tags=["mach-o", "libs"],
                    created_by=self.role,
                )
            )
            if libs.get("artifact_path"):
                cards[-1].attach_artifact(libs["artifact_path"])  # type: ignore[index]
        elif fmt == "ELF":
            # Prefer llvm-readobj on macOS or when available; fallback to readelf
            if context.is_macos() and context.which("llvm-readobj"):
                elf = context.run_command(
                    self.role,
                    "elf headers",
                    f"llvm-readobj -h {ipath}",
                    artifact_name=f"detective_llvm_readobj_h.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="ELF headers (llvm-readobj -h)",
                        summary=(elf.get("stdout") or "")[:400],
                        tool="llvm-readobj",
                        command=f"llvm-readobj -h {context.input_path.name}",
                        context=str(elf.get("stdout", "")),
                        tags=["elf", "headers"],
                        created_by=self.role,
                    )
                )
                if elf.get("artifact_path"):
                    cards[-1].attach_artifact(elf["artifact_path"])  # type: ignore[index]
            elif context.which("readelf"):
                elf = context.run_command(
                    self.role,
                    "readelf headers",
                    f"readelf -h {ipath}",
                    artifact_name=f"detective_readelf_h.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="ELF headers (readelf -h)",
                        summary=(elf.get("stdout") or "")[:400],
                        tool="readelf",
                        command=f"readelf -h {context.input_path.name}",
                        context=str(elf.get("stdout", "")),
                        tags=["elf", "headers"],
                        created_by=self.role,
                    )
                )
                if elf.get("artifact_path"):
                    cards[-1].attach_artifact(elf["artifact_path"])  # type: ignore[index]
        return cards

    def _execute_command(self, command: str) -> dict:
        try:
            completed = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                check=False,
            )
            return {
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
                "returncode": completed.returncode,
            }
        except FileNotFoundError:
            return {
                "stdout": "",
                "stderr": f"command not found: {command}",
                "returncode": -1,
            }

    @staticmethod
    def _summarize_output(output: str, limit: int = 400) -> str:
        if not output:
            return "No output captured."
        if len(output) <= limit:
            return output
        return output[: limit - 3] + "..."

    @staticmethod
    def _build_metadata(result: Dict[str, str]) -> Dict[str, str]:
        metadata = {
            "returncode": str(result.get("returncode", "")),
        }
        if stderr := result.get("stderr"):
            metadata["stderr"] = stderr
        return metadata

    @staticmethod
    def _derive_evidence_details(tag: str, output: str) -> Dict[str, object]:
        if not output:
            return {}
        if tag == "binwalk":
            # Parse first line containing an offset.
            for line in output.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                try:
                    offset = int(parts[0])
                    section = parts[1] if len(parts) > 1 else None
                    return {"offset": offset, "section": section, "metadata": {"binwalk_entry": line}}
                except ValueError:
                    continue
        if tag == "r2info":
            return {"metadata": {"radare_json": output[:1000]}}
        if tag == "strings":
            for line in output.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) != 2:
                    continue
                try:
                    offset = int(parts[0], 16)
                except ValueError:
                    continue
                return {
                    "offset": offset,
                    "metadata": {"string_sample": parts[1][:100]},
                }
        return {}

    def _analyze_docx(self, context: CaseContext, doc_path: Path) -> EvidenceCard | None:
        try:
            with zipfile.ZipFile(doc_path, "r") as archive:
                xml_bytes = archive.read("word/document.xml")
        except (FileNotFoundError, KeyError, zipfile.BadZipFile):
            return None

        try:
            root = ET.fromstring(xml_bytes)
            texts = [node.text for node in root.iter() if node.text]
            plain = " ".join(texts).strip()
        except ET.ParseError:
            plain = xml_bytes.decode("utf-8", errors="ignore")

        artifact_name = f"{doc_path.stem}_document.txt"
        artifact = context.create_artifact_path(artifact_name)
        artifact.write_text(plain, encoding="utf-8")

        return EvidenceCard(
            id=f"{self.role.lower()}-docx-{uuid4().hex[:6]}",
            source_agent=self.role,
            title="DOCX description extracted",
            summary=plain[:400] if plain else "DOCX contained no textual content",
            tool="zip",
            command="extract word/document.xml",
            context=plain,
            artifact_path=artifact,
            tags=["docx", "hint"],
            metadata={"source_docx": doc_path.name},
        )

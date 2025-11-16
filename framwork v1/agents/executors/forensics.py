"""
Digital forensics executor.
"""

from __future__ import annotations

from typing import List
from uuid import uuid4

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan, TaskStep

from .base import ExecutorAgent


class ForensicsExecutorAgent(ExecutorAgent):
    role = "ForensicsExecutorAgent"
    category = "Forensics"

    def _execute_step(
        self,
        context: CaseContext,
        plan: TaskPlan,
        step: TaskStep,
        **_,
    ) -> List[EvidenceCard]:
        prompt = (
            "You are the forensics executor handling disk/image investigations.\n"
            f"Mission: {context.mission_id}\n"
            f"Objective: {step.description}\n"
            f"Toolkit: {', '.join(self.toolkit)}\n"
            "Describe the imaging steps, carving targets, and expected artifacts."
        )
        if context.config.dry_run:
            prompt += " Dry-run is active; describe tool usage hypothetically."
        snippet = self.skillbook_snippet(context)
        if snippet:
            prompt += f"\nKnown patterns:\n{snippet}\n"
        analysis = f"Forensics step plan: {step.description}. Toolkit: {', '.join(self.toolkit)}."
        lowered = analysis.lower()
        if "web server" in lowered or "http" in lowered:
            self.request_support(
                "WebExecutorAgent",
                "Recovered web artifacts that require live exploitation follow-up.",
            )
        if "password" in lowered or "wordlist" in lowered:
            self.request_support(
                "MiscExecutorAgent",
                "Need creative cracking or scripting support for recovered secrets.",
            )
        cards: List[EvidenceCard] = []
        card = EvidenceCard(
            id=f"forensics-{uuid4().hex[:8]}",
            source_agent=self.role,
            title=f"Forensics step: {step.description}",
            summary=analysis[:400],
            tool="LLM",
            command=step.description,
            context=analysis,
            tags=["forensics"],
        )
        cards.append(card)
        ipath = context.input_path.as_posix()
        # Terminal-driven extraction using binwalk if present; otherwise adapt
        if context.which("binwalk"):
            res = context.run_command(
                self.role,
                "binwalk extract",
                f"binwalk --matryoshka -e {ipath}",
                artifact_name=f"{step.step_id}_binwalk.txt",
            )
            bw_card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Binwalk extraction summary",
                summary=(res.get("stdout") or "")[:400],
                tool="binwalk",
                command=f"binwalk --matryoshka -e {context.input_path.name}",
                context=str(res.get("stdout", "")),
                tags=["forensics", "extraction"],
                metadata={"binwalk_entry": (res.get("stdout") or "").splitlines()[0] if res.get("stdout") else ""},
            )
            if res.get("artifact_path"):
                bw_card.attach_artifact(res["artifact_path"])  # type: ignore[index]
            cards.append(bw_card)
        else:
            # Fallback reconnaissance: file, strings, hexdump; notify General
            self.request_support("General", "binwalk not available; using file/strings/hexdump fallback methods.")
            # file(1)
            finfo = context.run_command(
                self.role,
                "file identification",
                f"file {ipath}",
                artifact_name=f"{step.step_id}_file.txt",
            )
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="File identification (file)",
                    summary=(finfo.get("stdout") or "")[:400],
                    tool="file",
                    command=f"file {context.input_path.name}",
                    context=str(finfo.get("stdout", "")),
                    tags=["forensics", "ident"],
                )
            )
            # strings -n 6
            sres = context.run_command(
                self.role,
                "strings sample",
                f"strings -n 6 {ipath} | head -n 200",
                artifact_name=f"{step.step_id}_strings.txt",
            )
            cards.append(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Strings sample",
                    summary=(sres.get("stdout") or "")[:400],
                    tool="strings",
                    command=f"strings -n 6 {context.input_path.name}",
                    context=str(sres.get("stdout", "")),
                    tags=["forensics", "strings"],
                )
            )
            # hexdump/xxd
            if context.which("hexdump"):
                hcmd = f"hexdump -C -n 2048 {ipath}"
                hres = context.run_command(
                    self.role,
                    "hexdump sample",
                    hcmd,
                    artifact_name=f"{step.step_id}_hexdump.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Hexdump sample",
                        summary=(hres.get("stdout") or "")[:400],
                        tool="hexdump",
                        command=hcmd.replace(ipath, context.input_path.name),
                        context=str(hres.get("stdout", "")),
                        tags=["forensics", "hexdump"],
                    )
                )
            elif context.which("xxd"):
                xcmd = f"xxd -l 2048 -g 1 {ipath}"
                xres = context.run_command(
                    self.role,
                    "xxd sample",
                    xcmd,
                    artifact_name=f"{step.step_id}_xxd.txt",
                )
                cards.append(
                    EvidenceCard(
                        id="",
                        source_agent=self.role,
                        title="Hexdump sample (xxd)",
                        summary=(xres.get("stdout") or "")[:400],
                        tool="xxd",
                        command=xcmd.replace(ipath, context.input_path.name),
                        context=str(xres.get("stdout", "")),
                        tags=["forensics", "hexdump", "fallback"],
                    )
                )
            else:
                self.request_support("General", "Neither hexdump nor xxd available; limit binary surface insight.")

            # If file output hints a ZIP, try unzip/7z
            try:
                ftxt = (finfo.get("stdout") or "").lower()
                if "zip" in ftxt or context.input_path.suffix.lower() in {".zip", ".docx"}:
                    if context.which("unzip"):
                        uz = context.run_command(
                            self.role,
                            "unzip listing",
                            f"unzip -l {ipath}",
                            artifact_name=f"{step.step_id}_unzip_l.txt",
                        )
                        cards.append(
                            EvidenceCard(
                                id="",
                                source_agent=self.role,
                                title="Zip entries (unzip -l)",
                                summary=(uz.get("stdout") or "")[:400],
                                tool="unzip",
                                command=f"unzip -l {context.input_path.name}",
                                context=str(uz.get("stdout", "")),
                                tags=["forensics", "zip"],
                            )
                        )
                    elif context.which("7z"):
                        lz = context.run_command(
                            self.role,
                            "7z listing",
                            f"7z l {ipath}",
                            artifact_name=f"{step.step_id}_7z_l.txt",
                        )
                        cards.append(
                            EvidenceCard(
                                id="",
                                source_agent=self.role,
                                title="Archive entries (7z l)",
                                summary=(lz.get("stdout") or "")[:400],
                                tool="7z",
                                command=f"7z l {context.input_path.name}",
                                context=str(lz.get("stdout", "")),
                                tags=["forensics", "archive", "fallback"],
                            )
                        )
                    else:
                        self.request_support("General", "Archive detected but unzip/7z missing; cannot enumerate entries.")
            except Exception:
                pass

            # Content-aware adaptive proposals based on identification/strings
            try:
                ftxt_low = (finfo.get("stdout") or "").lower()
            except Exception:
                ftxt_low = ""
            try:
                s_low = (sres.get("stdout") or "").lower()
            except Exception:
                s_low = ""

            def _prop(desc: str, tools: List[str]):
                try:
                    self.propose_step(context, plan, desc, "ForensicsExecutorAgent", tools=tools)
                except Exception:
                    pass

            # Images -> steganalysis
            if any(k in ftxt_low for k in ("jpeg", "png", "gif", "bmp", "tiff")):
                _prop("Perform steganalysis on image assets (exif, zsteg/steghide/outguess)", ["exiftool", "zsteg", "steghide"])
            # Audio -> audio-stego or spectrogram
            if any(k in ftxt_low for k in ("wav", "mp3", "flac", "ogg")):
                _prop("Inspect audio for steganography and hidden channels", ["sox", "audacity"])  # tools as hints
            # Archives -> detailed extraction
            if any(k in ftxt_low for k in ("zip", "7-zip", "rar", "tar", "gzip", "bzip2", "xz")):
                _prop("Thoroughly extract and inspect archive contents", ["unzip", "7z", "tar"])
            # Network captures
            if any(k in ftxt_low for k in ("pcap", "tcpdump")):
                _prop("Analyze pcap flows (tshark/tcpdump) and carve credentials/artifacts", ["tshark", "tcpdump"])            
            # PDFs
            if "pdf" in ftxt_low:
                _prop("Extract PDF metadata and embedded streams", ["pdfinfo", "pdfimages", "qpdf"])
            # Office documents
            if any(k in ftxt_low for k in ("microsoft", ".docx", ".xlsx", ".pptx")):
                _prop("Extract OOXML parts and metadata for Office documents", ["unzip", "exiftool"])
            # Disk images / FS
            if any(k in ftxt_low for k in ("filesystem", "ext4", "ntfs", "fat", "iso 9660")):
                _prop("Mount or carve filesystem to recover files and timestamps", ["mount", "sleuthkit"])            

            # Opportunistic automatic runs for common formats
            try:
                # Images: EXIF
                if any(k in ftxt_low for k in ("jpeg", "jpg", "png", "gif", "bmp", "tiff")) and context.which("exiftool"):
                    ex = context.run_command(
                        self.role,
                        "exiftool metadata",
                        f"exiftool {ipath}",
                        artifact_name=f"{step.step_id}_exiftool.txt",
                    )
                    cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="Image metadata (exiftool)",
                            summary=(ex.get("stdout") or "")[:400],
                            tool="exiftool",
                            command=f"exiftool {context.input_path.name}",
                            context=str(ex.get("stdout", "")),
                            tags=["forensics", "image", "metadata"],
                        )
                    )
                # PDF: pdfinfo/pdfimages
                if "pdf" in ftxt_low and context.which("pdfinfo"):
                    pi = context.run_command(
                        self.role,
                        "pdfinfo",
                        f"pdfinfo {ipath}",
                        artifact_name=f"{step.step_id}_pdfinfo.txt",
                    )
                    cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="PDF info",
                            summary=(pi.get("stdout") or "")[:400],
                            tool="pdfinfo",
                            command=f"pdfinfo {context.input_path.name}",
                            context=str(pi.get("stdout", "")),
                            tags=["forensics", "pdf"],
                        )
                    )
                    if context.which("pdfimages"):
                        pim = context.run_command(
                            self.role,
                            "pdfimages list",
                            f"pdfimages -list {ipath}",
                            artifact_name=f"{step.step_id}_pdfimages_list.txt",
                        )
                        cards.append(
                            EvidenceCard(
                                id="",
                                source_agent=self.role,
                                title="PDF images (pdfimages -list)",
                                summary=(pim.get("stdout") or "")[:400],
                                tool="pdfimages",
                                command=f"pdfimages -list {context.input_path.name}",
                                context=str(pim.get("stdout", "")),
                                tags=["forensics", "pdf", "images"],
                            )
                        )
                # PCAP: tshark quick stats if available
                if any(k in ftxt_low for k in ("pcap", "tcpdump")) and context.which("tshark"):
                    ts = context.run_command(
                        self.role,
                        "tshark summary",
                        f"tshark -r {ipath} -q -z io,stat,0 | head -n 80",
                        artifact_name=f"{step.step_id}_tshark_stat.txt",
                        use_shell=True,
                    )
                    cards.append(
                        EvidenceCard(
                            id="",
                            source_agent=self.role,
                            title="PCAP IO stats (tshark)",
                            summary=(ts.get("stdout") or "")[:400],
                            tool="tshark",
                            command=f"tshark -r {context.input_path.name} -q -z io,stat,0",
                            context=str(ts.get("stdout", "")),
                            tags=["forensics", "pcap"],
                        )
                    )
            except Exception:
                pass

        return cards

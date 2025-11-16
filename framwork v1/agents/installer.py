"""
Installer agent: installs required tools, performs health checks, and emits
capability cards for downstream gating.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
import hashlib

from framework.context import CaseContext
from framework.evidence import EvidenceCard
from framework.plans import TaskPlan

from .base import BaseAgent


class InstallerAgent(BaseAgent):
    role = "Installer"

    def run(self, context: CaseContext, plan: TaskPlan, **_) -> None:
        self.bind_context(context)
        self.log("round_start", {"plan_id": plan.plan_id})

        # Determine capabilities needed from plan
        need_qemu = False
        need_angr = False
        for s in plan.steps:
            tools = set(s.tools or [])
            if "qemu" in tools or "qemu-x86_64" in tools:
                need_qemu = True
            if s.assigned_executor == "SymExecExecutorAgent" or "angr" in tools:
                need_angr = True

        # Aggregate declared tools for this plan (guides installation attempts)
        declared: List[str] = []
        try:
            for s in plan.steps:
                for t in (s.tools or []):
                    if t and t not in declared:
                        declared.append(t)
        except Exception:
            pass

        # Health check helpers
        def _check_qemu() -> Tuple[bool, str, Optional[str]]:
            which = context.which("qemu-x86_64")
            if not which:
                return False, "qemu-x86_64 not found", None
            res = context.run_command(
                self.role,
                "qemu version",
                "qemu-x86_64 -version",
                use_shell=False,
                artifact_name=f"{plan.plan_id}_qemu_version.txt",
            )
            ok = (res.get("returncode") == 0)
            ver = (res.get("stdout") or "").strip()
            return ok, (f"qemu-x86_64 path={which}; version={ver}" if ok else f"failed to run qemu-x86_64: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_angr() -> Tuple[bool, str, Optional[str]]:
            py = getattr(context.config, "python_bin", "python3")
            res = context.run_command(
                self.role,
                "angr import",
                f"{py} -c 'import angr,sys; print(getattr(angr, \"__version__\", \"ok\"))'",
                use_shell=True,
                artifact_name=f"{plan.plan_id}_angr_check.txt",
            )
            ok = (res.get("returncode") == 0)
            out = (res.get("stdout") or "").strip()
            return ok, (f"angr ok version={out}" if ok else f"angr import failed: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_readelf() -> Tuple[bool, str, Optional[str]]:
            # Prefer 'readelf', fallback to 'greadelf' (Homebrew binutils)
            bin_name = None
            for cand in ("readelf", "greadelf"):
                w = context.which(cand)
                if w:
                    bin_name = cand
                    break
            if not bin_name:
                return False, "readelf/greadelf not found", None
            which = context.which(bin_name) or bin_name
            res = context.run_command(
                self.role,
                f"{bin_name} --version",
                f"{bin_name} --version",
                use_shell=False,
                artifact_name=f"{plan.plan_id}_{bin_name}_version.txt",
            )
            ok = (res.get("returncode") == 0)
            ver = (res.get("stdout") or "").strip()
            return ok, (f"{bin_name} path={which}; version={ver}" if ok else f"failed to run {bin_name}: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_otool() -> Tuple[bool, str, Optional[str]]:
            # Use the actual input to validate presence/behavior
            ipath = context.input_path.as_posix()
            if not context.which("otool"):
                return False, "otool not found", None
            res = context.run_command(
                self.role,
                "otool header check",
                f"otool -h {ipath}",
                artifact_name=f"{plan.plan_id}_otool_h.txt",
            )
            ok = (res.get("returncode") == 0)
            return ok, ("otool ok" if ok else f"otool failed: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_llvm_objdump() -> Tuple[bool, str, Optional[str]]:
            if not context.which("llvm-objdump"):
                return False, "llvm-objdump not found", None
            res = context.run_command(
                self.role,
                "llvm-objdump version",
                "llvm-objdump --version",
                artifact_name=f"{plan.plan_id}_llvm_objdump_version.txt",
            )
            ok = (res.get("returncode") == 0)
            return ok, (res.get("stdout") or "").strip() , str(res.get("artifact_path") or "") or None

        def _check_llvm_readobj() -> Tuple[bool, str, Optional[str]]:
            if not context.which("llvm-readobj"):
                return False, "llvm-readobj not found", None
            res = context.run_command(
                self.role,
                "llvm-readobj version",
                "llvm-readobj --version",
                artifact_name=f"{plan.plan_id}_llvm_readobj_version.txt",
            )
            ok = (res.get("returncode") == 0)
            return ok, (res.get("stdout") or "").strip() , str(res.get("artifact_path") or "") or None

        def _check_objdump() -> Tuple[bool, str, Optional[str]]:
            if not context.which("objdump"):
                return False, "objdump not found", None
            res = context.run_command(
                self.role,
                "objdump version",
                "objdump --version | head -n 1",
                use_shell=True,
                artifact_name=f"{plan.plan_id}_objdump_version.txt",
            )
            ok = (res.get("returncode") == 0)
            return ok, (res.get("stdout") or "").strip() , str(res.get("artifact_path") or "") or None

        def _check_r2() -> Tuple[bool, str, Optional[str]]:
            which = context.which("r2")
            if not which:
                return False, "r2 not found", None
            res = context.run_command(
                self.role,
                "radare2 version",
                "r2 -v",
                artifact_name=f"{plan.plan_id}_r2_version.txt",
            )
            ok = (res.get("returncode") == 0)
            ver = (res.get("stdout") or "").strip()
            return ok, (f"r2 path={which}; version={ver}" if ok else f"failed to run r2: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_rabin2() -> Tuple[bool, str, Optional[str]]:
            which = context.which("rabin2")
            if not which:
                return False, "rabin2 not found", None
            res = context.run_command(
                self.role,
                "rabin2 version",
                "rabin2 -v",
                artifact_name=f"{plan.plan_id}_rabin2_version.txt",
            )
            ok = (res.get("returncode") == 0)
            ver = (res.get("stdout") or "").strip()
            return ok, (f"rabin2 path={which}; version={ver}" if ok else f"failed to run rabin2: {res.get('stderr','')}") , str(res.get("artifact_path") or "") or None

        def _check_strings() -> Tuple[bool, str, Optional[str]]:
            which = context.which("strings")
            if not which:
                return False, "strings not found", None
            # BSD strings may not support --version; do a simple usage
            res = context.run_command(
                self.role,
                "strings usage",
                # Run against the binary itself with no stdin so command terminates immediately.
                f"strings -n 8 \"{which}\" >/dev/null 2>&1",
                use_shell=True,
                artifact_name=f"{plan.plan_id}_strings_check.txt",
            )
            ok = (res.get("returncode") == 0) or bool(which)
            out = (res.get("stdout") or "").strip() or "strings present"
            return ok, (f"strings path={which}; {out}"), str(res.get("artifact_path") or "") or None

        # Pre-check existing state
        qemu_ok, qemu_info, qemu_art = _check_qemu() if need_qemu else (False, "not requested", None)
        angr_ok, angr_info, angr_art = _check_angr() if need_angr and getattr(context.config, "enable_angr", False) else (False, "disabled or not requested", None)
        # Always check readelf since many static routes prefer it
        readelf_ok, readelf_info, readelf_art = _check_readelf()
        otool_ok, otool_info, otool_art = _check_otool()
        llvmo_ok, llvmo_info, llvmo_art = _check_llvm_objdump()
        llvmr_ok, llvmr_info, llvmr_art = _check_llvm_readobj()
        objdump_ok, objdump_info, objdump_art = _check_objdump()
        r2_ok, r2_info, r2_art = _check_r2()
        rabin2_ok, rabin2_info, rabin2_art = _check_rabin2()
        strings_ok, strings_info, strings_art = _check_strings()

        def _hash(p: Optional[str]) -> Optional[str]:
            try:
                if not p:
                    return None
                h=hashlib.sha256()
                with open(p,'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                return h.hexdigest()
            except Exception:
                return None

        # Produce evidence cards for capability checks (with artifact+hash)
        try:
            from framework.evidence import EvidenceCard
            def add_check_card(title: str, info: str, art: Optional[str]) -> None:
                card = EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title=title,
                    summary=info,
                    tool="env",
                    command=title,
                    context=info,
                    tags=["capability", "check"],
                    created_by=self.role,
                )
                if art:
                    from pathlib import Path as _P
                    card.attach_artifact(_P(art))
                context.add_evidence(card)
            if need_qemu:
                add_check_card("Capability check: qemu-x86_64 -version", qemu_info, qemu_art)
            add_check_card("Capability check: readelf --version", readelf_info, readelf_art)
            add_check_card("Capability check: otool -h", otool_info, otool_art)
            add_check_card("Capability check: llvm-objdump --version", llvmo_info, llvmo_art)
            add_check_card("Capability check: llvm-readobj --version", llvmr_info, llvmr_art)
            add_check_card("Capability check: objdump --version", objdump_info, objdump_art)
            add_check_card("Capability check: r2 -v", r2_info, r2_art)
            add_check_card("Capability check: rabin2 -v", rabin2_info, rabin2_art)
            add_check_card("Capability check: strings", strings_info, strings_art)
            if need_angr and getattr(context.config, "enable_angr", False):
                add_check_card("Capability check: angr import", angr_info, angr_art)
        except Exception:
            pass

        # Installation attempts (brew/pip) only if missing and allowed (Installer is the sole actor)
        try:
            auto_brew = bool(getattr(context.config, "auto_install_tools", False))
            brew_ok = False
            brew = getattr(context.config, "brew_bin", "brew")
            if auto_brew and context.is_macos():
                if context.which(brew):
                    brew_ok = True
                elif getattr(context.config, "brew_install_allowed", False):
                    context.run_command(
                        self.role,
                        "install homebrew",
                        '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                        artifact_name=f"{plan.plan_id}_install_brew.txt",
                        use_shell=True,
                        timeout_secs=1800,
                    )
                    for candidate in ("brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
                        if context.which(candidate):
                            brew = candidate
                            brew_ok = True
                            break
            # Brew install for missing declared tools based on tool_install_map
            if auto_brew and brew_ok:
                install_map = dict(getattr(context.config, "tool_install_map", {}))
                casks = set(getattr(context.config, "tool_install_casks", []))
                # Identify missing tools among declared
                check_bin_map = {
                    "r2": ["r2"],
                    "radare2": ["r2"],
                    "rabin2": ["rabin2"],
                    "binwalk": ["binwalk"],
                    # macOS ships qemu-system-x86_64 (full system) instead of qemu-x86_64 user-mode.
                    "qemu": ["qemu-system-x86_64", "qemu-x86_64"],
                    "qemu-x86_64": ["qemu-system-x86_64", "qemu-x86_64"],
                    # Homebrew installs Ghidra launcher as ghidraRun; include original name as fallback.
                    "ghidra": ["ghidraRun", "ghidra"],
                    "strings": ["strings"],
                    "otool": ["otool"],
                    "nm": ["nm"],
                    "readelf": ["readelf", "greadelf"],
                    "objdump": ["objdump", "gobjdump", "llvm-objdump"],
                    "llvm-objdump": ["llvm-objdump"],
                    "llvm-readobj": ["llvm-readobj"],
                }
                to_install: List[str] = []
                for t in declared:
                    bins = check_bin_map.get(t, [])
                    if bins and not any(context.which(b) for b in bins):
                        if install_map.get(t):
                            to_install.append(t)
                for t in to_install:
                    pkg = install_map.get(t)
                    is_cask = pkg in casks
                    cmd = f"{brew} install {'--cask ' if is_cask else ''}{pkg}"
                    res = context.run_command(
                        self.role,
                        f"install {pkg}",
                        cmd,
                        artifact_name=f"{plan.plan_id}_install_{pkg}.txt",
                        use_shell=True,
                        timeout_secs=1800,
                    )
                    try:
                        from framework.evidence import EvidenceCard as _EC
                        from pathlib import Path as _P
                        ic = _EC(
                            id="",
                            source_agent=self.role,
                            title=f"Install attempt: {pkg} (brew)",
                            summary=(res.get("stdout") or "")[:400],
                            tool="brew",
                            command=cmd,
                            context=str(res.get("stdout", "")),
                            tags=["install", "attempt"],
                            created_by=self.role,
                        )
                        if res.get("artifact_path"):
                            ic.attach_artifact(_P(str(res.get("artifact_path"))))
                        context.add_evidence(ic)
                    except Exception:
                        pass

            # Python packages via pip if allowed
            auto_py = bool(getattr(context.config, 'auto_install_python_tools', False))
            pip_allowed = bool(getattr(context.config, 'pip_install_allowed', False))
            if auto_py and pip_allowed:
                py_tool_map = dict(getattr(context.config, 'python_tool_map', {}))
                import_map = dict(getattr(context.config, 'python_import_map', {}))
                py = getattr(context.config, 'python_bin', 'python3')
                pip = getattr(context.config, 'pip_bin', 'pip3')
                py_needed: List[str] = []
                for t in declared:
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
                    res = context.run_command(
                        self.role,
                        f"pip install {pkg}",
                        f"{pip} install {pkg}",
                        use_shell=True,
                        artifact_name=f"{plan.plan_id}_pip_{pkg}.txt",
                        timeout_secs=1800,
                    )
                    try:
                        from framework.evidence import EvidenceCard as _EC
                        from pathlib import Path as _P
                        ic = _EC(
                            id="",
                            source_agent=self.role,
                            title=f"Install attempt: {pkg} (pip)",
                            summary=(res.get("stdout") or "")[:400],
                            tool="pip",
                            command=f"{pip} install {pkg}",
                            context=str(res.get("stdout", "")),
                            tags=["install", "attempt"],
                            created_by=self.role,
                        )
                        if res.get("artifact_path"):
                            ic.attach_artifact(_P(str(res.get("artifact_path"))))
                        context.add_evidence(ic)
                    except Exception:
                        pass
        except Exception:
            pass

        # Re-run checks to capture post-install state
        qemu_ok, qemu_info, qemu_art = _check_qemu() if need_qemu else (qemu_ok, qemu_info, qemu_art)
        angr_ok, angr_info, angr_art = _check_angr() if need_angr and getattr(context.config, "enable_angr", False) else (angr_ok, angr_info, angr_art)
        readelf_ok, readelf_info, readelf_art = _check_readelf()
        otool_ok, otool_info, otool_art = _check_otool()
        llvmo_ok, llvmo_info, llvmo_art = _check_llvm_objdump()
        llvmr_ok, llvmr_info, llvmr_art = _check_llvm_readobj()
        objdump_ok, objdump_info, objdump_art = _check_objdump()
        r2_ok, r2_info, r2_art = _check_r2()
        rabin2_ok, rabin2_info, rabin2_art = _check_rabin2()
        strings_ok, strings_info, strings_art = _check_strings()

        # pip for angr
        if need_angr and not angr_ok and getattr(context.config, "auto_install_python_tools", False) and getattr(context.config, "pip_install_allowed", False):
            pip = getattr(context.config, "pip_bin", "pip3")
            inst_angr = context.run_command(
                self.role,
                "pip install angr",
                f"{pip} install angr",
                artifact_name=f"{plan.plan_id}_pip_angr.txt",
                use_shell=True,
                timeout_secs=1800,
            )
            try:
                from framework.evidence import EvidenceCard
                from pathlib import Path as _P
                ic = EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Install attempt: angr (pip)",
                    summary=str(inst_angr.get("stdout",""))[:400],
                    tool="pip",
                    command=f"{pip} install angr",
                    context=str(inst_angr.get("stdout","")),
                    tags=["install", "attempt"],
                    created_by=self.role,
                )
                if inst_angr.get("artifact_path"):
                    ic.attach_artifact(_P(str(inst_angr.get("artifact_path"))))
                context.add_evidence(ic)
            except Exception:
                pass
            angr_ok, angr_info = _check_angr()

        # Emit capability card summarizing the final state
        try:
            # Build capability JSON with artifact hashes
            cap = {
                "qemu": {"ok": qemu_ok, "info": qemu_info, "artifact": qemu_art, "sha256": _hash(qemu_art)},
                "readelf": {"ok": readelf_ok, "info": readelf_info, "artifact": readelf_art, "sha256": _hash(readelf_art)},
                "angr": {"ok": angr_ok, "info": angr_info, "artifact": angr_art, "sha256": _hash(angr_art)},
                "otool": {"ok": otool_ok, "info": otool_info, "artifact": otool_art, "sha256": _hash(otool_art)},
                "llvm-objdump": {"ok": llvmo_ok, "info": llvmo_info, "artifact": llvmo_art, "sha256": _hash(llvmo_art)},
                "llvm-readobj": {"ok": llvmr_ok, "info": llvmr_info, "artifact": llvmr_art, "sha256": _hash(llvmr_art)},
                "objdump": {"ok": objdump_ok, "info": objdump_info, "artifact": objdump_art, "sha256": _hash(objdump_art)},
                "radare2": {"ok": r2_ok, "info": r2_info, "artifact": r2_art, "sha256": _hash(r2_art)},
                "rabin2": {"ok": rabin2_ok, "info": rabin2_info, "artifact": rabin2_art, "sha256": _hash(rabin2_art)},
                "strings": {"ok": strings_ok, "info": strings_info, "artifact": strings_art, "sha256": _hash(strings_art)},
                "enable_angr": bool(getattr(context.config, 'enable_angr', False)),
            }
            import json as _json
            cap_path = context.create_artifact_path(f"{plan.plan_id}_capability_card.json")
            cap_path.write_text(_json.dumps(cap, indent=2), encoding="utf-8")
            summary = (
                f"Capabilities: qemu-x86_64={'yes' if qemu_ok else 'no'}; readelf={'yes' if readelf_ok else 'no'}; "
                f"angr={'yes' if angr_ok else 'no'}; enable_angr={'yes' if getattr(context.config, 'enable_angr', False) else 'no'}"
            )
            from framework.evidence import EvidenceCard
            ccard = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Capability Card",
                summary=summary,
                tool="env",
                command="installer: health checks",
                context=_json.dumps(cap),
                tags=["env", "capability"],
                created_by=self.role,
            )
            ccard.attach_artifact(cap_path)
            context.add_evidence(ccard)
        except Exception:
            # If capability card cannot be produced, record failure
            fail = f"Installer failed to produce Capability Card; qemu_ok={qemu_ok}, angr_ok={angr_ok}"
            context.add_evidence(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Installer failure",
                    summary=fail,
                    tool="installer",
                    command="installer: failure",
                    context=fail,
                    tags=["install", "failure"],
                    created_by=self.role,
                )
            )

        # If required capabilities still missing, record explicit failure reason
        missing_reasons: List[str] = []
        if need_qemu and not qemu_ok:
            missing_reasons.append("qemu-x86_64 unavailable after install")
        if need_angr and not angr_ok and getattr(context.config, "enable_angr", False):
            missing_reasons.append("angr unavailable after install")
        if not readelf_ok:
            missing_reasons.append("readelf/greadelf unavailable")
        if ("radare2" in declared or "r2" in declared or "rabin2" in declared) and not (r2_ok or rabin2_ok):
            missing_reasons.append("radare2/rabin2 unavailable")
        if missing_reasons:
            reason = "; ".join(missing_reasons)
            context.add_evidence(
                EvidenceCard(
                    id="",
                    source_agent=self.role,
                    title="Capability failure",
                    summary=reason,
                    tool="installer",
                    command="installer: post-check",
                    context=reason,
                    tags=["capability", "failure"],
                    created_by=self.role,
                )
            )
            try:
                # force pivot to static route when capabilities insufficient
                context.route_tracker["force_static_template"] = True
                context.add_support_request({
                    "from": self.role,
                    "to": "General",
                    "payload": "Installer reports missing capabilities; enforcing static-only route.",
                })
            except Exception:
                pass

        # Mandatory LLM call: summarize capability state and propose next actions
        try:
            matrix = [
                f"qemu={'yes' if qemu_ok else 'no'}",
                f"angr={'yes' if angr_ok else 'no'}",
                f"readelf={'yes' if readelf_ok else 'no'}",
                f"otool={'yes' if otool_ok else 'no'}",
                f"llvm-objdump={'yes' if llvmo_ok else 'no'}",
                f"llvm-readobj={'yes' if llvmr_ok else 'no'}",
                f"objdump={'yes' if objdump_ok else 'no'}",
            ]
            prompt = (
                "You are the Installer. Given this capability matrix, propose minimal installation/fallback actions and quick health checks.\n"
                + "\n".join("- " + s for s in matrix) + "\nEnvironment: macOS Terminal (zsh)."
            )
            resp = str(self.call_model(prompt))
            from framework.evidence import EvidenceCard as _EC
            card = _EC(
                id="",
                source_agent=self.role,
                title="Installer LLM advice",
                summary=resp[:400],
                tool="LLM",
                command="installer_llm",
                context=resp,
                tags=["capability", "info"],
                created_by=self.role,
            )
            context.add_evidence(card)
        except Exception:
            pass

        self.clear_context()
        return None

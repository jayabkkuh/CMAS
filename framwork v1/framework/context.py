"""
Shared context object that persists across the agent collaboration lifecycle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
import sys
import shlex
import subprocess
import textwrap
from pathlib import Path
from typing import Dict, List, Optional
import time

from .evidence import EvidenceCard
from .logger import ValidatorLogger
from .plans import TaskPlan
from .config import FrameworkConfig, load_config
from .knowledge import SkillBook, SkillEntry


@dataclass
class CaseContext:
    """
    Mutable state bag that flows through every round of the framework.
    """

    mission_id: str
    input_path: Path
    raw_inputs: Dict[str, Path] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    # In-memory runtime trackers (not persisted across runs)
    route_tracker: Dict[str, object] = field(default_factory=dict)
    evidence: List[EvidenceCard] = field(default_factory=list)
    strategy_history: List[TaskPlan] = field(default_factory=list)
    active_plan: Optional[TaskPlan] = None
    execution_logs: List[Dict[str, str]] = field(default_factory=list)
    support_requests: List[Dict[str, str]] = field(default_factory=list)
    validation_report: Optional[Dict[str, str]] = None
    retrospective: Optional[Dict[str, str]] = None
    logger: Optional[ValidatorLogger] = None
    config: FrameworkConfig = field(default_factory=FrameworkConfig)
    mission_dir: Optional[Path] = field(init=False, default=None)
    artifacts_dir: Optional[Path] = field(init=False, default=None)
    logs_dir: Optional[Path] = field(init=False, default=None)
    skillbook: Optional[SkillBook] = field(init=False, default=None)
    id_counters: Dict[str, int] = field(default_factory=dict)
    command_log: List[Dict[str, str]] = field(default_factory=list)
    plan_reviews: List[Dict[str, str]] = field(default_factory=list)
    dialogue_log: List[Dict[str, str]] = field(default_factory=list)
    mission_status: str = "in_progress"
    validator_commands: List[List[str]] = field(default_factory=list)
    # macOS Terminal state
    terminal_window_id: Optional[int] = None
    terminal_tab_index: Optional[int] = None
    # Current round index for title/telemetry
    current_round: int = 1

    def set_terminal_title(self, agent: str = "Team", description: Optional[str] = None) -> None:
        """
        Set Terminal tab title based on template. Respects reuse_tab/window tracking.

        Safe no-op on non-macOS or when Terminal control disabled.
        """
        try:
            if not getattr(self.config, "macos_terminal_control", False):
                return
            if not self.is_macos():
                return
            # Ensure Terminal is running and a window exists if possible
            import subprocess  # lazy import
            subprocess.run(["osascript", "-e", "tell application \"Terminal\" to activate"], check=False, capture_output=True, text=True)
            reuse_tab = bool(getattr(self.config, "macos_terminal_reuse_tab", True))
            # If no known window, create a session to bind title
            if reuse_tab and not self.terminal_window_id:
                subprocess.run(["osascript", "-e", "tell application \"Terminal\" to do script \"\""], check=False, capture_output=True, text=True)
                rid = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to id of front window"], check=False, capture_output=True, text=True)
                try:
                    wid = int((rid.stdout or "").strip())
                    if wid > 0:
                        self.terminal_window_id = wid
                except Exception:
                    pass
                rtab = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to index of selected tab of front window"], check=False, capture_output=True, text=True)
                try:
                    tidx = int((rtab.stdout or "").strip())
                    if tidx > 0:
                        self.terminal_tab_index = tidx
                except Exception:
                    pass
            tmpl = getattr(self.config, "macos_terminal_title_template", "{mission_id} R{round} · {agent}")
            text = str(tmpl).format(
                mission_id=self.mission_id,
                round=getattr(self, "current_round", 1),
                agent=agent,
                cmd_id="",
                description=(description or ""),
            )
            title_esc = text.replace("\\", "\\\\").replace("\"", "\\\"")
            if reuse_tab and self.terminal_window_id and self.terminal_tab_index:
                set_title = (
                    f"tell application \"Terminal\" to set custom title of tab {self.terminal_tab_index} of window id {self.terminal_window_id} to \"{title_esc}\""
                )
            else:
                set_title = "tell application \"Terminal\" to set custom title of selected tab of front window to \"" + title_esc + "\""
            subprocess.run(["osascript", "-e", set_title], check=False, capture_output=True, text=True)
        except Exception:
            return

    def launch_terminal_tab(self, command: str, title: str = "Watcher") -> None:
        """
        Open a new Terminal tab and execute the given shell command. Reuses the
        known Terminal window if tracked. No output capture here.
        """
        try:
            if not getattr(self.config, "macos_terminal_control", False):
                return
            if not self.is_macos():
                return
            import subprocess
            subprocess.run(["osascript", "-e", "tell application \"Terminal\" to activate"], check=False, capture_output=True, text=True)
            reuse_tab = bool(getattr(self.config, "macos_terminal_reuse_tab", True))
            cmd_esc = command.replace("\\", "\\\\").replace("\"", "\\\"")
            if self.terminal_window_id:
                do_line = f"tell application \"Terminal\" to do script \"{cmd_esc}\" in window id {self.terminal_window_id}"
            else:
                do_line = f"tell application \"Terminal\" to do script \"{cmd_esc}\""
            subprocess.run(["osascript", "-e", do_line], check=False, capture_output=True, text=True)
            # Update title for the new selected tab
            try:
                rid = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to id of front window"], check=False, capture_output=True, text=True)
                wid = int((rid.stdout or "").strip()) if (rid.stdout or "").strip() else None
                if wid:
                    self.terminal_window_id = wid
                rtab = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to index of selected tab of front window"], check=False, capture_output=True, text=True)
                tidx = int((rtab.stdout or "").strip()) if (rtab.stdout or "").strip() else None
                if tidx:
                    self.terminal_tab_index = tidx
                title_esc = title.replace("\\", "\\\\").replace("\"", "\\\"")
                set_title = (
                    f"tell application \"Terminal\" to set custom title of tab {self.terminal_tab_index} of window id {self.terminal_window_id} to \"{title_esc}\""
                    if (reuse_tab and self.terminal_window_id and self.terminal_tab_index)
                    else f"tell application \"Terminal\" to set custom title of selected tab of front window to \"{title_esc}\""
                )
                subprocess.run(["osascript", "-e", set_title], check=False, capture_output=True, text=True)
            except Exception:
                pass
        except Exception:
            return

    def register_logger(self, logger: ValidatorLogger) -> None:
        self.logger = logger

    def next_id(self, prefix: str) -> str:
        counter = self.id_counters.get(prefix, 0) + 1
        self.id_counters[prefix] = counter
        return f"{prefix}-{counter:03d}"

    def add_evidence(self, card: EvidenceCard, linked_event_id: Optional[str] = None) -> None:
        # Normalize coordinates using address mapping when available
        try:
            self._normalize_card_coordinates(card)
        except Exception:
            pass
        if not card.id:
            card.id = self.next_id("ev")
        if linked_event_id:
            card.linked_event_id = linked_event_id
        self.evidence.append(card)
        if self.logger:
            self.logger.record_evidence(card)

    def _normalize_card_coordinates(self, card: EvidenceCard) -> None:
        # Skip mapping cards and environment-only cards
        ttl = (card.title or "").lower()
        if any(k in ttl for k in ("address mapping",)) or (card.tags and any(t in card.tags for t in ("capability", "env"))):
            return
        amap = self.route_tracker.get("address_map")
        if not isinstance(amap, dict):
            # fallback: attempt to load from last mapping evidence
            try:
                for e in reversed(self.evidence):
                    if isinstance(e.title, str) and e.title.lower() == "address mapping":
                        import json as _json
                        amap = _json.loads(e.context or "{}")
                        break
            except Exception:
                amap = None
        if not isinstance(amap, dict):
            return
        baddr = amap.get("baddr")
        try:
            if isinstance(baddr, str):
                baddr_int = int(baddr, 16) if baddr.startswith("0x") else int(baddr)
            else:
                baddr_int = int(baddr or 0)
        except Exception:
            baddr_int = 0
        sections = amap.get("sections") or []
        # Parse existing metadata hints
        vaddr = None
        if card.metadata:
            for key in ("vaddr", "vaddr_int", "address"):
                val = card.metadata.get(key)
                if not val:
                    continue
                try:
                    vaddr = int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
                    break
                except Exception:
                    continue
        # Compute offset if missing
        if card.offset is None:
            try:
                if vaddr is not None and baddr_int:
                    off = vaddr - baddr_int
                    if off >= 0:
                        card.offset = off
                        card.metadata.setdefault("offset_hex", f"0x{off:x}")
                elif card.metadata and card.metadata.get("offset"):
                    offv = card.metadata.get("offset")
                    card.offset = int(offv, 16) if isinstance(offv, str) and offv.startswith("0x") else int(offv)
            except Exception:
                pass
        # Compute vaddr from offset if needed
        if vaddr is None and card.offset is not None and baddr_int:
            vaddr = baddr_int + int(card.offset)
            card.metadata.setdefault("vaddr", f"0x{vaddr:x}")
        # Compute section if missing
        if not card.section:
            try:
                if vaddr is not None and sections:
                    for sec in sections:
                        sv = int(sec.get("vaddr") or 0)
                        ev = int(sec.get("vaddr_end") or (sv + int(sec.get("size") or 0)))
                        if sv <= vaddr < ev:
                            card.section = str(sec.get("name") or "")
                            break
                elif card.offset is not None and sections:
                    poff = int(card.offset)
                    for sec in sections:
                        sp = int(sec.get("paddr") or 0)
                        ep = int(sec.get("paddr_end") or (sp + int(sec.get("size") or 0)))
                        if sp <= poff < ep:
                            card.section = str(sec.get("name") or "")
                            break
            except Exception:
                pass
        # Attach mapping card id to evidence metadata for traceability
        try:
            mid = self.route_tracker.get("mapping_card_id")
            if isinstance(mid, str) and mid:
                card.metadata.setdefault("mapping_card_id", mid)
        except Exception:
            pass

    def add_strategy_revision(self, plan: TaskPlan) -> None:
        if not plan.plan_id:
            plan.plan_id = self.next_id("plan")
        if not plan.version:
            plan.version = self.next_id("planv")
        if not plan.status:
            plan.status = "draft"
        self.strategy_history.append(plan)
        self.plan_reviews.append(
            {
                "plan_id": plan.plan_id,
                "version": plan.version,
                "decision": plan.status,
                "notes": plan.notes or "",
            }
        )

    def set_active_plan(self, plan: TaskPlan) -> None:
        self.active_plan = plan
        # Emit a snapshot for post-run plan inspection
        if self.logger:
            try:
                steps = []
                for s in plan.steps:
                    steps.append(
                        {
                            "description": s.description,
                            "executor": s.assigned_executor or "",
                            "status": getattr(s.status, "value", str(s.status)) if getattr(s, "status", None) else "pending",
                            "step_id": s.step_id or "",
                            "tools": ",".join(s.tools or []) if getattr(s, "tools", None) else "",
                        }
                    )
                self.logger.record_event(
                    agent="MissionController",
                    event_type="plan_snapshot",
                    payload={
                        "plan_id": plan.plan_id,
                        "version": plan.version or "",
                        "status": plan.status,
                        "category": plan.category,
                        "hypothesis": plan.hypothesis,
                        "steps": steps,
                    },
                )
            except Exception:
                pass

    def log_execution(self, entry: Dict[str, str]) -> None:
        self.execution_logs.append(entry)
        if self.logger:
            self.logger.record_execution(entry)

    def register_command(self, agent: str, description: str, command: str) -> str:
        command_id = self.next_id("cmd")
        entry = {
            "command_id": command_id,
            "agent": agent,
            "description": description,
            "command": command,
        }
        self.command_log.append(entry)
        return command_id

    def complete_command(self, command_id: str, stdout: str, stderr: str, returncode: int) -> None:
        for entry in self.command_log:
            if entry.get("command_id") == command_id:
                entry.update(
                    {
                        "stdout": stdout,
                        "stderr": stderr,
                        "returncode": str(returncode),
                    }
                )
                agent = entry.get("agent", "unknown")
                command = entry.get("command", "")
                if self.logger:
                    self.logger.record_command(agent, command, stdout)
                # Heuristic: update tool outcome stats in SkillBook
                try:
                    if self.skillbook:
                        tool = self._extract_prog(command)
                        ok = (returncode == 0) and (bool(stdout) or not bool(stderr))
                        if tool:
                            self.skillbook.record_tool_outcome(agent, tool, ok)
                            self.skillbook.save()
                except Exception:
                    pass
                break

    def register_command(self, agent: str, description: str, command: str) -> str:
        command_id = self.next_id("cmd")
        entry = {
            "command_id": command_id,
            "agent": agent,
            "description": description,
            "command": command,
        }
        self.command_log.append(entry)
        return command_id

    def complete_command(self, command_id: str, stdout: str, stderr: str, returncode: int) -> None:
        for entry in self.command_log:
            if entry["command_id"] == command_id:
                entry.update(
                    {
                        "stdout": stdout,
                        "stderr": stderr,
                        "returncode": str(returncode),
                    }
                )
                agent = entry.get("agent", "unknown")
                command = entry.get("command", "")
                if self.logger:
                    self.logger.record_command(agent, command, stdout)
                try:
                    if self.skillbook:
                        tool = self._extract_prog(command)
                        ok = (returncode == 0) and (bool(stdout) or not bool(stderr))
                        if tool:
                            self.skillbook.record_tool_outcome(agent, tool, ok)
                            self.skillbook.save()
                except Exception:
                    pass
                break

    def add_support_request(self, request: Dict[str, str]) -> str:
        request_id = self.next_id("sr")
        request = {**request, "request_id": request_id}
        self.support_requests.append(request)
        if self.logger:
            self.logger.record_event(
                agent=request.get("from", "unknown"),
                event_type="support_request",
                payload=request,
            )
        return request_id

    def which(self, name: str) -> Optional[str]:
        """
        Resolve a binary in PATH. Returns absolute path or None.
        """
        from shutil import which as _which  # local import to avoid global dependency

        return _which(name)

    def _extract_prog(self, action: str) -> Optional[str]:
        try:
            s = (action or "").strip()
            if not s:
                return None
            # strip wrappers like bash -lc '...'
            if s.startswith("bash -lc ") or s.startswith("/bin/bash -lc "):
                # try to extract inside quotes
                q = s.find("'")
                if q != -1:
                    tail = s[q+1:]
                    q2 = tail.find("'")
                    inner = tail[:q2] if q2 != -1 else tail
                else:
                    inner = s
                s = inner.strip()
            # split and get base program
            parts = shlex.split(s)
            if not parts:
                return None
            prog = parts[0]
            base = Path(prog).name
            # normalize common interpreters
            if base.startswith("python"):
                return "python"
            if base in ("/bin/bash", "bash", "sh", "zsh") and len(parts) >= 2:
                base2 = Path(parts[1]).name
                return base2 or base
            return base
        except Exception:
            return None

    def run_command(
        self,
        agent: str,
        description: str,
        command: str,
        artifact_name: Optional[str] = None,
        *,
        input_data: Optional[str] = None,
        timeout_secs: Optional[int] = None,
        use_shell: Optional[bool] = None,
        cwd: Optional[Path] = None,
    ) -> Dict[str, object]:
        """
        Execute a shell command with unified logging. Honors dry_run.

        Returns a dict with stdout, stderr, returncode, command_id, and
        artifact_path (if saved).
        """
        # Platform-aware adaptation of common tool invocations to improve success on macOS.
        # This only adjusts analysis commands (e.g., readelf -h, objdump -d) and leaves
        # capability checks (like readelf --version) unaffected.
        def _adapt_command_for_macos(cmd: str) -> str:
            try:
                if not self.is_macos():
                    return cmd
                out = cmd
                # Prefer llvm-readobj for ELF headers instead of readelf -h
                if "readelf -h" in out and self.which("llvm-readobj"):
                    out = out.replace("readelf -h", "llvm-readobj -h")
                # Prefer llvm-objdump for disassembly instead of objdump -d
                if "objdump -d" in out and self.which("llvm-objdump"):
                    out = out.replace("objdump -d", "llvm-objdump -d -M intel")
                return out
            except Exception:
                return cmd

        adapted = _adapt_command_for_macos(command)
        cmd_id = self.register_command(agent, description, adapted)
        if self.config.dry_run:
            stdout = f"[dry-run] {adapted}"
            stderr = ""
            returncode = 0
        else:
            try:
                # macOS Terminal control for executor agents
                use_terminal = (
                    getattr(self.config, "macos_terminal_control", False)
                    and self.is_macos()
                    and not self.config.dry_run
                    and (
                        getattr(self.config, "macos_terminal_for_all_agents", False)
                        or ("executor" in (agent or "").lower())
                    )
                )
                if use_terminal:
                    # Prepare script and output paths
                    base_dir = Path(str(cwd if cwd else self.mission_dir or Path.cwd())).expanduser().resolve()
                    stdout_path = self.create_artifact_path(f"{cmd_id}.stdout.txt").resolve()
                    stderr_path = self.create_artifact_path(f"{cmd_id}.stderr.txt").resolve()
                    rc_path = self.create_artifact_path(f"{cmd_id}.rc").resolve()
                    script_path = self.create_artifact_path(f"{cmd_id}.sh").resolve()
                    # Show header + command in Terminal, mirror outputs to artifacts via tee, and record rc
                    cmd_display = adapted.replace("\\", "\\\\").replace("\"", "\\\"")
                    script_lines = [
                        "#!/bin/bash",
                        "set -o pipefail",
                        f"cd \"{base_dir.as_posix()}\"",
                        f"echo \"==== {agent} [{cmd_id}] {description} ====\"",
                        f"echo \"$ {cmd_display}\"",
                        # Route stderr through tee to stderr file, stdout through tee to stdout file; capture rc from left side
                        f"{{ {{ {adapted} 2> >(tee \"{stderr_path.as_posix()}\" >&2); }} | tee \"{stdout_path.as_posix()}\"; rc=${{PIPESTATUS[0]}}; }}",
                        f"echo -n $rc > \"{rc_path.as_posix()}\"",
                        "echo \"[rc=$rc]\"",
                    ]
                    script = "\n".join(script_lines) + "\n"
                    script_path.write_text(script, encoding="utf-8")
                    try:
                        script_path.chmod(0o755)
                    except Exception:
                        pass
                    # Launch Terminal to run the script (reuse same tab if enabled)
                    try:
                        subprocess.run(["osascript", "-e", "tell application \"Terminal\" to activate"], check=False, capture_output=True, text=True)
                        reuse_tab = bool(getattr(self.config, "macos_terminal_reuse_tab", True))
                        if reuse_tab and self.terminal_window_id and self.terminal_tab_index:
                            # Reuse existing tab if window exists; otherwise fall back
                            do_line = (
                                f"tell application \"Terminal\" to if (exists window id {self.terminal_window_id}) "
                                f"then do script \"/bin/bash '{script_path.as_posix()}'\" in tab {self.terminal_tab_index} of window id {self.terminal_window_id} "
                                f"else do script \"/bin/bash '{script_path.as_posix()}'\""
                            )
                            subprocess.run(["osascript", "-e", do_line], check=False, capture_output=True, text=True)
                        elif reuse_tab and self.terminal_window_id:
                            # Has window but no saved tab; run in the window (creates a new tab) and record its index
                            do_line = f"tell application \"Terminal\" to do script \"/bin/bash '{script_path.as_posix()}'\" in window id {self.terminal_window_id}"
                            subprocess.run(["osascript", "-e", do_line], check=False, capture_output=True, text=True)
                        else:
                            # New window or reuse disabled
                            do_line = f"tell application \"Terminal\" to do script \"/bin/bash '{script_path.as_posix()}'\""
                            subprocess.run(["osascript", "-e", do_line], check=False, capture_output=True, text=True)
                        # Capture window id and selected tab index for future reuse
                        if reuse_tab:
                            rid = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to id of front window"], check=False, capture_output=True, text=True)
                            try:
                                wid = int((rid.stdout or "").strip())
                                if wid > 0:
                                    self.terminal_window_id = wid
                            except Exception:
                                pass
                            rtab = subprocess.run(["osascript", "-e", "tell application \"Terminal\" to index of selected tab of front window"], check=False, capture_output=True, text=True)
                            try:
                                tidx = int((rtab.stdout or "").strip())
                                if tidx > 0:
                                    self.terminal_tab_index = tidx
                            except Exception:
                                pass
                        # Set tab custom title per command unless configured to only set on round start
                        try:
                            if not getattr(self.config, "macos_terminal_title_on_round_only", True):
                                tmpl = getattr(self.config, "macos_terminal_title_template", "{mission_id} R{round} · {agent}")
                                title = str(tmpl).format(
                                    mission_id=self.mission_id,
                                    round=getattr(self, "current_round", 1),
                                    agent=agent,
                                    cmd_id=cmd_id,
                                    description=description,
                                )
                                title_esc = title.replace("\\", "\\\\").replace("\"", "\\\"")
                                if reuse_tab and self.terminal_window_id and self.terminal_tab_index:
                                    set_title = (
                                        f"tell application \"Terminal\" to set custom title of tab {self.terminal_tab_index} of window id {self.terminal_window_id} to \"{title_esc}\""
                                    )
                                else:
                                    set_title = "tell application \"Terminal\" to set custom title of selected tab of front window to \"" + title_esc + "\""
                                subprocess.run(["osascript", "-e", set_title], check=False, capture_output=True, text=True)
                        except Exception:
                            pass
                    except Exception as e:
                        stdout = ""
                        stderr = f"failed to launch Terminal: {e}"
                        returncode = -1
                    else:
                        # Poll for completion (prefer terminal-specific timeout), optionally mirror live output
                        deadline = time.time() + float(timeout_secs or getattr(self.config, "terminal_timeout_secs", self.config.command_timeout_secs))
                        last_pos_out = 0
                        last_pos_err = 0
                        mirror = bool(getattr(self.config, "mirror_terminal_live", True))
                        while time.time() < deadline and not rc_path.exists():
                            try:
                                if mirror and self.logger:
                                    if stdout_path.exists():
                                        data = stdout_path.read_bytes()
                                        if len(data) > last_pos_out:
                                            chunk = data[last_pos_out:]
                                            last_pos_out = len(data)
                                            try:
                                                self.logger.record_event(
                                                    agent,
                                                    "command_live",
                                                    {"command_id": cmd_id, "stream": "stdout", "chunk": chunk.decode("utf-8", errors="ignore")},
                                                )
                                            except Exception:
                                                pass
                                    if stderr_path.exists():
                                        datae = stderr_path.read_bytes()
                                        if len(datae) > last_pos_err:
                                            chunk = datae[last_pos_err:]
                                            last_pos_err = len(datae)
                                            try:
                                                self.logger.record_event(
                                                    agent,
                                                    "command_live",
                                                    {"command_id": cmd_id, "stream": "stderr", "chunk": chunk.decode("utf-8", errors="ignore")},
                                                )
                                            except Exception:
                                                pass
                            except Exception:
                                pass
                            time.sleep(0.5)
                        if rc_path.exists():
                            try:
                                returncode = int(rc_path.read_text(encoding="utf-8").strip() or "0")
                            except Exception:
                                returncode = 0
                            try:
                                stdout = stdout_path.read_text(encoding="utf-8", errors="ignore")
                            except Exception:
                                stdout = ""
                            try:
                                stderr = stderr_path.read_text(encoding="utf-8", errors="ignore")
                            except Exception:
                                stderr = ""
                        else:
                            stdout = (stdout_path.read_text(encoding="utf-8", errors="ignore") if stdout_path.exists() else "")
                            stderr = ((stderr_path.read_text(encoding="utf-8", errors="ignore") if stderr_path.exists() else "") + "\n[timeout waiting for Terminal]")
                            returncode = 124
                else:
                    # Decide if need shell based on content or explicit flag
                    def _should_shell(cmd: str) -> bool:
                        if use_shell is not None:
                            return bool(use_shell)
                        specials = ['|', '&&', '||', '>', '<', '$(', '`']
                        return any(s in cmd for s in specials)

                    # Enforce single-tool command policy (no pipelines/redirections); semicolons allowed (for r2 -c scripts)
                    if getattr(self.config, "enforce_single_tool", True):
                        if any(sym in command for sym in ('|', '&&', '||', '>', '<', '$(', '`')):
                            stdout = ""
                            stderr = "command rejected: multi-tool pipelines/redirections are disallowed; perform filtering in framework"
                            returncode = -2
                            # Record and finalize early
                            self.complete_command(cmd_id, stdout, stderr, returncode)
                            return {
                                "stdout": stdout,
                                "stderr": stderr,
                                "returncode": returncode,
                                "command_id": cmd_id,
                                "artifact_path": None,
                            }

                    run_with_shell = _should_shell(command)
                    if run_with_shell:
                        full_cmd = ["bash", "-lc", command]
                        completed = subprocess.run(
                            full_cmd,
                            input=input_data,
                            capture_output=True,
                            text=True,
                            check=False,
                            cwd=str(cwd) if cwd else None,
                            timeout=timeout_secs or self.config.command_timeout_secs,
                        )
                    else:
                        completed = subprocess.run(
                            shlex.split(command),
                            input=input_data,
                            capture_output=True,
                            text=True,
                            check=False,
                            cwd=str(cwd) if cwd else None,
                            timeout=timeout_secs or self.config.command_timeout_secs,
                        )
                    stdout = completed.stdout
                    stderr = completed.stderr
                    returncode = completed.returncode
            except FileNotFoundError as exc:
                stdout = ""
                stderr = f"command not found: {exc}"
                returncode = -1
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = (exc.stderr or "") + "\n[timeout] command exceeded limit"
                returncode = 124

        # Persist command result into an artifact if requested
        artifact_path = None
        if artifact_name:
            artifact_path = self.create_artifact_path(artifact_name)
            try:
                artifact_path.write_text(stdout or "", encoding="utf-8")
            except Exception:
                # Ignore artifact write failure
                artifact_path = None

        self.complete_command(cmd_id, stdout.strip(), stderr.strip(), returncode)

        return {
            "stdout": (stdout or "").strip(),
            "stderr": (stderr or "").strip(),
            "returncode": returncode,
            "command_id": cmd_id,
            "artifact_path": artifact_path,
        }

    def record_dialogue(
        self,
        agent: str,
        direction: str,
        content: str,
        metadata: Optional[Dict[str, str]] = None,
        dialogue_id: Optional[str] = None,
    ) -> str:
        dialogue_id = dialogue_id or self.next_id("dlg")
        # Persist full content to an artifact and compute hash
        art_path: Optional[Path] = None
        art_hash: Optional[str] = None
        try:
            from hashlib import sha256 as _sha256
            art_path = self.create_artifact_path(f"{dialogue_id}.txt")
            art_path.write_text(str(content), encoding="utf-8")
            h = _sha256()
            with art_path.open('rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            art_hash = h.hexdigest()
        except Exception:
            art_path = None
            art_hash = None
        preview = str(content)[:600]
        entry = {
            "dialogue_id": dialogue_id,
            "agent": agent,
            "direction": direction,
            "content": preview,
            "metadata": metadata or {},
        }
        if art_path:
            entry["artifact_path"] = art_path.as_posix()
        if art_hash:
            entry["artifact_sha256"] = art_hash
        self.dialogue_log.append(entry)
        if self.logger:
            self.logger.record_event(agent, "dialogue", entry)
        return dialogue_id

    def mark_plan_status(self, plan: TaskPlan, decision: str, reviewer: str, notes: str) -> None:
        plan.status = decision
        plan.record_review(reviewer, decision, notes)
        self.plan_reviews.append(
            {
                "plan_id": plan.plan_id,
                "version": plan.version or plan.plan_id,
                "reviewer": reviewer,
                "decision": decision,
                "notes": notes,
            }
        )

    def mark_mission_complete(self, status: str, notes: Optional[str] = None) -> None:
        self.mission_status = status
        if self.logger:
            self.logger.record_event(
                "MissionController",
                "mission_complete",
                {"status": status, "notes": notes or ""},
            )

    def init_environment(self) -> None:
        self.config.ensure_directories()
        self.mission_dir = self.config.mission_outputs_root / self.mission_id
        self.artifacts_dir = self.mission_dir / "artifacts"
        self.logs_dir = self.mission_dir / "logs"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.skillbook = SkillBook(self.config.skillbook_path)
        if self.skillbook:
            self.skillbook.prune(
                retention_days=getattr(self.config, "skillbook_retention_days", 180),
                max_per_category=getattr(self.config, "skillbook_max_entries_per_category", 200),
            )
        # Compute and cache input file sha256 for reproducibility
        try:
            import hashlib as _hashlib
            h = _hashlib.sha256()
            with self.input_path.open('rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self.metadata["input_sha256"] = h.hexdigest()
        except Exception:
            pass
            self.skillbook.save()
        self.validator_commands = list(self.config.validator_commands)

    def persist_logs(self) -> Path:
        if not self.logs_dir:
            raise RuntimeError("CaseContext environment not initialized.")
        output = self.logs_dir / "events.json"
        if self.logger:
            payload = self.logger.export()
            if self.support_requests:
                payload["support_requests"] = list(self.support_requests)
            if self.command_log:
                payload["commands"] = list(self.command_log)
            if self.plan_reviews:
                payload["plan_reviews"] = list(self.plan_reviews)
            if self.dialogue_log:
                payload["dialogues"] = list(self.dialogue_log)
            payload["mission_status"] = self.mission_status
            payload_json = json.dumps(payload, indent=2)
            output.write_text(payload_json, encoding="utf-8")
        return output

    def persist_evidence(self) -> Path:
        if not self.mission_dir:
            raise RuntimeError("CaseContext environment not initialized.")
        output = self.mission_dir / "evidence.json"
        data = [card.to_dict() for card in self.evidence]
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return output

    def add_skill_entry(self, entry: SkillEntry) -> None:
        if not self.skillbook:
            self.skillbook = SkillBook(self.config.skillbook_path)
        self.skillbook.add_or_update(entry)
        self.skillbook.save()

    def suggest_from_skillbook(self, category: str | None = None, role: str | None = None) -> List[SkillEntry]:
        if not self.skillbook:
            self.skillbook = SkillBook(self.config.skillbook_path)
        suggestions: List[SkillEntry] = []
        for entry in self.skillbook.entries:
            if category and entry.category != category:
                continue
            if role and entry.role and entry.role != role:
                continue
            suggestions.append(entry)
        # Sort by usage and recency to prioritize proven tips
        def _score(e: SkillEntry) -> tuple[int, str]:
            return (int(e.uses or 0), e.updated_at or "")
        suggestions.sort(key=_score, reverse=True)
        for e in suggestions:
            self.skillbook.mark_used(e)
        self.skillbook.save()
        return suggestions

    def create_artifact_path(self, filename: str) -> Path:
        if not self.artifacts_dir:
            raise RuntimeError("CaseContext environment not initialized.")
        path = self.artifacts_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    # Platform helpers
    def is_macos(self) -> bool:
        return sys.platform == "darwin"

    def is_linux(self) -> bool:
        return sys.platform.startswith("linux")

    def detect_format(self) -> str:
        """
        Best-effort file format detection by magic bytes.
        Returns one of: ELF, MACHO, PE, ZIP, DOCX, UNKNOWN.
        """
        try:
            with self.input_path.open("rb") as f:
                magic = f.read(8)
        except OSError:
            return "UNKNOWN"
        # ELF: 0x7f 'E''L''F'
        if magic.startswith(b"\x7fELF"):
            return "ELF"
        # Mach-O: 0xFEEDFACE/0xFEEDFACF or byte-swapped counterparts
        if magic.startswith(bytes.fromhex("FEEDFACE")) or magic.startswith(bytes.fromhex("FEEDFACF")):
            return "MACHO"
        if magic.startswith(bytes.fromhex("CEFAEDFE")) or magic.startswith(bytes.fromhex("CFFAEDFE")):
            return "MACHO"
        # ZIP (and likely DOCX which is a zip)
        if magic.startswith(b"PK\x03\x04"):
            # detect docx by extension hint
            return "DOCX" if self.input_path.suffix.lower() == ".docx" else "ZIP"
        # PE: 'MZ'
        if magic.startswith(b"MZ"):
            return "PE"
        return "UNKNOWN"

    def persist_report(
        self,
        retrospective: Dict[str, str],
        validation_report: Dict[str, List[Dict[str, str]]],
    ) -> Path:
        """
        Generate a one-page, conclusion=evidence report with only:
        - Candidate flag
        - Table data + coordinate card
        - Inverse + forward replay log summary
        - All artifacts' hashes
        This makes the report fully reproducible across machines.
        """
        if not self.mission_dir:
            raise RuntimeError("CaseContext environment not initialized.")

        import re as _re
        def _find_flag_card() -> Optional[EvidenceCard]:
            # Prefer validated forward replay / Good! logs, then explicit flag-tag cards
            for e in reversed(self.evidence):
                ttl = (e.title or "").lower()
                summ = (e.summary or "").lower()
                ctx = (e.context or "").lower()
                if (e.tags and ("validated" in e.tags)) or ("forward replay" in ttl and ("good!" in summ or "good!" in ctx)):
                    return e
            for e in reversed(self.evidence):
                if e.tags and ("flag" in e.tags) and ("validated" in e.tags):
                    return e
            for e in reversed(self.evidence):
                if e.tags and ("flag" in e.tags):
                    return e
            return None

        def _find_table_card() -> Optional[EvidenceCard]:
            # Prefer explicit Table coordinates @ ... card
            for e in reversed(self.evidence):
                if isinstance(e.title, str) and e.title.lower().startswith("table coordinates @"):
                    return e
            # fallback: any coordinate card with dwords in context
            for e in reversed(self.evidence):
                if e.tags and ("coordinate" in e.tags):
                    return e
            return None

        def _find_hex_card(vaddr: str | None) -> Optional[EvidenceCard]:
            for e in reversed(self.evidence):
                if isinstance(e.title, str) and e.title.lower().startswith("hex neighborhood @"):
                    if not vaddr:
                        return e
                    if e.metadata and str(e.metadata.get("vaddr","")) == vaddr:
                        return e
            return None

        def _find_rule_card() -> Optional[EvidenceCard]:
            for e in reversed(self.evidence):
                ttl = (e.title or "").lower()
                if ttl.startswith("data-flow slice rule") or ttl.startswith("static-flow rule") or (e.tags and ("rule" in e.tags)):
                    if e.artifact_path:
                        return e
            return None

        # Extract key cards
        flag_card = _find_flag_card()
        table_card = _find_table_card()
        vaddr = str(table_card.metadata.get("vaddr")) if (table_card and table_card.metadata) else None  # type: ignore[assignment]
        hex_card = _find_hex_card(vaddr)
        rule_card = _find_rule_card()
        # Parse candidate flag string from flag_card
        candidate = ""
        log_excerpt = ""
        if flag_card:
            text = (flag_card.context or flag_card.summary or "")
            m = _re.search(r"d3ctf\{[^}\n]{1,120}\}", text, _re.I)
            if m:
                candidate = m.group(0)
            # capture Good! marker and a few lines
            lines = str(text).splitlines()
            tail = lines[-10:] if len(lines) > 10 else lines
            log_excerpt = "\n".join(tail)

        lines: List[str] = []
        lines.append(f"# Conclusion · {self.mission_id}")
        lines.append("")
        # Header + input hash
        if sha := self.metadata.get("input_sha256"):
            lines.append(f"(input sha256={sha})")
        lines.append("")
        # Candidate flag
        lines.append("## Candidate Flag")
        lines.append(candidate or "(not found)")
        lines.append("")
        # Table coordinates
        lines.append("## Table Coordinates")
        if table_card:
            vaddr_txt = (table_card.metadata.get("vaddr") if table_card.metadata else "") or ""
            baddr_txt = (table_card.metadata.get("baddr") if table_card.metadata else "") or ""
            section = (table_card.metadata.get("section") if table_card.metadata else "") or (table_card.section or "")
            off = f"0x{table_card.offset:x}" if table_card.offset is not None else ""
            lines.append(f"- vaddr: {vaddr_txt}")
            lines.append(f"- baddr: {baddr_txt}")
            if off:
                lines.append(f"- paddr/offset: {off}")
            if section:
                lines.append(f"- section: {section}")
            if table_card.artifact_hash and table_card.artifact_path:
                lines.append(f"- table.json: {table_card.artifact_path} (sha256={table_card.artifact_hash})")
        else:
            lines.append("(table coordinates not found)")
        lines.append("")
        # Neighborhood
        lines.append("## Hex Neighborhood")
        if hex_card:
            if hex_card.artifact_hash and hex_card.artifact_path:
                lines.append(f"- {hex_card.title}: {hex_card.artifact_path} (sha256={hex_card.artifact_hash})")
        else:
            lines.append("(hex neighborhood not found)")
        lines.append("")
        # Inverse/Forward Rule Summary
        lines.append("## Rule (inverse/forward)")
        if rule_card and rule_card.artifact_path and rule_card.artifact_hash:
            lines.append(f"- rule.json: {rule_card.artifact_path} (sha256={rule_card.artifact_hash})")
            # try summarize ops
            try:
                import json as _json
                data = _json.loads(rule_card.context or "{}")
                fwd = data.get("forward") or []
                inv = data.get("inverse") or []
                def _fmt(ops):
                    return ", ".join(f"{o.get('op')}({o.get('k',0)})" if isinstance(o, dict) and o.get('op') else str(o) for o in ops[:8])
                if fwd:
                    lines.append(f"- forward: {_fmt(fwd)}")
                if inv:
                    lines.append(f"- inverse: {_fmt(inv)}")
            except Exception:
                pass
        else:
            lines.append("(rule not found)")
        lines.append("")
        # Replay log
        lines.append("## Forward Replay (summary)")
        if flag_card and flag_card.artifact_hash and flag_card.artifact_path:
            lines.append(f"- log: {flag_card.artifact_path} (sha256={flag_card.artifact_hash})")
        if log_excerpt:
            lines.append("")
            lines.append("```")
            lines.append(log_excerpt)
            lines.append("```")
        lines.append("")
        # Artifact hashes (core triad)
        lines.append("## Artifact Hashes (core)")
        core_ids = set()
        for e in (table_card, hex_card, rule_card, flag_card):
            if e and e.artifact_path and e.artifact_hash:
                lines.append(f"- {e.title}: {e.artifact_path} (sha256={e.artifact_hash})")
                core_ids.add(e.id)
        # Appendix: other artifacts
        others = [e for e in self.evidence if e.artifact_path and e.artifact_hash and e.id not in core_ids]
        if others:
            lines.append("")
            lines.append("## Appendix: Other Artifacts")
            for e in others:
                lines.append(f"- {e.title}: {e.artifact_path} (sha256={e.artifact_hash})")

        report_path = self.mission_dir / "report.md"
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path

    def persist_transcript(self) -> Path:
        if not self.mission_dir:
            raise RuntimeError("CaseContext environment not initialized.")
        lines: List[str] = []
        lines.append(f"# Transcript: {self.mission_id}")
        lines.append("")
        if self.dialogue_log:
            lines.append("## Dialogues")
            for d in self.dialogue_log:
                direction = d.get("direction", "")
                agent = d.get("agent", "")
                content = d.get("content", "")
                arrow = "→" if direction == "prompt" else ("←" if direction == "response" else "·")
                lines.append(f"- {agent} {arrow} {direction}:")
                lines.append(textwrap.indent(content, prefix="    "))
            lines.append("")
        if self.command_log:
            lines.append("## Commands")
            for c in self.command_log:
                cmd = c.get("command", "")
                rc = c.get("returncode", "")
                cid = c.get("command_id", "")
                out = (c.get("stdout", "") or "")
                err = (c.get("stderr", "") or "")
                lines.append(f"- {cid} by {c.get('agent','')}: {cmd} [rc={rc}]")
                if out:
                    lines.append(textwrap.indent(out[:4000], prefix="    "))
                if err:
                    lines.append(textwrap.indent("[stderr]\n" + err[:2000], prefix="    "))
            lines.append("")
        if self.evidence:
            lines.append("## Evidence")
            for e in self.evidence:
                ah = f" hash={e.artifact_hash}" if e.artifact_hash else ""
                loc = []
                if e.offset is not None:
                    loc.append(f"offset=0x{e.offset:x}")
                if e.section:
                    loc.append(f"section={e.section}")
                if e.metadata.get("vaddr") if e.metadata else None:
                    loc.append(f"vaddr={e.metadata.get('vaddr')}")
                loc_s = (" [" + ", ".join(loc) + "]") if loc else ""
                lines.append(f"- {e.id} [{e.source_agent}] {e.title}{loc_s}{ah} -> {e.summary[:160]}")
            lines.append("")
        # Agent scores snapshot
        try:
            if self.skillbook:
                lines.append("## Agent Scores")
                board = self.skillbook.format_scoreboard()
                lines.append(board)
                lines.append("")
        except Exception:
            pass
        path = self.mission_dir / "transcript.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        # Extended transcript including conversation and support requests
        extended: List[str] = []
        extended.append(f"# Transcript (Full): {self.mission_id}")
        extended.append("")
        # From→To conversation derived from events
        try:
            if self.logger:
                extended.append("## Conversation")
                for ev in self.logger.events:
                    et = ev.event_type
                    ts = ev.timestamp.isoformat()
                    p = ev.payload or {}
                    def say(frm: str, to: str, text: str) -> None:
                        to_part = f" -> {to}" if to else ""
                        extended.append(f"- [{ts}] {frm}{to_part}: {text}")
                    if et == "dialogue":
                        direction = p.get("direction", "")
                        content = p.get("content", "")
                        if direction == "prompt":
                            say(p.get("agent", ev.agent) or ev.agent, "Model", content)
                        elif direction == "response":
                            say("Model", p.get("agent", ev.agent) or ev.agent, content)
                        else:
                            say(ev.agent, "", content)
                    elif et == "plan_proposed":
                        say("Strategist", "General", f"proposes plan {p.get('plan_id','')} (category={p.get('category','')})")
                    elif et == "plan_reviewed":
                        say("General", "Strategist", f"reviewed plan {p.get('plan_id','')} agree={p.get('agree','')}")
                    elif et == "dispatch_plan":
                        say("General", p.get("executor",""), f"dispatch full plan {p.get('plan_id','')} steps={p.get('steps','')}")
                    elif et == "dispatch_step":
                        say("General", p.get("executor",""), p.get("step",""))
                    elif et == "support_request":
                        say(p.get("from",""), p.get("to",""), p.get("payload",""))
                extended.append("")
        except Exception:
            pass
        full_path = self.mission_dir / "transcript_full.md"
        full_path.write_text("\n".join(extended), encoding="utf-8")
        return path

    @classmethod
    def from_input_path(
        cls,
        input_path: str,
        mission_id: Optional[str] = None,
        config_path: Optional[str] = None,
    ) -> "CaseContext":
        path = Path(input_path).expanduser().resolve()
        config = (
            load_config(Path(config_path).expanduser())
            if config_path
            else load_config()
        )
        return cls._from_path_and_config(path, config, mission_id)

    @classmethod
    def from_config(
        cls,
        input_path: Path,
        config: FrameworkConfig,
        mission_id: Optional[str] = None,
    ) -> "CaseContext":
        path = input_path.expanduser().resolve()
        return cls._from_path_and_config(path, config, mission_id)

    @classmethod
    def _from_path_and_config(
        cls,
        path: Path,
        config: FrameworkConfig,
        mission_id: Optional[str],
    ) -> "CaseContext":
        context = cls(
            mission_id=mission_id or path.stem,
            input_path=path,
            raw_inputs={"primary": path},
            config=config,
        )
        context.init_environment()
        return context

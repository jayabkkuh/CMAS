"""
Configuration utilities for the multi-agent framework.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Mapping, Optional


@dataclass
class FrameworkConfig:
    """
    Runtime configuration for mission orchestration.
    """

    artifact_root: Path = Path("artifacts")
    logs_root: Path = Path("logs")
    # skill file; loader supports migrating from legacy paths
    skillbook_path: Path = Path("knowledge/skill.json")
    dry_run: bool = False
    default_input: Optional[Path] = None
    detective_commands: Mapping[str, str] = field(
        default_factory=lambda: {
            "file": "file {input}",
            "binwalk": "binwalk --summary {input}",
            "strings": "strings -t x -n 8 {input} | head -n 200",
            "r2info": "r2 -2qc 'ij' {input}",
            "rabin2": "rabin2 -I {input}",
            "r2main": "r2 -2qc 'aa; s main; pdf' {input}",
            "rabin2z": "rabin2 -zz {input} | head -n 300",
            "r2agf": "r2 -2qc 'aa; s main; agf' {input}",
            "r2xrefs": "r2 -2qc 'aa; axt sym.imp.memcmp; axt sym.imp.strcmp' {input}",
        }
    )
    mission_outputs_root: Path = Path("missions")
    validator_commands: List[List[str]] = field(default_factory=list)
    # SkillBook lifecycle controls
    skillbook_retention_days: int = 180
    skillbook_max_entries_per_category: int = 200
    adaptive_max_new_steps: int = 5
    # Live console streaming (PyCharm right-click defaults ON)
    live_console: bool = True
    live_events: List[str] = field(
        default_factory=lambda: [
            "round_start",
            "plan_proposed",
            "plan_reviewed",
            "dispatch_start",
            "dispatch_step",
            "step_start",
            "command",
            "evidence",
            "dialogue",
            "execution",
            "stats_update",
            "route_policy_update",
            "round_complete",
            "support_request",
        ]
    )
    live_maxlen: int = 1000
    # Live console formatting options
    live_style: str = "converge"  # one of: 'simple', 'fancy', 'converge'
    live_color: bool = True
    live_lang: str = "zh"  # default zh for local usage
    live_verbosity: str = "normal"  # 'compact' | 'normal' | 'verbose'
    # Dispatch mode: 'stepwise' (default legacy) or 'bulk' (assign whole plan to one executor)
    dispatch_mode: str = "stepwise"
    # macOS Terminal control for executor commands
    macos_terminal_control: bool = True
    macos_terminal_keep_open: bool = True
    macos_terminal_reuse_tab: bool = True
    macos_terminal_title_template: str = "{mission_id} R{round} · {agent}"
    macos_terminal_title_on_round_only: bool = True
    # Use Terminal for all agents' shell commands (not only executors)
    macos_terminal_for_all_agents: bool = True
    # Skill usage
    include_scoreboard_in_planning: bool = True
    include_scoreboard_in_summary: bool = True
    # Event watcher
    watch_events_on_run: bool = True
    watch_events_include: List[str] = field(
        default_factory=lambda: [
            "round_start",
            "plan_proposed",
            "plan_reviewed",
            "dispatch_start",
            "dispatch_plan",
            "dispatch_step",
            "execution",
            "evidence",
            "support_request",
            "round_complete",
        ]
    )
    # Command execution defaults
    command_timeout_secs: int = 120
    # Mirror Terminal live output back to console as streaming events
    mirror_terminal_live: bool = True
    # Longer timeout for commands executed via macOS Terminal (interactive/visual)
    terminal_timeout_secs: int = 600
    # Enforce single-tool commands (no pipelines or shell operators). Filtering/regex in framework code.
    enforce_single_tool: bool = True
    # Convenience defaults for IDE runs (e.g., PyCharm right-click)
    # For converge mode, we do not limit to dialogues; keep full convergence stream
    auto_live_dialogue_only: bool = False
    # Post-run default view when no CLI --json/--show-* is provided
    # One of: 'summary' (default), 'dialogue', 'transcript', 'conversation', 'plan', 'conversation_full', 'json'
    default_post_run_view: str = "summary"
    # Built-in flag patterns for automatic detection/verification
    flag_patterns: List[str] = field(
        default_factory=lambda: [
            r"(?i)flag\{[^}\n]{4,120}\}",
            r"(?i)ctf\{[^}\n]{4,120}\}",
            r"(?i)d3ctf\{[^}\n]{4,120}\}",
            # Strong prior for this challenge: exactly 36 chars inside braces
            r"(?i)d3ctf\{[^}\n]{36}\}",
        ]
    )
    # Tool installation & verification (macOS)
    auto_install_tools: bool = False
    brew_bin: str = "brew"
    brew_install_allowed: bool = False
    tool_install_map: Mapping[str, str] = field(
        default_factory=lambda: {
            "r2": "radare2",
            "radare2": "radare2",
            "rabin2": "radare2",
            "binwalk": "binwalk",
            "qemu": "qemu",
            "qemu-x86_64": "qemu",
            "ghidra": "ghidra",
            # macOS developer tools / LLVM
            "readelf": "binutils",       # provides greadelf/gobjdump on macOS
            "objdump": "llvm",           # prefer llvm toolchain on macOS
            "llvm-objdump": "llvm",
            "llvm-readobj": "llvm",
        }
    )
    tool_install_casks: List[str] = field(default_factory=lambda: ["ghidra"])  # install via --cask
    # Python tools/packages installation (cross-platform)
    auto_install_python_tools: bool = False
    pip_bin: str = "pip3"
    pip_install_allowed: bool = False
    python_bin: str = "python3"
    python_tool_map: Mapping[str, str] = field(
        default_factory=lambda: {
            "pwntools": "pwntools",
            "pycryptodome": "pycryptodome",
            "requests": "requests",
            "volatility": "volatility3",
            "angr": "angr",
        }
    )
    python_import_map: Mapping[str, str] = field(
        default_factory=lambda: {
            "pwntools": "pwn",
            "pycryptodome": "Crypto",
            "requests": "requests",
            "volatility": "volatility3",
            "angr": "angr",
        }
    )
    # Optional symbolic execution support (angr)
    enable_angr: bool = False
    angr_timeout_secs: int = 300
    angr_find_regex: List[str] = field(
        default_factory=lambda: [
            r"d3ctf\{",
            r"flag\{",
            r"ctf\{",
        ]
    )
    # High-level orchestration
    max_rounds: int = 3
    # Validator scoring normalization
    validator_score_method: str = "rank"  # 'rank' | 'zscore'
    validator_score_mean: int = 75
    validator_score_std: int = 12
    # Phase event emission
    emit_phase_events: bool = True
    # Heuristics for Reverse challenges
    reverse_table_scan_aggressive: bool = True
    # Reverse known-path static analysis (CFG + tables + length hints)
    reverse_known_path_analysis: bool = True
    # main -> 0x40189d -> 0x40191e/0x4018e0 (byte transform loop)
    reverse_known_path_addrs: List[str] = field(default_factory=lambda: ["0x40189d", "0x40191e", "0x4018e0"])  # static-first path
    # Focus addresses (data/transform hotspots) to prioritize in analysis
    reverse_focus_addrs: List[str] = field(default_factory=lambda: ["0x40191e", "0x4018e0", "0x4029b0"])  # fcn.004029b0
    # Suppressed/low-value addresses (e.g., runtime support/termination paths)
    reverse_suppress_addrs: List[str] = field(default_factory=lambda: ["0x450590", "0x450f30", "0x451740"])  # avoid non-core branches

    @classmethod
    def from_file(cls, path: Path) -> "FrameworkConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        resolved = {}
        for key, value in data.items():
            if key.endswith("_root") or key.endswith("_path") or key == "default_input":
                resolved[key] = Path(value)
            else:
                resolved[key] = value
        if "validator_commands" in data:
            resolved["validator_commands"] = data["validator_commands"]
        return cls(**resolved)

    def ensure_directories(self) -> None:
        for directory in [
            self.artifact_root,
            self.logs_root,
            self.mission_outputs_root,
            self.skillbook_path.parent,
        ]:
            directory.mkdir(parents=True, exist_ok=True)


def load_config(config_path: Optional[Path] = None) -> FrameworkConfig:
    env_path = os.getenv("CTF_FRAMEWORK_CONFIG")
    if config_path is None and env_path:
        candidate = Path(env_path).expanduser()
        if candidate.exists():
            config_path = candidate

    if config_path is None:
        default_file = Path("config.json").expanduser()
        if default_file.exists():
            config_path = default_file

    if config_path and config_path.exists():
        config = FrameworkConfig.from_file(config_path)
    else:
        config = FrameworkConfig()

    if os.getenv("CTF_FRAMEWORK_DRY_RUN"):
        config.dry_run = os.getenv("CTF_FRAMEWORK_DRY_RUN") not in {"0", "false", "False"}

    if config.default_input is not None:
        config.default_input = config.default_input.expanduser()

    return config

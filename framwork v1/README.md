# Multi-Agent CTF Framework

This repository contains a macOS-optimized, multi-agent Capture-The-Flag (CTF) workflow built on top of Agentscope. It packages all phases of a reversal-focused competition run into a single orchestration layer that can be launched directly from PyCharm or the command line. Every action is echoed through macOS Terminal tabs while artifacts and evidence are persisted for post-run analysis.

## High-Level Overview

- **Mission-oriented workflow** – the entry point (`main.py`) spins up a `MissionController` that drives several specialized agents through reconnaissance, planning, execution, validation, and reporting rounds.
- **Agents as roles** – `agents/` implements Detective, Strategist, General, Installer, Validator, and a fleet of executor agents (Reverse, Pwn, Crypto, Web, Forensics, Misc, SymExec). Each role is backed by a language model specified in `api_config.json`.
- **Strong macOS integration** – the framework prefers macOS-friendly binaries (`ghidraRun`, `qemu-system-x86_64`, `otool`, LLVM toolchain) and executes every shell command inside Terminal via AppleScript, while mirroring the output back into the run log.
- **Artifacts by default** – evidence, transcripts, logs, and generated capability cards are stored under `missions/<mission_id>/` to support replay and auditing.

```
main.py → MissionController → CaseContext
   ├─ DetectiveAgent   (static reconnaissance, skill book updates)
   ├─ StrategistAgent  (plan synthesis from evidence)
   ├─ GeneralAgent     (plan review, capability gating, dispatch)
   ├─ InstallerAgent   (tool installation & capability checks)
   ├─ ExecutorHub      (Reverse/Pwn/Crypto/Forensics/Misc/Web/SymExec)
   └─ ValidatorAgent   (validation, retrospective, report)
```

## Repository Layout

| Path | Description |
| ---- | ----------- |
| `main.py` | CLI entry point; parses arguments, loads config, prints provider summary, kicks off `MissionController`. |
| `config.json` | Default runtime configuration tuned for macOS (live console on, Terminal integration, tool install maps). |
| `api_config.json` | Provider/model mapping consumed by `framework.api`. Update this with your API keys/models. |
| `framework/` | Core infrastructure: configuration loading, mission context, controller, plans, logging, evidence, knowledge base, prompts, and result serialization. |
| `agents/` | Agent implementations and toolkits. Includes cross-role helpers in `base.py` and executor specializations under `agents/executors/`. |
| `missions/` | Mission outputs organized per `mission_id` (artifacts, logs, evidence, transcripts). |
| `knowledge/` | Persistent skill book (`skill.json`) along with domain-specific insights. |
| `scripts/` | Utility scripts (e.g., `watch_events.py` for live JSONL tailing). |
| `artifacts/`, `logs/` | Default roots for raw challenge inputs and top-level logs when not inside a mission folder. |

## Quick Start

1. **Install runtime dependencies**
   - macOS Sonoma or newer with Xcode command-line tools.
   - Python 3.11 (`/opt/homebrew/bin/python3.11`) and corresponding `pip3.11`.
   - Homebrew packages: `radare2`, `binwalk`, `llvm`, `qemu` (for `qemu-system-x86_64`), `ghidra` (cask installs `ghidraRun`).

2. **Configure API providers**
   - Edit `api_config.json` to point each agent role to an LLM provider (OpenAI, Anthropic, etc.). The controller refuses to start without a valid API configuration.

3. **Run from PyCharm or CLI**
   - *PyCharm*: right-click `main.py` → “Run 'main'”. The default `config.json` already enables live console and Terminal mirroring.
   - *CLI examples*:
     ```bash
     python3 main.py --dry-run --live --live-style converge \
       --live-color --live-maxlen 0

     python3 main.py missions/jumpjump/input.bin --mission-id jumpjump_round2

     python3 main.py --show-dialogue  # replay latest transcript dialogues
     ```

4. **Inspect outputs**
   - `missions/<mission_id>/artifacts/` – command outputs, capability cards, installer scripts.
   - `missions/<mission_id>/logs/events.json` – consolidated event log (phases, emissions, tool usage).
   - `missions/<mission_id>/evidence.json` – structured evidence cards (summaries, offsets, attachments).
   - `missions/<mission_id>/transcript.txt` – full dialogue between agents and LLMs.

## Runtime Architecture

### Mission Controller (`framework/controller.py`)

The controller orchestrates up to `max_rounds` (see `config.json`), flowing through phases:

1. **Detective** – Runs static reconnaissance commands listed in `config.detective_commands`. Outputs are summarized into `EvidenceCard`s and optionally derive address mappings.
2. **Strategist** – Consumes evidence and skill book entries to propose a task plan (`framework.plans.TaskPlan`), selecting executors and required tools.
3. **General** – Reviews/adjusts the plan, ensures tool capability gating, normalizes tool lists for macOS (preferring LLVM/otool), and dispatches steps to executors.
4. **Installer** – Checks/install tools and Python packages, produces a capability card (`missions/..._capability_card.json`), and can enforce static-only routes when dynamic tooling is missing.
5. **Executors** – Concrete executor agents (Reverse, Pwn, Crypto, Web, Forensics, Misc, SymExec) execute assigned steps using their toolkits, each supported by prompts in `agents/executors/`.
6. **Validator** – Validates artifacts, produces retrospective summaries, and handles scoreboard updates. Also writes final reports and marks mission status.

Each agent inherits from `BaseAgent`, gaining context binding, logging utilities, and LLM invocation helpers.

### Case Context (`framework/context.py`)

`CaseContext` maintains mission state:

- **Terminal integration** – Commands run via `run_command` launch macOS Terminal scripts (with `osascript`). Outputs are tee’d into `missions/<mission_id>/artifacts/cmd-*.stdout/stderr.txt`.
- **Command registry** – Every command is assigned an ID, recorded in `command_log`, and optionally persisted as artifacts.
- **Evidence management** – Provides `add_evidence`, coordinate normalization using address maps, and artifact attachment helpers.
- **Skill book hook** – Writes back experiences to `knowledge/skill.json` between rounds.
- **Artifact creation** – Standardized naming for capability cards, command scripts, transcripts, and logs.

### Configuration (`framework/config.py`, `config.json`)

`FrameworkConfig` centralizes defaults and macOS adjustments:

- Paths: `artifact_root`, `logs_root`, `mission_outputs_root`, `skillbook_path`.
- Live console: `live_console`, `live_style`, `live_color`, `live_maxlen`, `live_events`.
- macOS Terminal: `macos_terminal_control`, `macos_terminal_for_all_agents`, `macos_terminal_title_template`, `terminal_timeout_secs`.
- Tooling: `detective_commands`, `tool_install_map`, `tool_install_casks`, `auto_install_tools`, `auto_install_python_tools`.
- Dispatch: `dispatch_mode` (`bulk` or `stepwise`), `enforce_single_tool` (disallows `|`/`&&`).
- Capability heuristics: `flag_patterns`, `reverse_*` hints, `max_rounds`.

Override configuration via CLI (`--config`) or environment variable `CTF_FRAMEWORK_CONFIG`.

### API Configuration (`framework/api.py`, `api_config.json`)

- Defines providers, authentication, and per-agent model mapping.
- `MissionController` refuses to run without a valid API config (`load_api_config`).
- Supports fallback defaults per provider and cross-role sharing.

### Logging & Evidence (`framework/logger.py`, `framework/evidence.py`, `framework/result.py`)

- `ValidatorLogger` records phase events, commands, support requests, plan reviews, dialogue snippets, and ending status.
- Evidence cards include tool, command, summary, metadata (offsets, vaddr, section), and optional artifact attachments.
- Final mission output: retrospective summary, validation report, transcripts, and logs persisted by `MissionResult`.

## Agent Responsibilities

### Detective (`agents/detective.py`)
- Executes reconnaissance commands (`file`, `strings`, `rabin2`, `r2`, `binwalk`, etc.) defined in `config.detective_commands`.
- Summarizes command outputs, extracts metadata (address mappings, section info), and populates evidence.
- Uses macOS fallbacks (`otool -l`) when ELF-oriented tools are unavailable.

### Strategist (`agents/strategist.py`)
- Assimilates evidence, prior rounds, and skill book hints to craft a plan.
- Ensures declared tool lists align with macOS availability (prefers `llvm-readobj`, `llvm-objdump`, `otool`, `ghidraRun`).
- Calls Installer when required tooling is missing and records plan rationale.
- May demote SymExec steps if heuristics (e.g., low `dynsym` weight) suggest static analysis is preferable.

### General (`agents/general.py`)
- Reviews plans, applies capability gating, and can rewrite steps to static-first routes when qemu/angr are unavailable.
- Coordinates plan dispatch: either bulk assignment or step-by-step execution via `ExecutorHub`.
- Normalizes tool names (replacing `readelf`/`objdump` with `llvm`/`otool` on macOS).
- Logs support requests when plan steps lack executors or capabilities.

### Installer (`agents/installer.py`)
- Performs health checks for qemu, angr, readelf/greadelf, otool, LLVM objdump/readobj, objdump, radare2/rabin2, and strings.
- Mac-aware tool detection: recognizes `qemu-system-x86_64` and `ghidraRun`.
- Executes Homebrew installs (`tool_install_map`) and pip installs (`python_tool_map`) when `auto_install_tools` / `auto_install_python_tools` are enabled.
- Emits a structured capability card and, if necessary, enforces static-only routes by notifying the General agent.
- Records each check/install attempt as evidence.

### Executors (`agents/executors/`)
- `ReverseExecutorAgent`, `PwnExecutorAgent`, `CryptoExecutorAgent`, `ForensicsExecutorAgent`, `WebExecutorAgent`, `MiscExecutorAgent`, `SymExecExecutorAgent`.
- Each inherits from `ExecutorAgent` (`agents/executors/base.py`) and is provided a toolkit list for plan alignment.
- Prompts instruct the LLM to reason over assigned tools and provide execution steps.

### Validator (`agents/validator.py`)
- Performs validation commands (`framework.config.validator_commands`), checks flags against regex patterns, and aggregates scoreboard metrics.
- Generates retrospective reports summarizing actions, evidence, and next steps.
- Writes experience entries to the skill book for future runs.

## Mission Lifecycle & Outputs

```
missions/<mission_id>/
├─ artifacts/
│  ├─ cmd-XXX.sh/.stdout.txt/.stderr.txt  (Terminal scripts and captured output)
│  ├─ *_capability_card.json             (Installer capability cards)
│  └─ ... other generated artifacts ...
├─ logs/
│  └─ events.json                        (phase events, commands, dialogue summaries)
├─ evidence.json                         (serialized EvidenceCard list)
├─ report.json                           (retrospective & validation report)
├─ transcript.txt                        (full agent dialogue)
└─ metadata (optional mission-level files)
```

- The `CaseContext` ensures directories exist, tracks command IDs, and archives LLM dialogues as text artifacts with SHA256 hashes.
- `scripts/watch_events.py` can tail `events.jsonl` in real time (when enabled via `--watch-events` or config settings).
- Skill book updates (`knowledge/skill.json`) capture new insights with retention and per-category limits.

## Configuration Deep Dive

Key `config.json` sections:

- `detective_commands` – templated commands executed during the Detective phase; `{input}` expands to the challenge artifact path.
- `tool_install_map` & `tool_install_casks` – maps logical tool names to Homebrew formulae/casks. Example: `"radare2": "radare2"`, `"ghidra": "ghidra"`.
- `python_tool_map` / `python_import_map` – maps logical names to pip packages and import symbols (e.g., `"pwntools": "pwn"`).
- `live_*` – toggles live console streaming, style (`simple`, `fancy`, `converge`), verbosity, ANSI color.
- `watch_events_*` – controls whether the framework spawns a Terminal watcher for `events.jsonl`.
- `reverse_*` hints – fine-tunes strategy for bin-reverse style missions (focus addresses, suppress addresses, zero-growth heuristics).

CLI switches in `main.py` provide runtime overrides:

| Flag | Description |
| ---- | ----------- |
| `input` (positional) | Path to primary artifact (file or directory). Falls back to `config.default_input`. |
| `--mission-id` | Override mission identifier used in output paths. |
| `--config` | Load an alternate framework configuration JSON. |
| `--api-config` | Load an alternate API config JSON. |
| `--json` | Emit final report as JSON to stdout. |
| `--dry-run` | Skip side-effecting commands (forces `config.dry_run = True`). |
| `--live`, `--live-dialogue-only`, `--live-conversation-only` | Control console streaming behavior. |
| `--live-maxlen`, `--live-style`, `--live-color` | Live output formatting. |
| `--auto-install-tools`, `--brew-install` | Allow Installer to install tools / install Homebrew itself if missing. |
| `--auto-install-python`, `--pip-install` | Allow Installer to install Python packages via pip. |
| `--show-transcript`, `--show-dialogue`, `--show-conversation`, `--show-conversation-full`, `--show-plan` | Post-run viewers for different data slices. |
| `--watch-events`, `--watch-all-events` | Spawn Terminal watcher for event logs. |

## macOS-Specific Behavior

- Terminal automation: `CaseContext.run_command` writes a shell script under `missions/<mission_id>/artifacts/cmd-XXX.sh` and triggers it via `osascript`. Standard output/error and exit codes are captured to companion files.
- Tool normalization: Strategist and General automatically prefer LLVM (`llvm-objdump`, `llvm-readobj`), `otool`, and `ghidraRun` over GNU counterparts to avoid missing tools on macOS.
- Capability fallback: If `qemu-x86_64` (Linux user-mode) is unavailable, the system degrades to static analysis or uses `qemu-system-x86_64` when suitable.
- Live console language: `config.live_lang` defaults to `zh`, matching local usage.

## Skill Book and Knowledge Integration

- `knowledge/skill.json` stores categorized experience entries (retained for `skillbook_retention_days`).
- Agents can propose new entries; the context prunes and saves the skill book after each round.
- The Strategist references the skill book to bias plan steps, while the Validator may update scoreboard-based experiences.

## Extensibility Guidelines

- **Add a new detective command** – update `config.detective_commands` with a `{input}` template; Detective will automatically execute and log it.
- **Add a new tool** – extend `tool_install_map`, `tool_install_casks`, and optionally adjust `agents/strategist.py` / `agents/installer.py` to recognize the binary.
- **Add a new executor specialization** – implement an agent under `agents/executors/`, register it in `MissionController._default_toolkits`, and update `agents/__init__.py`.
- **Customize prompts** – update `framework/prompts.py` or agent-specific prompt segments to tune LLM behavior.
- **Change live output style** – edit `config.json` (`live_style`, `live_verbosity`, `live_events`) or pass CLI flags.
- **Disable Terminal control** – set `macos_terminal_control` to `false` in the config to run commands inline without AppleScript.

## Troubleshooting Tips

- **Installer hangs on `strings`** – already addressed by running a zero-input check (`strings -n 8 <binary> >/dev/null`).
- **Capability card shows missing tools** – verify Homebrew and pip availability, then rerun with `--auto-install-tools` / `--auto-install-python`. On macOS, ensure `qemu-system-x86_64` and `ghidraRun` are installed.
- **Mission fails due to missing API config** – populate `api_config.json` or pass `--api-config` pointing to a valid file.
- **Live console too verbose** – adjust `live_verbosity` or restrict `live_events` in `config.json`.
- **Terminal tabs not appearing** – confirm `macos_terminal_control` and `macos_terminal_for_all_agents` are true and AppleScript automation is permitted for Terminal.

## Supporting Scripts

- `scripts/watch_events.py` – streams `events.jsonl` with optional filtering (`--include`) and colorized output. The controller can auto-launch this when `watch_events_on_run` is set.
- Additional helper scripts can be added under `scripts/` and referenced in plans or installer routines.

## Conclusion

This project provides a ready-to-run, macOS-first orchestration layer for collaborative CTF problem solving. By combining specialized agents, mac-aware tooling, rigorous evidence capture, and rich logging, it gives teams a reproducible workflow that can be triggered directly from PyCharm or the command line. Customize configuration, extend agents, or refine prompts to tailor the framework to new challenge categories or environments.

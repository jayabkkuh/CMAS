"""
Entry point for the multi-agent CTF framework powered by Agentscope.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from framework import CaseContext, MissionController
from framework.knowledge import SkillBook
from framework.api import load_api_config
from framework.config import load_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multi-agent CTF framework")
    parser.add_argument(
        "input",
        type=Path,
        nargs="?",
        help="Path to the primary challenge artifact (file or directory).",
    )
    parser.add_argument(
        "--mission-id",
        type=str,
        help="Optional override for the mission identifier.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to framework configuration JSON.",
    )
    parser.add_argument(
        "--api-config",
        type=Path,
        help="Path to API configuration JSON (overrides env).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the final report as JSON.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip side-effecting commands (forces config dry_run=true).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Stream live agent events to console during execution.",
    )
    parser.add_argument(
        "--live-dialogue-only",
        action="store_true",
        help="Stream only agent dialogues during execution (implies --live).",
    )
    parser.add_argument(
        "--live-conversation-only",
        action="store_true",
        help="Stream only inter-agent conversation events (plan, review, dispatch, support).",
    )
    parser.add_argument(
        "--live-maxlen",
        type=int,
        default=None,
        help="Max characters to print per live event (0 for unlimited).",
    )
    parser.add_argument(
        "--live-style",
        choices=["simple", "fancy", "converge"],
        help="Formatting style for live console output (try 'converge' to focus on Verified/zero-growth/cutover/triad).",
    )
    parser.add_argument(
        "--live-color",
        action="store_true",
        help="Enable ANSI colors in live console output (with --live).",
    )
    parser.add_argument(
        "--auto-install-tools",
        action="store_true",
        help="Allow Strategist to auto-install missing macOS tools via Homebrew.",
    )
    parser.add_argument(
        "--brew-install",
        action="store_true",
        help="Allow Strategist to install Homebrew itself if missing.",
    )
    parser.add_argument(
        "--auto-install-python",
        action="store_true",
        help="Allow Strategist to auto-install missing Python packages via pip.",
    )
    parser.add_argument(
        "--pip-install",
        action="store_true",
        help="Permit pip installations (with --auto-install-python).",
    )
    parser.add_argument(
        "--show-transcript",
        action="store_true",
        help="Print the saved transcript (agent prompts/responses, plus any command/evidence summaries).",
    )
    parser.add_argument(
        "--show-dialogue",
        action="store_true",
        help="Print only agent-to-agent dialogues (prompts/responses) after the run.",
    )
    parser.add_argument(
        "--show-conversation",
        action="store_true",
        help="Print inter-agent conversation (Strategist→General, General→Executors, support requests).",
    )
    parser.add_argument(
        "--show-conversation-full",
        action="store_true",
        help="Print conversation with from→to mapping plus dialogues (prompts/responses).",
    )
    parser.add_argument(
        "--show-plan",
        action="store_true",
        help="Print the active plan tree (steps, executors, status).",
    )
    parser.add_argument(
        "--watch-events",
        action="store_true",
        help="Open a Terminal tab to watch events.jsonl (non-dialogue by default).",
    )
    parser.add_argument(
        "--watch-all-events",
        action="store_true",
        help="Include dialogues in the events watcher.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(Path(args.config).expanduser()) if args.config else load_config()

    if args.dry_run:
        config.dry_run = True
    if args.live or args.live_dialogue_only or args.live_conversation_only:
        config.live_console = True
    if args.live_maxlen is not None:
        config.live_maxlen = int(args.live_maxlen)
    if args.live_style:
        config.live_style = args.live_style
        config.live_console = True
    if args.live_color:
        config.live_color = True
        config.live_console = True
    # Limit live stream to dialogues only if requested
    if args.live_dialogue_only:
        config.live_events = ["dialogue"]
    if args.live_conversation_only:
        config.live_events = [
            "plan_proposed",
            "plan_reviewed",
            "dispatch_step",
            "dispatch_start",
            "support_request",
        ]
    # If no CLI live flags and config prefers dialogue-only live, enable it
    if not args.live and not args.live_dialogue_only and getattr(config, "auto_live_dialogue_only", False):
        config.live_console = True
        config.live_events = ["dialogue"]
    if args.auto_install_tools:
        config.auto_install_tools = True
    if args.brew_install:
        config.brew_install_allowed = True
    if args.auto_install_python:
        config.auto_install_python_tools = True
    if args.pip_install:
        config.pip_install_allowed = True

    input_path = args.input
    if input_path is None:
        if config.default_input is None:
            raise SystemExit("No input provided and no default_input set in config.json")
        input_path = config.default_input

    context = CaseContext.from_config(
        input_path,
        config,
        mission_id=args.mission_id,
    )
    controller = MissionController(
        api_config_path=Path(args.api_config).expanduser()
        if args.api_config
        else None,
    )
    # Header: problem and provider overview
    try:
        print(f"[Problem] Source: {input_path}")
        api_cfg = load_api_config(Path(args.api_config).expanduser()) if args.api_config else load_api_config()
        if api_cfg:
            roles = []
            for role, spec in api_cfg.agents.items():
                prov = spec.provider or "?"
                model = spec.model or (api_cfg.providers.get(prov).default_model if api_cfg.providers.get(prov) else "")
                roles.append(f"{role}={prov}:{model}" if model else f"{role}={prov}")
            if roles:
                print("[Provider] " + "; ".join(sorted(roles)))
        else:
            print("[Provider] None (no api_config)")
        if getattr(config, "live_console", False):
            style = getattr(config, "live_style", "simple")
            verb = getattr(config, "live_verbosity", "normal")
            print(f"[Console] Realtime messages: ON ({style},{verb})")
    except Exception:
        pass

    # Optionally open events watcher in Terminal
    try:
        if args.watch_events or getattr(config, "watch_events_on_run", False):
            logs_dir = context.logs_dir or (context.config.logs_root / context.mission_id / "logs")
            events_path = (logs_dir / "events.jsonl").as_posix()
            repo_root = Path(__file__).resolve().parent.as_posix()
            py = getattr(config, "python_bin", "python3")
            inc = "" if args.watch_all_events else "--include=" + ",".join(getattr(config, "watch_events_include", []) or [])
            with_dialogue = "--with-dialogue" if args.watch_all_events else ""
            cmd = f"cd '{repo_root}' && {py} -u scripts/watch_events.py --file '{events_path}' {inc} {with_dialogue} --color"
            context.launch_terminal_tab(cmd, title=f"Watcher · {context.mission_id}")
    except Exception:
        pass

    result = controller.run(context)

    payload = {
        "retrospective": result.retrospective,
        "validation_report": result.validation_report,
        "logs_path": str(result.logs_path),
        "evidence_path": str(result.evidence_path),
        "dry_run": result.dry_run,
        "report_path": str(result.report_path),
        "transcript_path": str(result.transcript_path),
    }

    # Optional post-run views
    if args.show_transcript:
        try:
            print(Path(result.transcript_path).read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[error] failed to read transcript: {exc}")
        return

    if args.show_dialogue:
        try:
            import json as _json
            events = _json.loads(Path(result.logs_path).read_text(encoding="utf-8")).get("events", [])
            print("# Agent Dialogues\n")
            for ev in events:
                if ev.get("event_type") != "dialogue":
                    continue
                ts = ev.get("timestamp", "")
                agent = ev.get("agent", "")
                payload = ev.get("payload", {}) or {}
                direction = payload.get("direction", "")
                content = payload.get("content", "")
                arrow = "→" if direction == "prompt" else ("←" if direction == "response" else "·")
                print(f"[{ts}] {agent} {arrow} {direction}")
                print(content)
                print("")
            # Convergence overview
            try:
                last_stats = None
                last_policy = None
                for ev in events:
                    if ev.get("event_type") == "stats_update":
                        last_stats = ev.get("payload", {}) or {}
                    elif ev.get("event_type") == "route_policy_update":
                        last_policy = ev.get("payload", {}) or last_policy
                v = result.validation_report.get("verified", []) if isinstance(result.validation_report, dict) else []
                nf = result.validation_report.get("needs_followup", []) if isinstance(result.validation_report, dict) else []
                rj = result.validation_report.get("rejected", []) if isinstance(result.validation_report, dict) else []
                total = len(v) + len(nf) + len(rj)
                print("# Convergence\n")
                print(f"Verified/All: {len(v)}/{total}")
                if last_stats:
                    zg = last_stats.get("zero_growth", "0")
                    ts = last_stats.get("total_steps", "0")
                    print(f"Zero-growth ratio: {zg}/{ts}")
                    if last_stats.get("tool_missing_ratio"):
                        print(f"Missing tools: {last_stats.get('tool_missing_ratio')}")
                if last_policy:
                    fr = last_policy.get("force_static", "false")
                    pr = last_policy.get("preferred_route", "")
                    rs = last_policy.get("reason", "")
                    print(f"Route: preferred={pr or '(none)'}; force_static={fr}; reason={rs}")
                if v:
                    item = v[-1]
                    print("Latest triad:")
                    print(f"- {item.get('title','')} {('['+item.get('artifact','')+']') if item.get('artifact') else ''}")
            except Exception:
                pass
        except Exception as exc:
            print(f"[error] failed to read dialogues: {exc}")
        return

    if args.show_conversation:
        try:
            import json as _json
            data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
            events = data.get("events", [])
            support = data.get("support_requests", [])
            print("# Inter-Agent Conversation\n")
            # Helper to print a line
            def say(ts, frm, to, text):
                to_part = f" -> {to}" if to else ""
                print(f"[{ts}] {frm}{to_part}: {text}")

            for ev in events:
                et = ev.get("event_type")
                ts = ev.get("timestamp", "")
                agent = ev.get("agent", "")
                payload = ev.get("payload", {}) or {}
                if et == "plan_proposed":
                    if payload.get("steps") or payload.get("hypothesis"):
                        pid = payload.get("plan_id", "")
                        cat = payload.get("category", "")
                        say(ts, "Strategist", "General", f"proposes plan {pid} [{cat}]")
                        hyp = payload.get("hypothesis", "")
                        if hyp:
                            print("Hypothesis:")
                            print(hyp)
                        steps = payload.get("steps", []) or []
                        if steps:
                            print("Steps:")
                            for i, s in enumerate(steps, 1):
                                desc = s.get("description", "")
                                ex = s.get("executor", "")
                                tools = ",".join(s.get("tools", []) or [])
                                val = s.get("validation", "")
                                print(f"{i}. {desc} (executor={ex}; tools={tools}; validation={val})")
                    else:
                        say(ts, "Strategist", "General", f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                elif et == "plan_reviewed":
                    agree = payload.get("agree", "")
                    say(ts, "General", "Strategist", f"reviewed plan {payload.get('plan_id','')} agree={agree}")
                elif et == "plan_snapshot":
                    p = payload
                    pid = p.get("plan_id", "")
                    ver = p.get("version", "")
                    cat = p.get("category", "")
                    status = p.get("status", "")
                    say(ts, "General", "Strategist", f"plan snapshot {pid} (v={ver}) [{cat}] status={status}")
                    hyp = p.get("hypothesis", "")
                    if hyp:
                        print("Hypothesis:")
                        print(hyp)
                    steps = p.get("steps", []) or []
                    if steps:
                        print("Steps:")
                        for i, s in enumerate(steps, 1):
                            desc = s.get("description", "")
                            ex = s.get("executor", "")
                            tools = ",".join(s.get("tools", []) or [])
                            val = s.get("validation", "")
                            print(f"{i}. {desc} (executor={ex}; tools={tools}; validation={val})")
                elif et == "dispatch_plan":
                    say(ts, "General", payload.get("executor",""), f"dispatch full plan {payload.get('plan_id','')} steps={payload.get('steps','')}")
                elif et == "dispatch_step":
                    say(ts, "General", payload.get("executor",""), payload.get("step",""))
                elif et == "dispatch_start":
                    say(ts, "General", "Executors", f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                elif et == "support_request":
                    say(ts, payload.get("from",""), payload.get("to",""), payload.get("payload",""))
                # You can extend with more event types if useful
            # Support requests are explicit from→to
            if support:
                print("")
                print("# Support Requests\n")
                for sr in support:
                    ts = sr.get("timestamp","") or ""
                    say(ts, sr.get("from",""), sr.get("to",""), sr.get("payload",""))
            # Convergence overview
            try:
                last_stats = None
                last_policy = None
                for ev in events:
                    if ev.get("event_type") == "stats_update":
                        last_stats = ev.get("payload", {}) or {}
                    elif ev.get("event_type") == "route_policy_update":
                        last_policy = ev.get("payload", {}) or last_policy
                v = result.validation_report.get("verified", []) if isinstance(result.validation_report, dict) else []
                nf = result.validation_report.get("needs_followup", []) if isinstance(result.validation_report, dict) else []
                rj = result.validation_report.get("rejected", []) if isinstance(result.validation_report, dict) else []
                total = len(v) + len(nf) + len(rj)
                print("")
                print("# Convergence\n")
                print(f"Verified/All: {len(v)}/{total}")
                if last_stats:
                    print(f"Zero-growth ratio: {last_stats.get('zero_growth','0')}/{last_stats.get('total_steps','0')}")
                    if last_stats.get("tool_missing_ratio"):
                        print(f"Missing tools: {last_stats.get('tool_missing_ratio')}")
                if last_policy:
                    print(f"Route: preferred={last_policy.get('preferred_route','') or '(none)'}; force_static={last_policy.get('force_static','false')}; reason={last_policy.get('reason','')}")
                if v:
                    item = v[-1]
                    print("Latest triad:")
                    print(f"- {item.get('title','')} {('['+item.get('artifact','')+']') if item.get('artifact') else ''}")
            except Exception:
                pass
        except Exception as exc:
            print(f"[error] failed to read conversation: {exc}")
        return

    if args.show_conversation_full:
        try:
            import json as _json
            data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
            events = data.get("events", [])
            support = data.get("support_requests", [])
            print("# Conversation (Full)\n")
            def say(ts, frm, to, text):
                to_part = f" -> {to}" if to else ""
                print(f"[{ts}] {frm}{to_part}: {text}")
            for ev in events:
                et = ev.get("event_type")
                ts = ev.get("timestamp", "")
                agent = ev.get("agent", "")
                payload = ev.get("payload", {}) or {}
                if et == "dialogue":
                    direction = payload.get("direction", "")
                    content = payload.get("content", "")
                    if direction == "prompt":
                        say(ts, agent, "Model", content)
                    elif direction == "response":
                        say(ts, "Model", agent, content)
                    else:
                        say(ts, agent, "", content)
                elif et == "plan_proposed":
                    say(ts, "Strategist", "General", f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                elif et == "plan_reviewed":
                    agree = payload.get("agree", "")
                    say(ts, "General", "Strategist", f"reviewed plan {payload.get('plan_id','')} agree={agree}")
                elif et == "dispatch_step":
                    say(ts, "General", payload.get("executor",""), payload.get("step",""))
                elif et == "dispatch_start":
                    say(ts, "General", "Executors", f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                elif et == "support_request":
                    say(ts, payload.get("from",""), payload.get("to",""), payload.get("payload",""))
            if support:
                print("")
                print("# Support Requests\n")
                for sr in support:
                    ts = sr.get("timestamp","") or ""
                    say(ts, sr.get("from",""), sr.get("to",""), sr.get("payload",""))
        except Exception as exc:
            print(f"[error] failed to read full conversation: {exc}")
        return

    if args.show_plan:
        try:
            import json as _json
            data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
            events = data.get("events", [])
            snap = None
            for ev in events:
                if ev.get("event_type") == "plan_snapshot":
                    snap = ev
            # Build execution status map from events
            status_map = {}
            for ev in events:
                if ev.get("event_type") == "execution":
                    p = ev.get("payload", {}) or {}
                    step_desc = p.get("step", "")
                    st = p.get("status", "")
                    if step_desc:
                        status_map[step_desc] = st
            print("# Active Plan\n")
            if snap:
                p = snap.get("payload", {}) or {}
                pid = p.get("plan_id", "")
                ver = p.get("version", "")
                cat = p.get("category", "")
                status = p.get("status", "")
                print(f"Plan {pid} (v={ver}) [{cat}] status={status}")
                hyp = p.get("hypothesis", "")
                if hyp:
                    print("Hypothesis:")
                    print(hyp)
                steps = p.get("steps", []) or []
                if steps:
                    print("\nSteps:")
                for i, s in enumerate(steps, 1):
                    desc = s.get("description", "")
                    ex = s.get("executor", "")
                    st = status_map.get(desc) or s.get("status", "")
                    print(f"{i}. [{st}] {desc} (executor={ex})")
            else:
                # Fallback: derive from dispatch events
                lines = []
                for ev in events:
                    if ev.get("event_type") == "dispatch_step":
                        p = ev.get("payload", {}) or {}
                        desc = p.get("step", "")
                        ex = p.get("executor", "")
                        st = status_map.get(desc, "queued")
                        lines.append((desc, ex, st))
                if lines:
                    print("Derived Steps (from dispatch):")
                    for i, (desc, ex, st) in enumerate(lines, 1):
                        print(f"{i}. [{st}] {desc} (executor={ex})")
                else:
                    print("(no plan information found)")
                # Convergence overview
                try:
                    last_stats = None
                    last_policy = None
                    for ev in events:
                        if ev.get("event_type") == "stats_update":
                            last_stats = ev.get("payload", {}) or {}
                        elif ev.get("event_type") == "route_policy_update":
                            last_policy = ev.get("payload", {}) or last_policy
                    v = result.validation_report.get("verified", []) if isinstance(result.validation_report, dict) else []
                    nf = result.validation_report.get("needs_followup", []) if isinstance(result.validation_report, dict) else []
                    rj = result.validation_report.get("rejected", []) if isinstance(result.validation_report, dict) else []
                    total = len(v) + len(nf) + len(rj)
                    print("")
                    print("Convergence:")
                    print(f"- Verified/All: {len(v)}/{total}")
                    if last_stats:
                        print(f"- Zero-growth: {last_stats.get('zero_growth','0')}/{last_stats.get('total_steps','0')}; Missing: {last_stats.get('tool_missing_ratio','')}")
                    if last_policy:
                        print(f"- Route: preferred={last_policy.get('preferred_route','') or '(none)'}; force_static={last_policy.get('force_static','false')}; reason={last_policy.get('reason','')}")
                    if v:
                        item = v[-1]
                        print(f"- Latest triad: {item.get('title','')} {('['+item.get('artifact','')+']') if item.get('artifact') else ''}")
                except Exception:
                    pass
        except Exception as exc:
            print(f"[error] failed to show plan: {exc}")
        return

    # Config-driven post-run default view when no CLI view flags are set
    if not args.json and not args.show_transcript and not args.show_dialogue and not args.show_conversation and not args.show_conversation_full and not args.show_plan:
        default_view = getattr(config, "default_post_run_view", "summary").lower()
        if default_view == "dialogue":
            try:
                import json as _json
                events = _json.loads(Path(result.logs_path).read_text(encoding="utf-8")).get("events", [])
                print("# Agent Dialogues\n")
                for ev in events:
                    if ev.get("event_type") != "dialogue":
                        continue
                    ts = ev.get("timestamp", "")
                    agent = ev.get("agent", "")
                    payload = ev.get("payload", {}) or {}
                    direction = payload.get("direction", "")
                    content = payload.get("content", "")
                    arrow = "→" if direction == "prompt" else ("←" if direction == "response" else "·")
                    print(f"[{ts}] {agent} {arrow} {direction}")
                    print(content)
                    print("")
            except Exception as exc:
                print(f"[error] failed to read dialogues: {exc}")
            return
        elif default_view == "transcript":
            try:
                print(Path(result.transcript_path).read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"[error] failed to read transcript: {exc}")
            return
        elif default_view == "conversation":
            try:
                import json as _json
                data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
                events = data.get("events", [])
                support = data.get("support_requests", [])
                print("# Inter-Agent Conversation\n")
                def say(ts, frm, to, text):
                    to_part = f" -> {to}" if to else ""
                    print(f"[{ts}] {frm}{to_part}: {text}")
                for ev in events:
                    et = ev.get("event_type")
                    ts = ev.get("timestamp", "")
                    agent = ev.get("agent", "")
                    payload = ev.get("payload", {}) or {}
                    if et == "plan_proposed":
                        if payload.get("steps") or payload.get("hypothesis"):
                            pid = payload.get("plan_id", "")
                            cat = payload.get("category", "")
                            say(ts, "Strategist", "General", f"proposes plan {pid} [{cat}]")
                            hyp = payload.get("hypothesis", "")
                            if hyp:
                                print("Hypothesis:")
                                print(hyp)
                            steps = payload.get("steps", []) or []
                            if steps:
                                print("Steps:")
                                for i, s in enumerate(steps, 1):
                                    desc = s.get("description", "")
                                    ex = s.get("executor", "")
                                    tools = ",".join(s.get("tools", []) or [])
                                    val = s.get("validation", "")
                                    print(f"{i}. {desc} (executor={ex}; tools={tools}; validation={val})")
                        else:
                            say(ts, "Strategist", "General", f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                    elif et == "plan_reviewed":
                        agree = payload.get("agree", "")
                        say(ts, "General", "Strategist", f"reviewed plan {payload.get('plan_id','')} agree={agree}")
                    elif et == "plan_snapshot":
                        p = payload
                        pid = p.get("plan_id", "")
                        ver = p.get("version", "")
                        cat = p.get("category", "")
                        status = p.get("status", "")
                        say(ts, "General", "Strategist", f"plan snapshot {pid} (v={ver}) [{cat}] status={status}")
                        hyp = p.get("hypothesis", "")
                        if hyp:
                            print("Hypothesis:")
                            print(hyp)
                        steps = p.get("steps", []) or []
                        if steps:
                            print("Steps:")
                            for i, s in enumerate(steps, 1):
                                desc = s.get("description", "")
                                ex = s.get("executor", "")
                                tools = ",".join(s.get("tools", []) or [])
                                val = s.get("validation", "")
                                print(f"{i}. {desc} (executor={ex}; tools={tools}; validation={val})")
                    elif et == "dispatch_plan":
                        say(ts, "General", payload.get("executor",""), f"dispatch full plan {payload.get('plan_id','')} steps={payload.get('steps','')}")
                    elif et == "dispatch_step":
                        say(ts, "General", payload.get("executor",""), payload.get("step",""))
                    elif et == "dispatch_start":
                        say(ts, "General", "Executors", f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                    elif et == "support_request":
                        say(ts, payload.get("from",""), payload.get("to",""), payload.get("payload",""))
                if support:
                    print("")
                    print("# Support Requests\n")
                    for sr in support:
                        ts = sr.get("timestamp","") or ""
                        say(ts, sr.get("from",""), sr.get("to",""), sr.get("payload",""))
            except Exception as exc:
                print(f"[error] failed to read conversation: {exc}")
            return
        elif default_view == "conversation_full":
            try:
                import json as _json
                data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
                events = data.get("events", [])
                support = data.get("support_requests", [])
                print("# Conversation (Full)\n")
                def say(ts, frm, to, text):
                    to_part = f" -> {to}" if to else ""
                    print(f"[{ts}] {frm}{to_part}: {text}")
                for ev in events:
                    et = ev.get("event_type")
                    ts = ev.get("timestamp", "")
                    agent = ev.get("agent", "")
                    payload = ev.get("payload", {}) or {}
                    if et == "dialogue":
                        direction = payload.get("direction", "")
                        content = payload.get("content", "")
                        if direction == "prompt":
                            say(ts, agent, "Model", content)
                        elif direction == "response":
                            say(ts, "Model", agent, content)
                        else:
                            say(ts, agent, "", content)
                    elif et == "plan_proposed":
                        say(ts, "Strategist", "General", f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                    elif et == "plan_reviewed":
                        agree = payload.get("agree", "")
                        say(ts, "General", "Strategist", f"reviewed plan {payload.get('plan_id','')} agree={agree}")
                    elif et == "dispatch_step":
                        say(ts, "General", payload.get("executor",""), payload.get("step",""))
                    elif et == "dispatch_start":
                        say(ts, "General", "Executors", f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})")
                    elif et == "support_request":
                        say(ts, payload.get("from",""), payload.get("to",""), payload.get("payload",""))
                if support:
                    print("")
                    print("# Support Requests\n")
                    for sr in support:
                        ts = sr.get("timestamp","") or ""
                        say(ts, sr.get("from",""), sr.get("to",""), sr.get("payload",""))
            except Exception as exc:
                print(f"[error] failed to read full conversation: {exc}")
            return
        elif default_view == "plan":
            try:
                import json as _json
                data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
                events = data.get("events", [])
                snap = None
                for ev in events:
                    if ev.get("event_type") == "plan_snapshot":
                        snap = ev
                status_map = {}
                for ev in events:
                    if ev.get("event_type") == "execution":
                        p = ev.get("payload", {}) or {}
                        step_desc = p.get("step", "")
                        st = p.get("status", "")
                        if step_desc:
                            status_map[step_desc] = st
                print("# Active Plan\n")
                if snap:
                    p = snap.get("payload", {}) or {}
                    pid = p.get("plan_id", "")
                    ver = p.get("version", "")
                    cat = p.get("category", "")
                    status = p.get("status", "")
                    print(f"Plan {pid} (v={ver}) [{cat}] status={status}")
                    hyp = p.get("hypothesis", "")
                    if hyp:
                        print("Hypothesis:")
                        print(hyp)
                    steps = p.get("steps", []) or []
                    if steps:
                        print("\nSteps:")
                    for i, s in enumerate(steps, 1):
                        desc = s.get("description", "")
                        ex = s.get("executor", "")
                        st = status_map.get(desc) or s.get("status", "")
                        print(f"{i}. [{st}] {desc} (executor={ex})")
                # Triad acceptance overview under plan view
                try:
                    ver = result.validation_report.get("verified", []) or []
                    fol = result.validation_report.get("needs_followup", []) or []
                    rej = result.validation_report.get("rejected", []) or []
                    print("\nTriad Acceptance: coordinate + neighborhood + target")
                    print(f"- verified={len(ver)}; needs_followup={len(fol)}; rejected={len(rej)}")
                except Exception:
                    pass
                else:
                    print("(no plan information found)")
            except Exception as exc:
                print(f"[error] failed to read plan: {exc}")
            return
        elif default_view == "json":
            print(json.dumps(payload, indent=2))
            return
        elif default_view == "summary":
            try:
                print(Path(result.report_path).read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"[error] failed to read report: {exc}")
            return

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        summary = result.retrospective.get("summary", "(no summary)")
        mode = "DRY-RUN" if result.dry_run else "LIVE"
        print(f"=== Retrospective Summary ({mode}) ===")
        print(summary)
        # Agent scores (from SkillBook)
        try:
            from framework.config import FrameworkConfig  # noqa: F401
            if getattr(config, "include_scoreboard_in_summary", True):
                sb = SkillBook(config.skillbook_path).format_scoreboard()
                if sb:
                    print("\n=== Agent Scores ===")
                    print(sb)
        except Exception:
            pass
        print("\n=== Validation Overview ===")
        for status, entries in result.validation_report.items():
            if status == "support_requests":
                continue
            print(f"- {status}: {len(entries)} items")
        # Convergence signals
        try:
            import json as _json
            data = _json.loads(Path(result.logs_path).read_text(encoding="utf-8"))
            events = data.get("events", [])
            last_stats = None
            last_policy = None
            for ev in events:
                if ev.get("event_type") == "stats_update":
                    last_stats = ev.get("payload", {}) or {}
                elif ev.get("event_type") == "route_policy_update":
                    last_policy = ev.get("payload", {}) or last_policy
            v = result.validation_report.get("verified", []) if isinstance(result.validation_report, dict) else []
            nf = result.validation_report.get("needs_followup", []) if isinstance(result.validation_report, dict) else []
            rj = result.validation_report.get("rejected", []) if isinstance(result.validation_report, dict) else []
            total = len(v) + len(nf) + len(rj)
            print("\n=== Convergence ===")
            print(f"Verified/All: {len(v)}/{total}")
            if last_stats:
                zg = last_stats.get("zero_growth", "0")
                ts = last_stats.get("total_steps", "0")
                print(f"Zero-growth ratio: {zg}/{ts}")
                if last_stats.get("tool_missing_ratio"):
                    print(f"Missing tools: {last_stats.get('tool_missing_ratio')}")
            if last_policy:
                print(f"Route: preferred={last_policy.get('preferred_route','') or '(none)'}; force_static={last_policy.get('force_static','false')}; reason={last_policy.get('reason','')}")
            if v:
                item = v[-1]
                print("Latest triad:")
                print(f"- {item.get('title','')} {('['+item.get('artifact','')+']') if item.get('artifact') else ''}")
        except Exception:
            pass
        # Triad acceptance details: coordinate + neighborhood + target
        try:
            ver = result.validation_report.get("verified", []) or []
            fol = result.validation_report.get("needs_followup", []) or []
            rej = result.validation_report.get("rejected", []) or []
            print("\n=== Triad Acceptance (coordinate + neighborhood + target) ===")
            print(f"- Verified (triad satisfied): {len(ver)}")
            if ver:
                for item in ver[:5]:
                    title = item.get("title", "")
                    artifact = item.get("artifact", "")
                    print(f"  • {title} {'['+artifact+']' if artifact else ''}")
            print(f"- Needs follow-up (missing component): {len(fol)}")
            if fol:
                for item in fol[:5]:
                    title = item.get("title", "")
                    notes = item.get("notes", "")
                    print(f"  • {title} :: {notes}")
            print(f"- Rejected (no triad evidence): {len(rej)}")
            if rej and not ver:
                print("  • Hint: A step only completes when all three components are present with hashes.")
        except Exception:
            pass
        if support := result.validation_report.get("support_requests"):
            print("\nSupport Requests:")
            for req in support:
                print(
                    f"- {req.get('from')} → {req.get('to')}: {req.get('payload')}"
                )
        print(f"\nLogs saved to: {result.logs_path}")
        print(f"Evidence saved to: {result.evidence_path}")
        print(f"Report saved to: {result.report_path}")
        print(f"Transcript saved to: {result.transcript_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Watch events.jsonl and print formatted updates")
    ap.add_argument("--file", required=True, help="Path to events.jsonl")
    ap.add_argument("--include", default="",
                    help="Comma-separated event types to include; empty=all")
    ap.add_argument("--from-start", action="store_true", help="Read from start instead of tail")
    ap.add_argument("--with-dialogue", action="store_true", help="Include dialogue events as well")
    ap.add_argument("--color", action="store_true", help="ANSI colors")
    return ap.parse_args()


def colorize(s: str, code: str, enable: bool) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if enable else s


def route(ev: dict) -> tuple[str, str, str | None]:
    et = str(ev.get("event_type", ""))
    payload = ev.get("payload") or {}
    agent = str(ev.get("agent", ""))
    to = ""
    line: str | None = None
    if et == "plan_proposed":
        to = "General"; line = f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})"
    elif et == "plan_reviewed":
        to = "Strategist"; line = f"reviewed plan {payload.get('plan_id','')} agree={payload.get('agree','')}"
    elif et == "dispatch_plan":
        to = payload.get("executor","") or "Executor"; line = f"dispatch full plan {payload.get('plan_id','')} steps={payload.get('steps','')}"
    elif et == "dispatch_start":
        to = "Executors"; line = f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})"
    elif et == "dispatch_step":
        to = payload.get("executor",""); line = payload.get("step","")
    elif et == "support_request":
        agent = payload.get("from", agent) or agent; to = payload.get("to", ""); line = payload.get("payload", "")
    elif et == "round_start":
        to = "System"; line = f"round_start round={payload.get('round','')}"
    elif et == "round_complete":
        to = "System"; line = f"round_complete round={payload.get('round','')} status={payload.get('status','')}"
    elif et == "dialogue":
        direction = payload.get("direction", ""); content = payload.get("content", "")
        if direction == "prompt":
            to = "Model"; line = content
        elif direction == "response":
            agent, to = "Model", agent; line = content
        else:
            line = content
    return agent, to, line


def main() -> int:
    args = parse_args()
    path = Path(args.file).expanduser()
    include = set([s.strip() for s in args.include.split(",") if s.strip()])
    buf = ""
    # Wait for file to appear
    while not path.exists():
        time.sleep(0.2)
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        if not args.from-start:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            et = str(ev.get("event_type", ""))
            if include and et not in include:
                if not (et == "dialogue" and args.with_dialogue):
                    continue
            if (not args.with_dialogue) and et == "dialogue":
                continue
            ts = ev.get("timestamp", "")
            frm, to, text = route(ev)
            to_part = (" -> " + to) if to else ""
            head = f"[{ts}] {frm}{to_part}:"
            head_c = colorize(head, "36", args.color)
            print(head_c)
            if text:
                body = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
                print(body)
            print("")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


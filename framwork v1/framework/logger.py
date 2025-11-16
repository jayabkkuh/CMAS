"""
Validator-centric logging utilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence, Set
import json as _json
from pathlib import Path

from .evidence import EvidenceCard


@dataclass
class LogEvent:
    timestamp: datetime
    agent: str
    event_type: str
    payload: Dict[str, str]
    evidence_ids: List[str] = field(default_factory=list)


class ValidatorLogger:
    """
    Lightweight in-memory log aggregator for Validator auditing.
    """

    def __init__(self) -> None:
        self.events: List[LogEvent] = []
        self.evidence_index: Dict[str, EvidenceCard] = {}
        self._listeners: List[Callable[[Dict[str, object]], None]] = []

    def record_event(
        self,
        agent: str,
        event_type: str,
        payload: Optional[Dict[str, str]] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        event = LogEvent(
            timestamp=datetime.utcnow(),
            agent=agent,
            event_type=event_type,
            payload=payload or {},
            evidence_ids=evidence_ids or [],
        )
        self.events.append(event)
        # Notify listeners in real-time
        payload = {
            "timestamp": event.timestamp.isoformat(),
            "agent": event.agent,
            "event_type": event.event_type,
            "payload": dict(event.payload),
            "evidence_ids": list(event.evidence_ids),
        }
        for cb in self._listeners:
            try:
                cb(payload)
            except Exception:
                # Don't let listeners break logging
                pass

    def record_command(self, agent: str, command: str, result: str) -> None:
        self.record_event(
            agent=agent,
            event_type="command",
            payload={"command": command, "result": result},
        )

    def record_evidence(self, card: EvidenceCard) -> None:
        self.evidence_index[card.id] = card
        self.record_event(
            agent=card.source_agent,
            event_type="evidence",
            payload={
                "title": card.title,
                "summary": card.summary,
                "offset": str(card.offset) if card.offset is not None else "",
                "section": card.section or "",
                "artifact": str(card.artifact_path) if card.artifact_path else "",
                "artifact_sha256": str(card.artifact_hash or ""),
                "plan_step_id": card.plan_step_id or "",
                "tags": ",".join(card.tags or []),
                "vaddr": str((card.metadata or {}).get("vaddr", "")) if card.metadata else "",
                "mapping_card_id": str((card.metadata or {}).get("mapping_card_id", "")) if card.metadata else "",
            },
            evidence_ids=[card.id],
        )

    def record_execution(self, entry: Dict[str, str]) -> None:
        agent = entry.get("agent", "executor")
        self.record_event(agent=agent, event_type="execution", payload=entry)

    def export(self) -> Dict[str, object]:
        return {
            "events": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "agent": event.agent,
                    "event_type": event.event_type,
                    "payload": dict(event.payload),
                    "evidence_ids": list(event.evidence_ids),
                }
                for event in self.events
            ],
            "evidence": {
                evidence_id: card.to_dict()
                for evidence_id, card in self.evidence_index.items()
            },
        }

    # Live listeners
    def add_listener(self, fn: Callable[[Dict[str, object]], None]) -> None:
        self._listeners.append(fn)


class ConsoleSink:
    """
    Console sink for live event streaming with optional fancy formatting.
    """

    def __init__(
        self,
        include: Optional[Sequence[str]] = None,
        maxlen: int = 1000,
        *,
        style: str = "simple",
        color: bool = False,
        lang: str = "en",
        verbosity: str = "normal",
    ) -> None:
        self.include: Optional[Set[str]] = set(include) if include else None
        self.maxlen = maxlen
        self.style = style
        self.color = color
        self.lang = (lang or "en").lower()
        self.verbosity = (verbosity or "normal").lower()
        # Convergence panel state
        self._triads: Dict[str, Dict[str, Dict[str, str]]] = {}
        self._stats: Dict[str, str] = {}
        self._route: Dict[str, str] = {}

    def on_event(self, event: Dict[str, object]) -> None:  # pragma: no cover - console I/O
        etype = str(event.get("event_type", ""))
        if self.include is not None and etype not in self.include:
            return
        agent = str(event.get("agent", ""))
        ts = str(event.get("timestamp", ""))
        payload = event.get("payload") or {}
        frm, to, conv = self._conversation_route(etype, agent, payload)
        # Converge style: focus on convergence signals and triad summary; ignore dialogues
        if self.style == "converge":
            if etype == "dialogue":
                return
            try:
                if etype == "stats_update" and isinstance(payload, dict):
                    self._stats.update({
                        "triad_verified": str(payload.get("triad_verified", "")),
                        "total_steps": str(payload.get("total_steps", "")),
                        "zero_growth": str(payload.get("zero_growth", payload.get("no_growth_streak", ""))),
                        "no_growth_streak": str(payload.get("no_growth_streak", "")),
                    })
                    self._print_converge(ts)
                    return
                if etype == "route_policy_update" and isinstance(payload, dict):
                    self._route.update({
                        "force_static": str(payload.get("force_static", "")),
                        "preferred_route": str(payload.get("preferred_route", "")),
                        "reason": str(payload.get("reason", "")),
                    })
                    self._print_converge(ts)
                    return
                if etype == "evidence" and isinstance(payload, dict):
                    step_id = str(payload.get("plan_step_id", ""))
                    if step_id:
                        tags = set((str(payload.get("tags", "")) or "").split(","))
                        title = str(payload.get("title", ""))
                        sha = str(payload.get("artifact_sha256", ""))
                        sec = str(payload.get("section", ""))
                        vaddr = str(payload.get("vaddr", ""))
                        entry = self._triads.setdefault(step_id, {})
                        low = title.lower()
                        if ("coordinate" in tags) or ("table coordinates" in low) or ("address mapping" in low):
                            entry["coord"] = {"title": title, "section": sec, "vaddr": vaddr, "sha": sha}
                        if ("hex" in tags) or ("neighborhood" in tags) or ("hex neighborhood" in low):
                            entry["neigh"] = {"title": title, "sha": sha}
                        if ("validated" in tags) or ("flag" in tags) or ("forward replay" in low) or ("good!" in (str(payload.get("summary","")) or "").lower()):
                            entry["target"] = {"title": title, "sha": sha}
                        self._print_converge(ts, step_id)
                        return
            except Exception:
                pass
            # default: suppress other noise in converge view
            return
        # Color policy: emphasize convergence/route signals; keep dialogues plain
        def _col(s: str, code: str) -> str:
            return f"\x1b[{code}m{s}\x1b[0m"
        def _event_color() -> str | None:
            if not self.color:
                return None
            try:
                if etype == "route_policy_update":
                    # Red if force_static, magenta otherwise
                    fs = str((payload or {}).get("force_static", "")).lower() in {"true", "1", "yes"}
                    return "31" if fs else "35"  # red / magenta
                if etype == "stats_update":
                    return "33"  # yellow
                if etype == "execution":
                    st = str((payload or {}).get("status", ""))
                    if st == "completed":
                        return "32"  # green
                    if st in {"blocked_missing_capability", "skipped_duplicate", "blocked_missing_tool"}:
                        return "31"  # red
                    return "36"  # cyan default
                if etype == "evidence":
                    title = str((payload or {}).get("title", "")).lower()
                    if any(k in title for k in ("flag", "validated")):
                        return "32"  # green
                    if any(k in title for k in ("rule", "rip-relative", "hex neighborhood")):
                        return "36"  # cyan
                    return None
                if etype == "dialogue":
                    return None
            except Exception:
                return None
            return None
        ev_color = _event_color()
        if self.style == "fancy":
            if self.verbosity == "verbose":
                # Always print full structured payload when available
                body = self._format_long(etype, payload)
                actor = f"{frm} -> {to}" if to else frm
                header = self._format_header(ts, actor, etype)
                if ev_color:
                    header = _col(header, ev_color)
                print(f"{header}\n{self._indent(body)}\n")
            elif self.verbosity == "compact":
                body = conv or self._format_short(etype, payload)
                actor = f"{frm} -> {to}" if to else frm
                header = self._format_header(ts, actor, etype)
                if ev_color:
                    header = _col(header, ev_color)
                print(f"{header}\n  {self._clip(body)}\n")
            else:
                if conv:
                    body = conv
                else:
                    body = self._format_long(etype, payload)
                actor = f"{frm} -> {to}" if to else frm
                header = self._format_header(ts, actor, etype)
                if ev_color:
                    header = _col(header, ev_color)
                print(f"{header}\n{self._indent(body)}\n")
        else:
            msg = self._format_short(etype, payload)
            if to:
                line = f"[{ts}] {frm} -> {to} {etype}: {msg}"
            else:
                line = f"[{ts}] {frm} {etype}: {msg}"
            if ev_color:
                line = _col(line, ev_color)
            print(line)

    def _print_converge(self, ts: str, step_id: Optional[str] = None) -> None:  # pragma: no cover - console I/O
        try:
            tv = self._stats.get("triad_verified", "0")
            tot = self._stats.get("total_steps", "0")
            zg = self._stats.get("zero_growth", self._stats.get("no_growth_streak", "0"))
            fs = self._route.get("force_static", "false")
            reason = self._route.get("reason", "")
            head = f"[Converge] V/A={tv}/{tot} zero_growth={zg} force_static={fs} reason={reason}"
            if self.color:
                head = f"\x1b[36m{head}\x1b[0m"
            print(f"{head}")
            # Latest triad snapshot (per-step)
            sid = step_id
            if not sid and self._triads:
                # pick the most recent step_id heuristically
                sid = next(reversed(self._triads.keys()))
            if sid and sid in self._triads:
                tri = self._triads[sid]
                def fmt(h: Dict[str, str]) -> str:
                    t = h.get("title", "")
                    sha = h.get("sha", "")
                    v = h.get("vaddr", "")
                    sec = h.get("section", "")
                    extra = f" {sec} {v}" if (sec or v) else ""
                    return f"{t}{extra} [{sha[:10]}]" if sha else f"{t}{extra}"
                coord = fmt(tri.get("coord", {})) if tri.get("coord") else "(coord: n/a)"
                neigh = fmt(tri.get("neigh", {})) if tri.get("neigh") else "(neigh: n/a)"
                targ = fmt(tri.get("target", {})) if tri.get("target") else "(target: n/a)"
                print(f"  triad: {coord} | {neigh} | {targ}")
        except Exception:
            pass

    def _conversation_route(self, etype: str, agent: str, payload: object) -> tuple[str, str, str | None]:
        to = ""
        line: str | None = None
        if not isinstance(payload, dict):
            return agent, to, None
        if etype == "plan_proposed":
            to = "General"
            # When detailed payload is present, prefer full JSON body in fancy view
            if isinstance(payload, dict) and (payload.get("steps") or payload.get("hypothesis")):
                line = None
            else:
                line = f"proposes plan {payload.get('plan_id','')} (category={payload.get('category','')})"
        elif etype == "plan_reviewed":
            to = "Strategist"
            agree = payload.get("agree", "")
            line = f"reviewed plan {payload.get('plan_id','')} agree={agree}"
        elif etype == "dispatch_step":
            to = payload.get("executor", "")
            line = payload.get("step", "")
        elif etype == "dispatch_start":
            to = "Executors"
            line = f"dispatch plan {payload.get('plan_id','')} (category={payload.get('category','')})"
        elif etype == "dispatch_plan":
            to = payload.get("executor", "") or "Executor"
            line = f"dispatch full plan {payload.get('plan_id','')} steps={payload.get('steps','')} (category={payload.get('category','')})"
        elif etype == "support_request":
            frm = payload.get("from", agent) or agent
            to = payload.get("to", "")
            agent = frm
            line = payload.get("payload", "")
        elif etype == "round_start":
            to = "System"
            if isinstance(payload, dict) and payload.get("round"):
                line = f"round_start round={payload.get('round','')}"
            else:
                line = f"round_start plan={payload.get('plan_id','')}"
        elif etype == "round_complete":
            to = "System"
            if isinstance(payload, dict) and payload.get("round"):
                line = f"round_complete round={payload.get('round','')} status={payload.get('status','')}"
            else:
                line = "round_complete"
        # plan_snapshot contains a full plan view after approval; prefer structured body
        if etype == "plan_snapshot":
            to = "General"
            line = None
        return agent, to, line

    def _format_header(self, ts: str, agent: str, etype: str) -> str:
        label = {
            "en": {
                "prefix": "\n\u2500\u2500",
            },
            "zh": {
                "prefix": "\n\u2500\u2500",
            },
        }.get(self.lang, {"prefix": "\n\u2500\u2500"})
        title = f"{etype}"
        bar = label["prefix"]
        line = f"{bar} {title} \u2500" + "\u2500" * 44
        actor = f"{agent}"
        if self.color:
            line = f"\x1b[36m{line}\x1b[0m"
            actor = f"\x1b[33m{actor}\x1b[0m"
        return f"{line}\n{actor}"

    def _format_short(self, etype: str, payload: object) -> str:
        if not isinstance(payload, dict):
            return self._clip(self._stringify(payload))
        if etype == "command":
            cmd = payload.get("command", "")
            res = payload.get("result", "")
            return f"{self._clip(cmd)} => {self._clip(res)}"
        if etype == "evidence":
            title = payload.get("title", "")
            section = payload.get("section", "")
            return self._clip(f"{title} {section}")
        if etype == "dialogue":
            direction = payload.get("direction", "")
            content = payload.get("content", "")
            arrow = "→" if direction == "prompt" else ("←" if direction == "response" else "·")
            return self._clip(f"{arrow} {direction}: {content}")
        if etype in {"dispatch_step", "step_start"}:
            step = payload.get("step", "")
            ex = payload.get("executor", "")
            return self._clip(f"{step} -> {ex}")
        if etype == "support_request":
            frm = payload.get("from", "")
            to = payload.get("to", "")
            text = payload.get("payload", "")
            return self._clip(f"{frm}->{to} {text}")
        if etype == "execution":
            step = payload.get("step", "")
            status = payload.get("status", "")
            return self._clip(f"{step} [{status}]")
        if etype == "command_live":
            stream = payload.get("stream", "")
            chunk = payload.get("chunk", "")
            return self._clip(f"[{stream}] {chunk}")
        if etype == "stats_update":
            # Present core ratios in a compact line; verbose mode prints full JSON
            v = payload
            try:
                voa = v.get("verified_over_all", "")
                ftr = v.get("first_try_rate", "")
                z = v.get("zero_growth", "0")
                miss = v.get("tool_missing_ratio", "0/0")
                return self._clip(f"V/A={voa} first_try={ftr} zero_growth={z} missing={miss}")
            except Exception:
                return self._clip(str(payload))
        # default: join key details
        return self._clip(" ".join(f"{k}={v}" for k, v in payload.items()))

    def _format_long(self, etype: str, payload: object) -> str:
        # Turn payload into a readable, de-noised, clipped block
        if isinstance(payload, dict):
            if etype == "dialogue":
                direction = payload.get("direction", "")
                content = payload.get("content", "")
                text = f"{direction}:\n{self._stringify(content)}"
                return self._clip_block(text)
            if etype == "command":
                cmd = payload.get("command", "")
                res = payload.get("result", "")
                text = f"$ {cmd}\n=> {self._stringify(res)}"
                return self._clip_block(text)
            if etype == "support_request":
                frm = payload.get("from", "")
                to = payload.get("to", "")
                text = payload.get("payload", "")
                body = self._stringify(text)
                return self._clip_block(f"{frm} -> {to}\n{body}")
            if etype == "evidence":
                title = payload.get("title", "")
                summary = payload.get("summary", "")
                section = payload.get("section", "")
                return self._clip_block(f"{title} {section}\n{self._stringify(summary)}")
            # default: pretty JSON if dict-like
            try:
                return self._clip_block(self._pretty_json(payload))
            except Exception:
                return self._clip_block(self._stringify(payload))
        # Non-dict payloads
        return self._clip_block(self._stringify(payload))

    def _pretty_json(self, obj: object) -> str:
        import json as _json
        return _json.dumps(obj, ensure_ascii=False, indent=2)

    def _sanitize_text_layers(self, s: str) -> str:
        # Collapse nested quoting/escaping and try JSON layers if any
        cur: object = s
        for _ in range(3):
            if not isinstance(cur, str):
                break
            st = cur.strip()
            # Try unquote JSON string
            if len(st) >= 2 and ((st[0] == '"' and st[-1] == '"') or (st[0] == "'" and st[-1] == "'")):
                try:
                    import json as _json
                    cur = _json.loads(st)
                    continue
                except Exception:
                    pass
            # Try parse as JSON object/array substring
            try:
                import json as _json
                start = st.find('{'); end = st.rfind('}')
                cand = st if start == -1 or end == -1 or end <= start else st[start:end+1]
                cur = _json.loads(cand)
                continue
            except Exception:
                pass
            # Lenient: squash over-escaping then retry
            if ("\\\\" in st) or ("\\u" in st) or (st.count('\\') >= 2):
                try:
                    squashed = st.replace('\\\"','\"').replace('\\\\','\\')
                    import json as _json
                    start = squashed.find('{'); end = squashed.rfind('}')
                    cand2 = squashed if start == -1 or end == -1 or end <= start else squashed[start:end+1]
                    cur = _json.loads(cand2)
                    continue
                except Exception:
                    pass
            break
        # Render back to string
        if isinstance(cur, (dict, list)):
            try:
                return self._pretty_json(cur)
            except Exception:
                return str(cur)
        return str(cur)

    def _repair_mojibake(self, s: str) -> str:
        try:
            if not isinstance(s, str) or not s:
                return s
            suspect = any(ch in s for ch in ("Ã", "Â", "å", "æ", "ç", "è", "é"))
            if not suspect:
                return s
            repaired = s.encode('latin-1', errors='ignore').decode('utf-8', errors='ignore')
            def _ratio(x: str) -> float:
                return sum(1 for ch in x if ord(ch) > 127) / max(1, len(x))
            return repaired if _ratio(repaired) > _ratio(s) else s
        except Exception:
            return s

    def _stringify(self, obj: object) -> str:
        if isinstance(obj, str):
            txt = self._sanitize_text_layers(obj)
            txt = self._repair_mojibake(txt)
            # Compress excessive backslashes for readability
            if '\\' in txt and txt.count('\\') > 200:
                import re as _re
                def _compress(m):
                    n = len(m.group(0))
                    return '\\\\...\\\\' + f' [x{n} backslashes] '
                txt = _re.sub(r'\\{8,}', _compress, txt)
            return txt
        try:
            return self._pretty_json(obj)
        except Exception:
            return str(obj)

    def _clip(self, s: object) -> str:
        n = self.maxlen
        text = str(s)
        if n is None or n <= 0:
            return text
        return text if len(text) <= n else text[: n - 3] + "..."

    def _clip_block(self, s: str) -> str:
        n = self.maxlen
        if n is None or n <= 0:
            return s
        return s if len(s) <= n else s[: n - 12] + "\n... [truncated]"

    def _indent(self, s: str, prefix: str = "  ") -> str:
        return "\n".join(prefix + line for line in (s or "").splitlines())


class FileSink:
    """
    Append events to a JSONL file for real-time consumption by external tools.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def on_event(self, event: Dict[str, object]) -> None:  # pragma: no cover - file I/O
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(_json.dumps(event, ensure_ascii=False))
                f.write("\n")
        except Exception:
            # Swallow file errors to avoid affecting run
            pass

"""
Skill book utilities for capturing mission learnings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from textwrap import shorten
from typing import Dict, List, Optional


@dataclass
class SkillEntry:
    category: str
    pattern: str
    takeaway: str
    tools: List[str] = field(default_factory=list)
    role: str = ""
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    uses: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "category": self.category,
            "pattern": self.pattern,
            "takeaway": self.takeaway,
            "tools": self.tools,
            "role": self.role,
            "updated_at": self.updated_at,
            "uses": self.uses,
        }


class SkillBook:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: List[SkillEntry] = []
        # scores[role][category] = {ema: float, count: int, last_score: int, updated_at: iso}
        self.scores: Dict[str, Dict[str, Dict[str, object]]] = {}
        # tool_stats[role][tool] = {success: int, fail: int, last_used: iso}
        self.tool_stats: Dict[str, Dict[str, Dict[str, object]]] = {}
        self._load()

    _ANSI_RE = re.compile(r"\x1B\[[0-9;?]*[ -/]*[@-~]")
    _FLAG_RE = re.compile(r"(?i)(?:flag|ctf)\{")

    def _load(self) -> None:
        # Migrate from legacy paths if needed
        sources = [self.path]
        legacy = [
            Path("knowledge/skillbook.json"),
            Path("skillbook.json"),
        ]
        for lp in legacy:
            if lp.exists() and not self.path.exists():
                sources = [lp]
                break
        for src in sources:
            if not src.exists():
                continue
            try:
                raw = json.loads(src.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    # legacy layout: entries only
                    for item in raw:
                        entry = SkillEntry(
                            category=item.get("category", "Misc"),
                            pattern=item.get("pattern", ""),
                            takeaway=item.get("takeaway", ""),
                            tools=item.get("tools", []),
                            role=item.get("role", ""),
                            updated_at=item.get("updated_at") or datetime.utcnow().isoformat(),
                            uses=int(item.get("uses", 0)),
                        )
                        self.add_or_update(entry)
                elif isinstance(raw, dict):
                    for item in raw.get("entries", []) or []:
                        entry = SkillEntry(
                            category=item.get("category", "Misc"),
                            pattern=item.get("pattern", ""),
                            takeaway=item.get("takeaway", ""),
                            tools=item.get("tools", []),
                            role=item.get("role", ""),
                            updated_at=item.get("updated_at") or datetime.utcnow().isoformat(),
                            uses=int(item.get("uses", 0)),
                        )
                        self.add_or_update(entry)
                    scores = raw.get("scores", {}) or {}
                    if isinstance(scores, dict):
                        self.scores = scores  # trust on load; keys validated on use
                    tstats = raw.get("tool_stats", {}) or {}
                    if isinstance(tstats, dict):
                        self.tool_stats = tstats
                else:
                    # unknown format
                    pass
            except json.JSONDecodeError:
                self.entries = []
        # Ensure dedupe/retention rules and sanitization are applied after load
        cleaned: List[SkillEntry] = []
        for entry in list(self.entries):
            if entry := self._sanitize_entry(entry):
                cleaned.append(entry)
        self.entries = cleaned
        self.prune()

    def _key(self, entry: SkillEntry) -> str:
        norm_pat = " ".join(entry.pattern.lower().split())
        return f"{entry.category}::{entry.role}::{norm_pat}"

    def _sanitize_entry(self, entry: SkillEntry | None) -> Optional[SkillEntry]:
        if entry is None:
            return None
        pattern = self._clean_text(entry.pattern, max_len=160)
        takeaway = self._clean_text(entry.takeaway, max_len=260)
        # Skip entries that collapse to empty or leak potential flags
        if not pattern or not takeaway:
            return None
        if self._FLAG_RE.search(pattern) or self._FLAG_RE.search(takeaway):
            return None
        tools = sorted({t.strip() for t in (entry.tools or []) if t and t.strip()})
        # Limit tool list to avoid noise
        tools = tools[:8]
        entry.pattern = pattern
        entry.takeaway = takeaway
        entry.tools = tools
        return entry

    def _clean_text(self, text: str, *, max_len: int) -> str:
        if not isinstance(text, str):
            return ""
        cleaned = self._ANSI_RE.sub("", text)
        cleaned = cleaned.replace("\r", " ")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if not cleaned:
            return ""
        if len(cleaned) > max_len:
            cleaned = shorten(cleaned, width=max_len, placeholder="…")
        return cleaned

    def add_or_update(self, entry: SkillEntry) -> None:
        entry = self._sanitize_entry(entry)
        if not entry:
            return
        key = self._key(entry)
        now = datetime.utcnow().isoformat()
        for existing in self.entries:
            if self._key(existing) == key:
                # update in place
                if entry.takeaway and entry.takeaway != existing.takeaway:
                    existing.takeaway = entry.takeaway
                # merge tools
                seen = set(existing.tools)
                for t in entry.tools:
                    if t not in seen:
                        existing.tools.append(t)
                        seen.add(t)
                existing.updated_at = now
                return
        entry.updated_at = now
        self.entries.append(entry)

    def mark_used(self, entry: SkillEntry) -> None:
        entry.uses = int(entry.uses or 0) + 1
        entry.updated_at = datetime.utcnow().isoformat()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "entries": [entry.to_dict() for entry in self.entries],
            "scores": self.scores,
            "tool_stats": self.tool_stats,
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def prune(self, retention_days: int = 180, max_per_category: int = 200) -> None:
        # Remove entries older than retention if rarely used
        cutoff = datetime.utcnow() - timedelta(days=max(1, retention_days))
        def parse_dt(s: str) -> datetime:
            try:
                return datetime.fromisoformat(s)
            except Exception:
                return datetime.utcnow()

        # Deduplicate by key, keep most recent
        by_key: Dict[str, SkillEntry] = {}
        for e in self.entries:
            key = self._key(e)
            best = by_key.get(key)
            if not best or parse_dt(e.updated_at) > parse_dt(best.updated_at):
                by_key[key] = e
        pruned = list(by_key.values())

        # Age-based pruning
        kept: List[SkillEntry] = []
        for e in pruned:
            age_ok = parse_dt(e.updated_at) >= cutoff or int(e.uses or 0) > 0
            if age_ok:
                kept.append(e)

        # Cap per category by recency
        by_cat: Dict[str, List[SkillEntry]] = {}
        for e in kept:
            by_cat.setdefault(e.category, []).append(e)
        final: List[SkillEntry] = []
        for cat, items in by_cat.items():
            items.sort(key=lambda x: parse_dt(x.updated_at), reverse=True)
            final.extend(items[: max_per_category])
        self.entries = final

    # ---- Scores API -----------------------------------------------------
    def record_score(self, role: str, category: str, score: int, *, alpha: float = 0.3) -> None:
        role = str(role or "").strip() or "(unknown)"
        category = str(category or "Misc")
        bucket = self.scores.setdefault(role, {}).setdefault(category, {})
        old = float(bucket.get("ema", 1.0))
        try:
            val = float(score) / 100.0 if score is not None else 0.6
        except Exception:
            val = 0.6
        new = (1 - alpha) * old + alpha * val
        bucket.update({
            "ema": round(new, 3),
            "count": int(bucket.get("count", 0)) + 1,
            "last_score": int(score or 0),
            "updated_at": datetime.utcnow().isoformat(),
        })

    def get_role_scores(self, role: str) -> Dict[str, Dict[str, object]]:
        return dict(self.scores.get(role, {}))

    def format_scoreboard(self) -> str:
        if not self.scores:
            return "Agent Scores: (no records yet)"
        lines = ["Agent Scores (EMA, n):"]
        for role in sorted(self.scores.keys()):
            cats = self.scores[role]
            parts = [
                f"{cat}={info.get('ema', 1.0):.3f} (n={int(info.get('count', 0))})"
                for cat, info in sorted(cats.items())
            ]
            if parts:
                lines.append(f"- {role}: " + "; ".join(parts))
        return "\n".join(lines)

    # ---- Tool stats -----------------------------------------------------
    def record_tool_outcome(self, role: str, tool: str, success: bool) -> None:
        role = (role or "").strip() or "(unknown)"
        tool = (tool or "").strip()
        if not tool:
            return
        slot = self.tool_stats.setdefault(role, {}).setdefault(tool, {"success": 0, "fail": 0, "last_used": None})
        key = "success" if success else "fail"
        slot[key] = int(slot.get(key, 0) or 0) + 1
        slot["last_used"] = datetime.utcnow().isoformat()

    def get_tool_preference(self, role: str) -> List[str]:
        stats = self.tool_stats.get(role or "", {}) or {}
        def score(t: str) -> tuple[float, int, str]:
            meta = stats.get(t, {}) or {}
            succ = int(meta.get("success", 0) or 0)
            fail = int(meta.get("fail", 0) or 0)
            total = succ + fail
            rate = (succ / total) if total else 0.0
            return (rate, total, str(meta.get("last_used", "")))
        tools = list(stats.keys())
        tools.sort(key=lambda t: score(t), reverse=True)
        return tools

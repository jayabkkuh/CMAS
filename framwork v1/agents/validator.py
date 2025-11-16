"""
Validator agent owns auditing, verification, and retrospectives.
"""

from __future__ import annotations

from typing import Dict, List, Tuple
import math

from framework.context import CaseContext
from framework.evidence import EvidenceCard

from .base import BaseAgent


class ValidatorAgent(BaseAgent):
    role = "Validator"

    def run(self, context: CaseContext, **_) -> Dict[str, List[Dict[str, str]]]:
        self.bind_context(context)
        self.log("round_start", {"evidence": str(len(context.evidence))})
        report = self._audit_evidence(context)
        # Mission success heuristic: verified any flag evidence
        success = False
        for item in report.get("verified", []):
            tags = (item.get("tags") or "").lower()
            if "flag" in tags:
                success = True
                break
        context.mark_mission_complete("success" if success else "completed")
        context.validation_report = report
        self.log("round_complete", {"verified": str(len(report["verified"]))})
        self.clear_context()
        return report

    def retrospective(self, context: CaseContext) -> Dict[str, str]:
        self.bind_context(context)
        # Build a deterministic summary without network
        events = context.logger.events if context.logger else []
        kinds = {}
        for ev in events:
            kinds[ev.event_type] = kinds.get(ev.event_type, 0) + 1
        lines = [
            f"Validator retrospective for Mission ID: {context.mission_id}",
            "",
            "Event counts:",
        ]
        for k, v in sorted(kinds.items()):
            lines.append(f"- {k}: {v}")
        summary = "\n".join(lines)
        # Agent-level reviews and coaching (offline, deterministic)
        reviews = self._compile_agent_reviews(context)
        for agent, rev in reviews.items():
            evc = int(rev.get("evidence", 0))
            ver = int(rev.get("verified", 0))
            if ver == 0 and evc > 0:
                advice = "Focus on producing verifiable artifacts with coordinates and hashes."
            elif ver > 0:
                advice = "Good verification coverage; keep explicit linkage between commands and evidence."
            else:
                advice = "Ensure each action yields traceable evidence and define acceptance checks up front."
            rev["advice"] = advice

        # Broadcast scoring + advice as inter-agent messages (Validator -> each agent)
        try:
            for agent, rev in reviews.items():
                score = rev.get("score", 0)
                advice = rev.get("advice", "")
                payload = f"Score={score}. {advice}"
                context.add_support_request({"from": self.role, "to": agent, "payload": payload})
        except Exception:
            pass

        # Each agent posts a short lessons-learned note to the team (peer recap)
        try:
            for agent, rev in reviews.items():
                notes = rev.get("notes", "")
                if notes:
                    context.add_support_request({"from": agent, "to": "Team", "payload": f"Lessons learned: {notes}"})
        except Exception:
            pass

        # Peer reviews: each agent reviews others + self-summary (deterministic templates)
        peer_reviews: Dict[str, List[Dict[str, str]]] = {}
        self_summaries: Dict[str, str] = {}
        try:
            agent_names = list(reviews.keys())
            def _peer_note(viewer: str, target: str) -> str:
                meta = reviews.get(target, {})
                evc = int(meta.get("evidence", 0))
                ver = int(meta.get("verified", 0))
                cmd = int(meta.get("commands", 0))
                rate = (ver / evc) if evc else 0.0
                if ver == 0 and evc > 0:
                    hint = "提升证据闭环：补充坐标/邻域/artifact。"
                elif ver > 0 and rate >= 0.5:
                    hint = "验证覆盖较好，继续保持并强化命令与证据的映射。"
                else:
                    hint = "注意每一步设定验证方式，并输出可溯源证据。"
                return (
                    f"对 {target} 的观察：evidence={evc}, verified={ver} (rate={rate:.0%}), commands={cmd}。建议：{hint}"
                )
            def _self_summary(agent: str) -> str:
                meta = reviews.get(agent, {})
                evc = int(meta.get("evidence", 0))
                ver = int(meta.get("verified", 0))
                cmd = int(meta.get("commands", 0))
                tools = ", ".join(meta.get("tools", []) or [])
                if ver > 0:
                    takeaway = "本轮闭环成功，优先复用高产出工具与方法；后续提升复杂场景处理能力。"
                elif evc > 0:
                    takeaway = "已产出证据但闭环不足，后续在每一步前明确定义验证方式与坐标。"
                else:
                    takeaway = "产出偏少，需提高行动密度并确保每一步有可落盘的证据。"
                return (
                    f"自评：evidence={evc}, verified={ver}, commands={cmd}, tools=[{tools}]。经验：{takeaway}"
                )
            for a in agent_names:
                peers: List[Dict[str, str]] = []
                for b in agent_names:
                    if a == b:
                        continue
                    note = _peer_note(a, b)
                    peers.append({"to": b, "note": note})
                    # Also log as support request to surface in conversation
                    try:
                        context.add_support_request({"from": a, "to": b, "payload": f"Peer review: {note}"})
                    except Exception:
                        pass
                peer_reviews[a] = peers
                self_summaries[a] = _self_summary(a)
        except Exception:
            pass

        context.retrospective = {
            "summary": summary,
            "agent_reviews": reviews,
            "peer_reviews": peer_reviews,
            "self_summaries": self_summaries,
        }
        # Mandatory LLM call: produce a concise final write-up
        try:
            counts = ", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))
            prompt = (
                "You are the Validator producing a brief mission retrospective. "
                "Write a short executive summary (<=120 words) highlighting verified artifacts and next steps.\n"
                f"Event counts: {counts}\n"
                "Environment: macOS Terminal (zsh)."
            )
            resp = str(self.call_model(prompt))
            from framework.evidence import EvidenceCard
            card = EvidenceCard(
                id="",
                source_agent=self.role,
                title="Validator LLM summary",
                summary=resp[:400],
                tool="LLM",
                command="validator_summary",
                context=resp,
                tags=["summary", "info"],
                created_by=self.role,
            )
            context.add_evidence(card)
            context.retrospective["summary"] = f"{context.retrospective.get('summary','')}\n[LLM]\n{resp[:800]}"
        except Exception:
            pass
        self.clear_context()
        return context.retrospective

    def _audit_evidence(self, context: CaseContext) -> Dict[str, List[Dict[str, str]]]:
        """
        Enforce triad requirements per plan step:
        1) Coordinate card: paddr/vaddr/section/function present (offset/section/metadata.vaddr)
        2) Neighborhood artifact: hex/disasm context with artifact hash
        3) Target hit: flag-like pattern or reproducible rule/table
        Only when the triad is satisfied will a step be considered verified.
        """
        from pathlib import Path as _P
        import hashlib as _hashlib

        def _ensure_hash(c: EvidenceCard) -> None:
            if c.artifact_path and not c.artifact_hash and _P(c.artifact_path).exists():
                try:
                    h = _hashlib.sha256()
                    with _P(c.artifact_path).open('rb') as f:
                        for chunk in iter(lambda: f.read(8192), b""):
                            h.update(chunk)
                    c.artifact_hash = h.hexdigest()
                except Exception:
                    c.artifact_hash = None

        # Extract mapping information (iron rule: offset<->vaddr mapping card must exist)
        mapping_baddr: Optional[int] = None
        # Prefer runtime mapping from route_tracker
        try:
            amap = context.route_tracker.get("address_map")
            if isinstance(amap, dict):
                b = amap.get("baddr")
                try:
                    mapping_baddr = int(b, 16) if isinstance(b, str) and b.startswith("0x") else int(b)
                except Exception:
                    mapping_baddr = None
        except Exception:
            mapping_baddr = None
        # Fallback: parse mapping card text
        if mapping_baddr is None:
            try:
                for c in context.evidence:
                    if (c.tags and "mapping" in c.tags) or (isinstance(c.title, str) and "mapping" in c.title.lower()):
                        txt = (c.summary or "") + " " + (c.context or "")
                        m = re_compile(r"baddr\s*=\s*0x([0-9a-fA-F]+)")
                        mm = m.search(txt)
                        if mm:
                            mapping_baddr = int(mm.group(1), 16)
                            break
            except Exception:
                mapping_baddr = None

        # Group cards by step id; or by (agent,title) fallback
        groups: Dict[str, List[EvidenceCard]] = {}
        for c in context.evidence:
            _ensure_hash(c)
            gid = c.plan_step_id or f"{c.created_by or c.source_agent}:{c.title}"
            groups.setdefault(gid, []).append(c)

        verified, needs_followup, rejected = [], [], []
        for gid, cards in groups.items():
            # triad checks with mapping iron rule (ignore info/env/capability-only cards)
            def _is_info(c: EvidenceCard) -> bool:
                tg = set(c.tags or [])
                return bool(tg & {"info", "env", "capability"}) or (isinstance(c.title, str) and any(k in c.title.lower() for k in ("llm", "advice", "summary")))
            def _has_coord(c: EvidenceCard) -> bool:
                if _is_info(c):
                    return False
                sec = bool(c.section or (c.metadata and c.metadata.get("section")))
                off = c.offset is not None or (c.metadata and c.metadata.get("offset"))
                v = bool(c.metadata and c.metadata.get("vaddr"))
                return (sec and off) or (sec and v)
            has_coord = any(_has_coord(c) for c in cards)
            # Neighborhood: require artifact with hash; for hex dumps prefer >=64 bytes
            def _hex_bytes_count(text: str) -> int:
                from re import findall as _findall
                # count byte pairs in lines
                return sum(len([p for p in line.split() if len(p)==2 and all(ch in '0123456789abcdefABCDEF' for ch in p)]) for line in (text or '').splitlines())
            has_neigh = False
            for c in cards:
                if _is_info(c):
                    continue
                if not (c.artifact_path and c.artifact_hash):
                    continue
                title = (c.title or "").lower()
                tg = set(c.tags or [])
                if (tg & {"neighborhood", "disasm", "hex"}) or any(k in title for k in ("disassembly", "hex", "neighborhood")):
                    # For hex, enforce >=64 bytes where possible
                    ok = True
                    try:
                        if ("hex" in tg) or ("hex" in title):
                            txt = c.context or ""
                            if txt:
                                ok = _hex_bytes_count(txt) >= 64
                    except Exception:
                        ok = True
                    if ok:
                        has_neigh = True
                        break
            # Target acceptance (final): require forward replay validated/Good! or explicit flag evidence
            has_target = False
            for c in cards:
                # info-only/planning do not qualify as target
                if (c.tags and ("info" in c.tags or "env" in c.tags or "capability" in c.tags)) or (c.tool and str(c.tool).lower() == "planning"):
                    continue
                tg = set(c.tags or [])
                if self._contains_flag(c) or ("validated" in tg) or ("good!" in (c.summary or "").lower()) or ("good!" in (c.context or "").lower()):
                    has_target = True
                    break

            # Strong rule: 8-bit domain semantics and low-byte compare for dword tables
            # Applicable when a rule/replay exists in the group or a table JSON is present.
            eight_bit_ok = True
            low8_ok = True
            try:
                has_rule = any((isinstance(c.title, str) and ("slice rule" in c.title.lower() or "data-flow" in c.title.lower())) or (c.tags and ("rule" in c.tags)) for c in cards)
                has_replay = any((isinstance(c.title, str) and "forward replay" in c.title.lower()) or (c.tags and ("validated" in c.tags)) for c in cards)
                # detect table using dword semantics
                table_is_dword = False
                for c in cards:
                    if _is_info(c):
                        continue
                    ttl = (c.title or "").lower()
                    if any(k in ttl for k in ("table coordinates", "rip-relative table", "jump table")):
                        # parse context JSON if present
                        import json as _json
                        jd = None
                        try:
                            jd = _json.loads(c.context or "{}")
                        except Exception:
                            jd = None
                        stride = None
                        ew = None
                        if isinstance(jd, dict):
                            stride = jd.get("stride") or (4 if (jd.get("dwords") is not None) else None)
                            ew = jd.get("entry_width")
                        if (ew and str(ew).lower() == "dword") or stride == 4:
                            table_is_dword = True
                            break
                # 8-bit domain check on rule JSON
                if has_rule or has_replay:
                    eight_bit_ok = False
                    for c in cards:
                        if _is_info(c):
                            continue
                        if not (c.tags and ("rule" in c.tags)) and not (isinstance(c.title, str) and ("slice rule" in c.title.lower() or "data-flow" in c.title.lower())):
                            continue
                        import json as _json
                        data = None
                        try:
                            data = _json.loads(c.context or "{}")
                        except Exception:
                            data = None
                        # Accept if explicit domain metadata present
                        if c.metadata and str(c.metadata.get("domain","")) == "8bit":
                            eight_bit_ok = True
                            break
                        note = (data or {}).get("note") if isinstance(data, dict) else None
                        if isinstance(note, str) and ("8-bit" in note or "0x100" in note or "modulo" in note.lower()):
                            eight_bit_ok = True
                            break
                        # Validate ops constants within 0..255 and allowed ops
                        def _ops_ok(arr) -> bool:
                            if not isinstance(arr, list):
                                return False
                            allowed = {"add", "sub", "xor", "and", "or", "rol", "ror", "shl", "shr", "movzx"}
                            for op in arr:
                                if not isinstance(op, dict):
                                    return False
                                name = str(op.get("op") or "")
                                if name not in allowed:
                                    return False
                                if "k" in op:
                                    try:
                                        k = int(op.get("k"))
                                    except Exception:
                                        return False
                                    if not (0 <= (k & 0xFF) <= 255):
                                        return False
                            return True
                        if isinstance(data, dict) and (_ops_ok(data.get("forward")) and _ops_ok(data.get("inverse"))):
                            eight_bit_ok = True
                            break
                # Low-8-bit compare check when dword table found
                if table_is_dword and (has_rule or has_replay):
                    low8_ok = False
                    for c in cards:
                        ttl = (c.title or "").lower()
                        if ("forward replay" in ttl) or (c.tags and ("validated" in c.tags)):
                            if c.metadata and str(c.metadata.get("byte_compare","")) == "low8":
                                low8_ok = True
                                break
            except Exception:
                pass

            # mapping iron rule: any addressing must reference mapping card; and vaddr must equal baddr+offset where both given;
            # section name must be present when addressing used
            mapping_ok = True
            addressing_used = any((c.offset is not None) or (c.metadata and (c.metadata.get("vaddr") or c.metadata.get("offset"))) for c in cards)
            mapping_reason: Optional[str] = None
            if addressing_used and mapping_baddr is None:
                mapping_ok = False
                mapping_reason = "mapping"
            # Require section present when addressing used
            if mapping_ok and addressing_used:
                has_section = any(bool(c.section) or (c.metadata and c.metadata.get("section")) for c in cards)
                if not has_section:
                    mapping_ok = False
                    mapping_reason = "missing_section"
            # Validate vaddr vs baddr+offset where available
            if mapping_ok and mapping_baddr is not None:
                for c in cards:
                    off = c.offset
                    v = None
                    if c.metadata and c.metadata.get("vaddr"):
                        vtxt = str(c.metadata.get("vaddr"))
                        try:
                            v = int(vtxt, 16) if vtxt.lower().startswith("0x") else int(vtxt)
                        except Exception:
                            v = None
                    if off is not None and v is not None:
                        if v == off and mapping_baddr != 0:
                            mapping_ok = False
                            mapping_reason = "mapping_mismatch(offset_used_as_vaddr)"
                            break
                        if v != (mapping_baddr + off):
                            mapping_ok = False
                            mapping_reason = "mapping_mismatch(vaddr != baddr+offset)"
                            break

            # Only strict triad with final target (forward replay/flag) qualifies as verified
            if has_coord and has_neigh and has_target and mapping_ok and eight_bit_ok and low8_ok:
                for c in cards:
                    c.mark_verified("Triad satisfied: coordinate + neighborhood + target.")
                    verified.append(self._report_entry(c))
            else:
                missing = []
                if not has_coord:
                    missing.append("coordinate")
                if not has_neigh:
                    missing.append("neighborhood")
                if not has_target:
                    missing.append("target_final_replay")
                if not mapping_ok and mapping_reason:
                    missing.append(mapping_reason)
                if not eight_bit_ok:
                    missing.append("eight_bit_domain")
                if not low8_ok:
                    missing.append("low8_compare_required")
                note = "Missing triad component(s): " + ", ".join(missing)
                for c in cards:
                    c.mark_rejected(note)
                    # Classify as needs_followup if at least one component present; otherwise rejected
                    if has_coord or has_neigh or has_target:
                        needs_followup.append(self._report_entry(c))
                    else:
                        rejected.append(self._report_entry(c))

        return {
            "verified": verified,
            "needs_followup": needs_followup,
            "rejected": rejected,
            "support_requests": list(context.support_requests),
        }

    def _classify_card(self, card: EvidenceCard) -> str:
        has_context = bool(card.context and card.context.strip())
        has_artifact = bool(card.artifact_path and card.artifact_path.exists())
        has_location = card.offset is not None or (
            card.metadata and any(key in card.metadata for key in ("vaddr", "offset", "binwalk_entry"))
        )
        # Auto-flag detection in context or artifact
        if self._contains_flag(card):
            return "verified"
        if has_context and has_artifact and has_location:
            return "verified"
        if has_context and (has_artifact or has_location):
            return "needs_followup"
        return "rejected"

    def _contains_flag(self, card: EvidenceCard) -> bool:
        from re import compile as re_compile, MULTILINE
        from itertools import chain
        patterns = []
        try:
            cfg = self._context.config if hasattr(self, "_context") and self._context else None
            if cfg and getattr(cfg, "flag_patterns", None):
                patterns = [re_compile(p, MULTILINE) for p in cfg.flag_patterns]
        except Exception:
            patterns = []
        if not patterns:
            return False
        haystacks = []
        if card.context:
            haystacks.append(card.context)
        if card.artifact_path and card.artifact_path.exists():
            try:
                data = card.artifact_path.read_text(encoding="utf-8", errors="ignore")
                haystacks.append(data)
            except Exception:
                pass
        for text in haystacks:
            for rx in patterns:
                if rx.search(text or ""):
                    return True
        return False

    def _report_entry(self, card: EvidenceCard) -> Dict[str, str]:
        return {
            "id": card.id,
            "title": card.title,
            "summary": card.summary,
            "verified": str(card.verified),
            "notes": card.verification_notes or "",
            "artifact": str(card.artifact_path) if card.artifact_path else "",
            "offset": str(card.offset) if card.offset is not None else "",
            "tags": ",".join(card.tags) if card.tags else "",
        }

    def _build_recap_prompt(self, context: CaseContext) -> str:
        steps = "\n".join(
            f"- {event.event_type} by {event.agent}"
            for event in (context.logger.events if context.logger else [])
        )
        return (
            "You are the Validator summarizing the entire operation.\n"
            "Highlight successful paths, blockers, and recommended improvements.\n"
            f"Mission ID: {context.mission_id}\n"
            f"Dry run mode: {'yes' if context.config.dry_run else 'no'}\n"
            "Event log summary:\n"
            f"{steps}\n"
            "Provide actionable bullet points."
        )

    def _compile_agent_reviews(self, context: CaseContext) -> Dict[str, Dict[str, object]]:
        reviews: Dict[str, Dict[str, object]] = {}
        events = context.logger.events if context.logger else []

        # Only these agents participate in scoring: Detective, Strategist, General, Validator, and all *ExecutorAgent roles
        def _is_scored_agent(name: str) -> bool:
            base = {"Detective", "Strategist", "General", "Validator"}
            if name in base:
                return True
            # Strictly require concrete executor agent roles
            return name.endswith("ExecutorAgent")

        # init agents from events (filtered)
        for ev in events:
            agent = ev.agent
            if not _is_scored_agent(agent):
                continue
            reviews.setdefault(agent, {"commands": 0, "evidence": 0, "verified": 0, "tools": set(), "score": 0})
            if ev.event_type == "command":
                reviews[agent]["commands"] = int(reviews[agent]["commands"]) + 1
        # evidence stats
        for card in context.evidence:
            agent = card.created_by or card.source_agent
            if not _is_scored_agent(agent):
                continue
            reviews.setdefault(agent, {"commands": 0, "evidence": 0, "verified": 0, "tools": set(), "score": 0})
            reviews[agent]["evidence"] = int(reviews[agent]["evidence"]) + 1
            if card.verified:
                reviews[agent]["verified"] = int(reviews[agent]["verified"]) + 1
            if card.tool:
                tset = reviews[agent]["tools"]
                if isinstance(tset, set):
                    tset.add(card.tool)
        # compute raw score and notes
        raw_scores: List[Tuple[str, float]] = []
        for agent, rev in reviews.items():
            evc = int(rev.get("evidence", 0))
            ver = int(rev.get("verified", 0))
            cmd = int(rev.get("commands", 0))
            rate = (ver / evc) if evc else 0.0
            base = 60.0 * rate + 40.0 * (1.0 if cmd > 0 else 0.0)
            base = max(0.0, min(100.0, base))
            raw_scores.append((agent, base))
            tools = sorted(list(rev.get("tools", [])))
            rev["tools"] = tools
            rev["notes"] = (
                f"Evidence: {evc}, Verified: {ver} ({rate:.0%}). Commands: {cmd}. "
                f"Tools: {', '.join(tools) if tools else 'n/a'}."
            )

        # normalize to approximate normal distribution across agents
        def _rank_normalize(pairs: List[Tuple[str, float]], mean: float, std: float) -> Dict[str, int]:
            n = len(pairs)
            if n == 0:
                return {}
            if n == 1:
                return {pairs[0][0]: int(round(mean))}
            # sort by raw; handle ties with average rank
            sorted_pairs = sorted(pairs, key=lambda x: x[1])
            ranks: Dict[str, float] = {}
            i = 0
            while i < n:
                j = i
                v = sorted_pairs[i][1]
                while j + 1 < n and abs(sorted_pairs[j + 1][1] - v) < 1e-6:
                    j += 1
                # average rank for ties
                avg_rank = (i + 1 + j + 1) / 2.0
                for k in range(i, j + 1):
                    ranks[sorted_pairs[k][0]] = avg_rank
                i = j + 1
            out: Dict[str, int] = {}
            for agent, _ in pairs:
                r = ranks.get(agent, 1.0)
                p = (r - 0.5) / n
                p = min(max(p, 1e-6), 1.0 - 1e-6)
                z = _inv_norm_cdf(p)
                s = mean + std * z
                s = max(0.0, min(100.0, s))
                out[agent] = int(round(s))
            return out

        def _zscore_normalize(pairs: List[Tuple[str, float]], mean: float, std: float) -> Dict[str, int]:
            n = len(pairs)
            if n == 0:
                return {}
            vals = [v for _, v in pairs]
            mu = sum(vals) / n
            var = sum((v - mu) ** 2 for v in vals) / n
            sigma = math.sqrt(var) if var > 0 else 0.0
            out: Dict[str, int] = {}
            for agent, v in pairs:
                if sigma == 0:
                    s = mean
                else:
                    z = (v - mu) / sigma
                    s = mean + std * z
                s = max(0.0, min(100.0, s))
                out[agent] = int(round(s))
            return out

        def _inv_norm_cdf(p: float) -> float:
            # Acklam's approximation for inverse normal CDF
            # https://web.archive.org/web/20150910044729/http://home.online.no/~pjacklam/notes/invnorm/
            a1 = -39.69683028665376
            a2 = 220.9460984245205
            a3 = -275.9285104469687
            a4 = 138.3577518672690
            a5 = -30.66479806614716
            a6 = 2.506628277459239
            b1 = -54.47609879822406
            b2 = 161.5858368580409
            b3 = -155.6989798598866
            b4 = 66.80131188771972
            b5 = -13.28068155288572
            c1 = -0.007784894002430293
            c2 = -0.3223964580411365
            c3 = -2.400758277161838
            c4 = -2.549732539343734
            c5 = 4.374664141464968
            c6 = 2.938163982698783
            d1 = 0.007784695709041462
            d2 = 0.3224671290700398
            d3 = 2.445134137142996
            d4 = 3.754408661907416
            plow = 0.02425
            phigh = 1 - plow
            if p < plow:
                q = math.sqrt(-2 * math.log(p))
                return (((((c1 * q + c2) * q + c3) * q + c4) * q + c5) * q + c6) / (
                    ((((d1 * q + d2) * q + d3) * q + d4) * q + 1)
                )
            if p > phigh:
                q = math.sqrt(-2 * math.log(1 - p))
                return -(((((c1 * q + c2) * q + c3) * q + c4) * q + c5) * q + c6) / (
                    ((((d1 * q + d2) * q + d3) * q + d4) * q + 1)
                )
            q = p - 0.5
            r = q * q
            return (((((a1 * r + a2) * r + a3) * r + a4) * r + a5) * r + a6) * q / (
                (((((b1 * r + b2) * r + b3) * r + b4) * r + b5) * r + 1))

        mean = float(getattr(context.config, "validator_score_mean", 75))
        std = float(getattr(context.config, "validator_score_std", 12))
        method = str(getattr(context.config, "validator_score_method", "rank")).lower()
        if method == "zscore":
            norm = _zscore_normalize(raw_scores, mean, std)
        else:
            norm = _rank_normalize(raw_scores, mean, std)

        for agent, rev in reviews.items():
            rev["score"] = int(norm.get(agent, int(next((s for a, s in raw_scores if a == agent), 60))))
        return reviews

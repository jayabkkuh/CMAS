"""
Evidence data structures used across the multi-agent workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import hashlib


@dataclass
class EvidenceCard:
    """
    Standardized representation of a single piece of evidence.

    Each card captures the provenance of the observation so that the Validator
    can later confirm or reject the claim. Fields are intentionally verbose to
    support downstream analytics and auditing.
    """

    id: str
    source_agent: str
    title: str
    summary: str
    offset: Optional[int] = None
    section: Optional[str] = None
    tool: Optional[str] = None
    command: Optional[str] = None
    artifact_path: Optional[Path] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, str] = field(default_factory=dict)
    context: Optional[str] = None
    verified: bool = False
    verification_notes: Optional[str] = None
    linked_event_id: Optional[str] = None
    command_id: Optional[str] = None
    plan_step_id: Optional[str] = None
    requirement_id: Optional[str] = None
    artifact_hash: Optional[str] = None
    created_by: Optional[str] = None

    def attach_artifact(self, artifact: Path) -> None:
        self.artifact_path = artifact
        # Best-effort compute a content hash for traceability
        try:
            h = hashlib.sha256()
            with artifact.open("rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self.artifact_hash = h.hexdigest()
        except Exception:
            # Non-fatal if hashing fails
            self.artifact_hash = None

    def mark_verified(self, notes: str = "") -> None:
        self.verified = True
        self.verification_notes = notes or None

    def mark_rejected(self, notes: str) -> None:
        self.verified = False
        self.verification_notes = notes

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "source_agent": self.source_agent,
            "title": self.title,
            "summary": self.summary,
            "offset": self.offset,
            "section": self.section,
            "tool": self.tool,
            "command": self.command,
            "artifact_path": str(self.artifact_path) if self.artifact_path else None,
            "tags": list(self.tags),
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
            "context": self.context,
            "verified": self.verified,
            "verification_notes": self.verification_notes,
            "linked_event_id": self.linked_event_id,
            "command_id": self.command_id,
            "plan_step_id": self.plan_step_id,
            "requirement_id": self.requirement_id,
            "artifact_hash": self.artifact_hash,
            "created_by": self.created_by,
        }

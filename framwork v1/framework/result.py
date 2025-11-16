"""
Mission result container.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass
class MissionResult:
    retrospective: Dict[str, str]
    validation_report: Dict[str, List[Dict[str, str]]]
    logs_path: Path
    evidence_path: Path
    dry_run: bool
    report_path: Path
    transcript_path: Path

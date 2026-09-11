from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceMetadata:
    evidence_id: str
    file_name: str
    file_path: str
    image_type: str
    size_bytes: int
    hashes: dict[str, str]
    intake_timestamp_utc: str


@dataclass
class DiskArtifact:
    artifact_type: str
    source_path: str
    timestamp: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryProcess:
    pid: int
    ppid: int
    process_name: str
    path: str = ""
    handles_count: int | None = None
    timestamp: str = field(default_factory=utc_now)


@dataclass
class CorrelatedEvent:
    timestamp: str
    source_module: str
    event_type: str
    description: str
    risk_score: int = 0
    details: dict[str, Any] = field(default_factory=dict)


def to_dict(obj: Any) -> dict[str, Any]:
    return asdict(obj)

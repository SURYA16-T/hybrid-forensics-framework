from __future__ import annotations

from datetime import datetime, timezone
from src.config.data_models import CorrelatedEvent, DiskArtifact, MemoryProcess


def _parse_ts(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


class TimelineBuilder:
    def __init__(self) -> None:
        self.events: list[CorrelatedEvent] = []

    def ingest_disk_artifacts(self, artifacts: list[DiskArtifact]) -> None:
        for artifact in artifacts:
            self.events.append(CorrelatedEvent(
                timestamp=artifact.timestamp,
                source_module="disk",
                event_type=artifact.artifact_type,
                description=f"Disk artifact: {artifact.artifact_type}",
                details={"source_path": artifact.source_path, **artifact.details},
            ))

    def ingest_memory_processes(self, processes: list[MemoryProcess], anchor_timestamp: str | None = None) -> None:
        anchor_timestamp = anchor_timestamp or datetime.now(timezone.utc).isoformat()
        for proc in processes:
            self.events.append(CorrelatedEvent(
                timestamp=proc.timestamp or anchor_timestamp,
                source_module="memory",
                event_type="Process",
                description=f"Memory process: {proc.process_name} (PID {proc.pid})",
                details={"pid": proc.pid, "ppid": proc.ppid, "path": proc.path, "handles_count": proc.handles_count},
            ))

    def ingest_memory_findings(self, findings) -> None:
        for finding in findings:
            self.events.append(CorrelatedEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                source_module="memory",
                event_type="MemoryFinding",
                description=f"{finding.rule} in {finding.process_name} (PID {finding.pid})",
                risk_score=int(finding.risk_score),
                details={
                    "pid": finding.pid,
                    "process_name": finding.process_name,
                    "base_address": finding.base_address,
                    "region_size": finding.region_size,
                    "protection": finding.protection,
                    **finding.details,
                },
            ))

    def build_timeline(self) -> list[CorrelatedEvent]:
        return sorted(self.events, key=lambda e: _parse_ts(e.timestamp))

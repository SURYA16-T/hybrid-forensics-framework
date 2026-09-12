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
            pid = getattr(finding, "pid", 0)
            pname = getattr(finding, "process_name", "unknown")
            rule = getattr(finding, "rule", "UNKNOWN_RULE")
            score = int(getattr(finding, "risk_score", 0))
            details = {"pid": pid, "process_name": pname, "rule": rule}

            if hasattr(finding, "base_address"):
                details["base_address"] = finding.base_address
            if hasattr(finding, "region"):
                details["region"] = finding.region
            if hasattr(finding, "region_size"):
                details["region_size"] = finding.region_size
            if hasattr(finding, "size_bytes"):
                details["size_bytes"] = finding.size_bytes
            if hasattr(finding, "protection"):
                details["protection"] = finding.protection
            if hasattr(finding, "permissions"):
                details["permissions"] = finding.permissions

            inner_details = getattr(finding, "details", {})
            if isinstance(inner_details, dict):
                details.update(inner_details)

            self.events.append(CorrelatedEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                source_module="memory",
                event_type="MemoryFinding",
                description=f"{rule} in {pname} (PID {pid})",
                risk_score=score,
                details=details,
            ))

    def build_timeline(self) -> list[CorrelatedEvent]:
        return sorted(self.events, key=lambda e: _parse_ts(e.timestamp))

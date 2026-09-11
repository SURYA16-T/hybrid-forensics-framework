from __future__ import annotations

from pathlib import Path
from src.config.data_models import EvidenceMetadata, utc_now
from .validator import calculate_hashes


class EvidenceIntake:
    def __init__(self, file_path: str, image_type: str = "generic") -> None:
        self.path = Path(file_path).expanduser().resolve()
        self.image_type = image_type.lower()

    def process_evidence(self) -> EvidenceMetadata:
        hashes = calculate_hashes(self.path)
        evidence_id = f"{self.image_type}_{hashes['md5'][:8]}"
        return EvidenceMetadata(
            evidence_id=evidence_id,
            file_name=self.path.name,
            file_path=str(self.path),
            image_type=self.image_type,
            size_bytes=self.path.stat().st_size,
            hashes=hashes,
            intake_timestamp_utc=utc_now(),
        )

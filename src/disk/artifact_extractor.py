from __future__ import annotations

from pathlib import Path
from src.config.data_models import DiskArtifact
from .fs_parser import FileSystemParser


class ArtifactExtractor:
    def __init__(self, mount_point: str) -> None:
        self.fs = FileSystemParser(mount_point)

    def extract_system_hives(self) -> list[DiskArtifact]:
        artifacts: list[DiskArtifact] = []
        candidates = self.fs.find_files(
            lambda p: p.name.upper() == "SYSTEM" and "config" in {part.lower() for part in p.parts}
        )
        for p in candidates:
            meta = self.fs.metadata(p)
            artifacts.append(DiskArtifact(
                artifact_type="Registry Hive",
                source_path=str(p),
                timestamp=meta["modified"],
                details={"hive_type": "SYSTEM", **meta},
            ))
        return artifacts

    def extract_prefetch(self) -> list[DiskArtifact]:
        artifacts: list[DiskArtifact] = []
        candidates = self.fs.find_files(
            lambda p: p.suffix.lower() == ".pf" and "prefetch" in {part.lower() for part in p.parts}
        )
        for p in candidates:
            meta = self.fs.metadata(p)
            executable = p.name.split("-")[0] + ".exe" if "-" in p.name else p.stem + ".exe"
            artifacts.append(DiskArtifact(
                artifact_type="Prefetch File",
                source_path=str(p),
                timestamp=meta["modified"],
                details={"executable_identified": executable, **meta},
            ))
        return artifacts

    def extract_all(self) -> list[DiskArtifact]:
        return self.extract_system_hives() + self.extract_prefetch()

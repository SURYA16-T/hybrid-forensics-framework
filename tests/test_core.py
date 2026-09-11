from pathlib import Path

from src.correlation import (
    ThreatScorer,
    TimelineBuilder,
)

from src.disk import ArtifactExtractor
from src.intake import EvidenceIntake


def test_hash_and_intake(tmp_path: Path):
    evidence_file = (
        tmp_path / "evidence.bin"
    )

    evidence_file.write_bytes(
        b"forensic-test"
    )

    evidence = EvidenceIntake(
        str(evidence_file),
        "generic",
    ).process_evidence()

    assert evidence.size_bytes > 0
    assert len(
        evidence.hashes["md5"]
    ) == 32

    assert len(
        evidence.hashes["sha256"]
    ) == 64


def test_disk_artifacts():
    root = Path(
        "samples/disk_root"
    )

    extractor = ArtifactExtractor(
        str(root)
    )

    artifacts = (
        extractor.extract_all()
    )

    types = {
        item.artifact_type
        for item in artifacts
    }

    assert "Registry Hive" in types
    assert "Prefetch File" in types


def test_timeline_and_scoring():
    extractor = ArtifactExtractor(
        "samples/disk_root"
    )

    artifacts = (
        extractor.extract_all()
    )

    timeline = TimelineBuilder()

    timeline.ingest_disk_artifacts(
        artifacts
    )

    events = (
        timeline.build_timeline()
    )

    threats = (
        ThreatScorer()
        .evaluate_timeline(events)
    )

    assert len(events) >= 2
    assert len(threats) >= 1
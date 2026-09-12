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


def test_threat_scorer_paths_and_names():
    from src.config.data_models import CorrelatedEvent

    scorer = ThreatScorer()

    # Windows Temp path
    e_win_temp = CorrelatedEvent("2026-09-12T00:00:00Z", "disk", "file", "C:\\Temp\\unknown.exe")
    assert scorer.score_event(e_win_temp) >= 20

    # Windows AppData Local Temp path
    e_win_appdata = CorrelatedEvent("2026-09-12T00:00:00Z", "disk", "file", "C:\\Users\\user\\AppData\\Local\\Temp\\dropper.exe")
    assert scorer.score_event(e_win_appdata) >= 35

    # Suspicious executable by name with and without .exe
    e_mimikatz = CorrelatedEvent("2026-09-12T00:00:00Z", "memory", "proc", "mimikatz.exe running")
    assert scorer.score_event(e_mimikatz) >= 75

    e_mimikatz_stem = CorrelatedEvent("2026-09-12T00:00:00Z", "memory", "proc", "mimikatz spawned")
    assert scorer.score_event(e_mimikatz_stem) >= 75


def test_cross_platform_memory_findings_ingest():
    from src.capture import MacOSMemoryFinding, LinuxMemoryFinding, MemoryFinding

    tb = TimelineBuilder()
    mac_f = MacOSMemoryFinding(101, "node", "0x1000", "rwx", 4096, "RWX_EXECUTABLE_MEMORY", 85, {"jit": True})
    lin_f = LinuxMemoryFinding(202, "proc", "0x2000", "rwxp", 8192, "RWX_EXECUTABLE_MEMORY", 85, {"mapping": ""})
    win_f = MemoryFinding(303, "test.exe", 0x3000, 65536, 0x40, 0x20000, "RWX_SHELLCODE_INJECTION", 90, {})

    tb.ingest_memory_findings([mac_f, lin_f, win_f])
    events = tb.build_timeline()
    assert len(events) == 3

    scorer = ThreatScorer()
    threats = scorer.evaluate_timeline(events)
    assert len(threats) == 3


def test_memory_finding_to_dict():
    from src.capture import MemoryFinding, MacOSMemoryFinding, LinuxMemoryFinding

    win_f = MemoryFinding(1, "proc.exe", 0x1000, 4096, 0x40, 0x20000, "RWX_SHELLCODE_INJECTION", 90, {})
    d_win = win_f.to_dict()
    assert isinstance(d_win, dict)
    assert d_win["pid"] == 1
    assert d_win["rule"] == "RWX_SHELLCODE_INJECTION"

    mac_f = MacOSMemoryFinding(2, "proc", "0x1000", "rwx", 4096, "RWX_EXECUTABLE_MEMORY", 85, {})
    d_mac = mac_f.to_dict()
    assert isinstance(d_mac, dict)
    assert d_mac["pid"] == 2

    lin_f = LinuxMemoryFinding(3, "proc", "0x1000", "rwxp", 4096, "RWX_EXECUTABLE_MEMORY", 85, {})
    d_lin = lin_f.to_dict()
    assert isinstance(d_lin, dict)
    assert d_lin["pid"] == 3


def test_jit_whitelist_coverage():
    from src.config.settings import JIT_WHITELIST

    # Ensure cross-platform names are present
    assert "node.exe" in JIT_WHITELIST
    assert "node" in JIT_WHITELIST
    assert "chrome.exe" in JIT_WHITELIST
    assert "chrome" in JIT_WHITELIST
import os
from pathlib import Path

files = {
"src/capture/macos_live.py": r"""from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Any

from src.config.settings import JIT_WHITELIST, MAC_MEMORY_RULES


@dataclass
class MacOSMemoryFinding:
    pid: int
    process_name: str
    region: str
    permissions: str
    size_bytes: int
    rule: str
    risk_score: int
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MacOSLiveAnalyzer:
    \"\"\"Best-effort live macOS process and virtual-memory inspection.

    Uses built-in macOS tools (ps and vmmap). It does not claim to acquire
    physical RAM. Access to protected processes can be restricted by macOS.
    \"\"\"

    def __init__(self) -> None:
        if platform.system() != "Darwin":
            raise OSError("MacOSLiveAnalyzer is supported only on macOS.")
        missing = [tool for tool in ("ps", "vmmap") if shutil.which(tool) is None]
        if missing:
            raise EnvironmentError(f"Required macOS tools not found: {', '.join(missing)}")

    @staticmethod
    def _parse_ps(output: str) -> list[tuple[int, int, str, str]]:
        rows: list[tuple[int, int, str, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("PID"):
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
            except ValueError:
                continue
            name = parts[2]
            command = parts[3]
            rows.append((pid, ppid, name, command))
        return rows

    def list_processes(self) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,comm=,command="],
            capture_output=True, text=True, check=True,
        )
        return [
            {"pid": pid, "ppid": ppid, "process_name": name, "path": command}
            for pid, ppid, name, command in self._parse_ps(result.stdout)
        ]

    @staticmethod
    def _permission_flags(header: str) -> str:
        match = re.search(r"\b([r-][w-][x-])(?:/[r-][w-][x-])?\b", header)
        return match.group(1) if match else ""

    @staticmethod
    def _size_bytes(text: str) -> int:
        match = re.search(r"\b([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?B)\b", text.upper())
        if not match:
            return 0
        value = float(match.group(1))
        unit = match.group(2)
        multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4, "PB": 1024**5}
        return int(value * multipliers[unit])

    def inspect_process(self, pid: int, process_name: str) -> list[MacOSMemoryFinding]:
        result = subprocess.run(
            ["vmmap", str(pid)], capture_output=True, text=True
        )
        if result.returncode != 0:
            return []

        findings: list[MacOSMemoryFinding] = []
        for line in result.stdout.splitlines():
            lower = line.lower()
            perms = self._permission_flags(line)
            if not perms:
                continue
            size = self._size_bytes(line)
            rule = None
            risk = 0

            # macOS VM permissions are represented as r/w/x flags by vmmap.
            if "rwx" in perms:
                rule = "RWX_EXECUTABLE_MEMORY"
                risk = MAC_MEMORY_RULES[rule]
            elif perms == "r-x" and size >= 1024 * 1024:
                rule = "LARGE_EXECUTABLE_REGION"
                risk = MAC_MEMORY_RULES[rule]
            elif perms == "rwx" and size >= 256 * 1024:
                rule = "RWX_REGION"
                risk = MAC_MEMORY_RULES[rule]

            if rule:
                whitelisted = process_name.lower() in JIT_WHITELIST
                if whitelisted:
                    risk = max(10, risk - 30)
                findings.append(MacOSMemoryFinding(
                    pid=pid,
                    process_name=process_name,
                    region=line.strip(),
                    permissions=perms,
                    size_bytes=size,
                    rule=rule,
                    risk_score=min(100, risk),
                    details={"jit_whitelisted": whitelisted},
                ))
        return findings

    def scan(self) -> list[MacOSMemoryFinding]:
        findings: list[MacOSMemoryFinding] = []
        for proc in self.list_processes():
            findings.extend(self.inspect_process(int(proc["pid"]), str(proc["process_name"])))
        return findings
""",
"src/capture/live_snapshot.py": r"""from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from .linux_live import LinuxLiveAnalyzer
from .macos_live import MacOSLiveAnalyzer
from .native_ram import NativeLiveRAMAnalyzer


def capture_live_snapshot(output_path: str) -> str:
    \"\"\"Save a platform-specific live triage snapshot as JSON.

    Windows: native Win32 virtual-memory findings.
    macOS: ps + vmmap findings.
    Linux: /proc process/maps findings.
    This is not a physical RAM image acquisition function.
    \"\"\"
    system = platform.system()
    if system == "Windows":
        findings = [f.to_dict() for f in NativeLiveRAMAnalyzer().scan()]
    elif system == "Darwin":
        findings = [f.to_dict() for f in MacOSLiveAnalyzer().scan()]
    elif system == "Linux":
        findings = [f.to_dict() for f in LinuxLiveAnalyzer().scan()]
    else:
        raise OSError(f"Unsupported operating system: {system}")

    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": system,
        "capture_type": "live_virtual_memory_triage",
        "physical_ram_acquired": False,
        "findings": findings,
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(target)
""",
"src/config/__init__.py": r"""from .data_models import EvidenceMetadata, DiskArtifact, MemoryProcess, CorrelatedEvent
""",
"src/config/settings.py": r"""from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_HASH_CHUNK = 64 * 1024
ALLOW_NETWORK_ACCESS = False
OFFLINE_MODE = True

SUPPORTED_MEMORY_EXTENSIONS = {".raw", ".vmem", ".dmp", ".sav", ".mem"}
SUPPORTED_DISK_EXTENSIONS = {".raw", ".dd", ".img", ".vhd", ".vhdx", ".vmdk"}

SUSPICIOUS_NAMES = {
    "mimikatz.exe": 75,
    "psexec.exe": 70,
    "powershell.exe": 60,
    "pwsh.exe": 60,
    "cmd.exe": 35,
    "wscript.exe": 45,
    "cscript.exe": 45,
}

SUSPICIOUS_PATH_PARTS = {
    "\\temp\\": 20,
    "/tmp/": 20,
    "\\downloads\\": 40,
    "/downloads/": 40,
    "\\appdata\\local\\temp\\": 35,
    "/.cache/": 20,
}

JIT_WHITELIST = {
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe",
    "node.exe", "code.exe", "electron.exe"
}

MEMORY_RULES = {
    "RWX_SHELLCODE_INJECTION": 90,
    "RWX_WRITECOPY_SUSPICIOUS": 80,
    "RWX_GUARD_STAGED_PAYLOAD": 75,
    "LARGE_PRIVATE_EXECUTABLE": 60,
}

# Linux/macOS live virtual-memory triage rules. These are heuristics, not malware proof.
LINUX_MEMORY_RULES = {
    "RWX_EXECUTABLE_MEMORY": 85,
    "LARGE_EXECUTABLE_REGION": 55,
}

MAC_MEMORY_RULES = {
    "RWX_EXECUTABLE_MEMORY": 85,
    "LARGE_EXECUTABLE_REGION": 55,
    "RWX_REGION": 75,
}
""",
"src/config/data_models.py": r"""from __future__ import annotations

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
""",
"src/intake/__init__.py": r"""from .ingest_image import EvidenceIntake
""",
"src/intake/validator.py": r"""from __future__ import annotations

import hashlib
from pathlib import Path
from src.config.settings import DEFAULT_HASH_CHUNK


def calculate_hashes(path: str | Path, chunk_size: int = DEFAULT_HASH_CHUNK) -> dict[str, str]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
""",
"src/intake/ingest_image.py": r"""from __future__ import annotations

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
""",
"src/disk/__init__.py": r"""from .artifact_extractor import ArtifactExtractor
""",
"src/disk/fs_parser.py": r"""from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class FileSystemParser:
    def __init__(self, mount_point: str) -> None:
        self.root = Path(mount_point).expanduser().resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise NotADirectoryError(f"Disk root is not a directory: {self.root}")

    def find_files(self, predicate) -> list[Path]:
        results: list[Path] = []
        for path in self.root.rglob("*"):
            try:
                if path.is_file() and predicate(path):
                    results.append(path)
            except OSError:
                continue
        return results

    def metadata(self, path: Path) -> dict:
        st = path.stat()
        return {
            "created": _utc(getattr(st, "st_ctime", st.st_mtime)),
            "modified": _utc(st.st_mtime),
            "accessed": _utc(st.st_atime),
            "size_bytes": st.st_size,
        }
""",
"src/disk/artifact_extractor.py": r"""from __future__ import annotations

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
""",
"src/memory/__init__.py": r"""from .process_scanner import ProcessScanner
""",
"src/memory/volatility_wrapper.py": r"""from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class VolatilityError(RuntimeError):
    pass


class VolatilityWrapper:
    def __init__(self, executable: str = "vol") -> None:
        resolved = shutil.which(executable) or executable
        self.executable = resolved

    def run(self, memory_image: str, plugin: str = "windows.pslist.PsList") -> list[dict[str, Any]]:
        cmd = [self.executable, "-f", str(Path(memory_image)), "-r", "json", plugin]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError as exc:
            raise VolatilityError(
                "Volatility executable not found. Install Volatility 3 and ensure 'vol' is in PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise VolatilityError("Volatility analysis timed out after 300 seconds.") from exc
        if proc.returncode != 0:
            raise VolatilityError(proc.stderr.strip() or "Volatility returned a non-zero exit code.")
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise VolatilityError("Volatility did not return valid JSON.") from exc
        return parsed if isinstance(parsed, list) else parsed.get("rows", []) if isinstance(parsed, dict) else []
""",
"src/memory/process_scanner.py": r"""from __future__ import annotations

import os
import platform
from pathlib import Path
from src.config.data_models import MemoryProcess
from .volatility_wrapper import VolatilityWrapper


class ProcessScanner:
    def __init__(self, memory_image: str | None = None, volatility: str = "vol") -> None:
        self.memory_image = memory_image
        self.volatility = volatility

    def scan_offline(self) -> list[MemoryProcess]:
        if not self.memory_image:
            raise ValueError("A memory image is required for offline scanning.")
        rows = VolatilityWrapper(self.volatility).run(self.memory_image)
        processes: list[MemoryProcess] = []
        for row in rows:
            try:
                pid = int(row.get("PID", row.get("pid", 0)) or 0)
                ppid = int(row.get("PPID", row.get("ppid", 0)) or 0)
                name = str(row.get("ImageFileName", row.get("Name", row.get("name", "unknown"))) or "unknown")
                path = str(row.get("Path", row.get("path", "")) or "")
                processes.append(MemoryProcess(pid=pid, ppid=ppid, process_name=name, path=path))
            except (TypeError, ValueError):
                continue
        return processes

    def list_live_processes(self) -> list[MemoryProcess]:
        if platform.system() == "Windows":
            raise RuntimeError("Use NativeLiveRAMAnalyzer on Windows for live process/memory inspection.")
        results: list[MemoryProcess] = []
        proc_root = Path("/proc")
        if proc_root.exists():
            for entry in proc_root.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    pid = int(entry.name)
                    stat = (entry / "stat").read_text(errors="replace")
                    close = stat.rfind(")")
                    fields = stat[close + 2:].split()
                    ppid = int(fields[1]) if len(fields) > 1 else 0
                    comm = stat[stat.find("(") + 1:close]
                    exe = os.readlink(entry / "exe") if (entry / "exe").exists() else ""
                    results.append(MemoryProcess(pid, ppid, comm, exe))
                except (OSError, ValueError):
                    continue
        return results
""",
"src/correlation/__init__.py": r"""from .timeline_builder import TimelineBuilder
from .threat_scorer import ThreatScorer
""",
"src/correlation/timeline_builder.py": r"""from __future__ import annotations

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
""",
"src/correlation/threat_scorer.py": r"""from __future__ import annotations

from src.config.settings import SUSPICIOUS_NAMES, SUSPICIOUS_PATH_PARTS


class ThreatScorer:
    def score_event(self, event) -> int:
        score = int(event.risk_score or 0)
        text = f"{event.description} {event.details}".lower()
        for name, points in SUSPICIOUS_NAMES.items():
            if name in text:
                score = max(score, points)
        for part, points in SUSPICIOUS_PATH_PARTS.items():
            if part in text.replace("\\", "/"):
                score += points
        return min(100, score)

    def evaluate_timeline(self, timeline):
        threats = []
        for event in timeline:
            event.risk_score = self.score_event(event)
            if event.risk_score > 0:
                threats.append(event)
        return threats
""",
"src/response/__init__.py": r"""from .report_generator import ReportGenerator
""",
"src/response/report_generator.py": r"""from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path


class ReportGenerator:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _dict_list(items):
        return [asdict(x) if hasattr(x, "__dataclass_fields__") else x for x in items]

    def generate(self, evidence, timeline, threats) -> tuple[str, str]:
        payload = {
            "evidence": asdict(evidence),
            "timeline": self._dict_list(timeline),
            "threats": self._dict_list(threats),
            "summary": {
                "event_count": len(timeline),
                "threat_count": len(threats),
                "max_risk": max((getattr(x, "risk_score", 0) for x in threats), default=0),
            },
        }
        json_path = self.output_dir / "forensic_report.json"
        html_path = self.output_dir / "forensic_report.html"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        rows = "".join(
            f"<tr><td>{e.timestamp}</td><td>{e.source_module}</td><td>{e.event_type}</td>"
            f"<td>{e.description}</td><td>{e.risk_score}</td></tr>" for e in timeline
        )
        html = f"<!doctype html><html><head><meta charset='utf-8'><title>Forensic Report</title>\n<style>body{{font-family:Arial,sans-serif;margin:2rem;background:#f5f7fb;color:#172033}} .card{{background:white;padding:1rem;margin-bottom:1rem;border-radius:10px}} table{{width:100%;border-collapse:collapse;background:white}} th,td{{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}} th{{background:#eef2f7}}</style>\n</head><body><div class='card'><h1>Hybrid Forensic Report</h1><p><b>Evidence ID:</b> {evidence.evidence_id}</p><p><b>MD5:</b> {evidence.hashes['md5']}</p><p><b>SHA-256:</b> {evidence.hashes['sha256']}</p><p><b>Events:</b> {len(timeline)} &nbsp; <b>Threats:</b> {len(threats)} &nbsp; <b>Max Risk:</b> {payload['summary']['max_risk']}</p></div>\n<table><thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Description</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table></body></html>"
        html_path.write_text(html, encoding="utf-8")
        return str(json_path), str(html_path)
"""
}

project_root = Path("/Users/suryaprakasht/Downloads/hybrid-forensics-framework")
for filename, content in files.items():
    p = project_root / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    print(f"Updated {filename}")

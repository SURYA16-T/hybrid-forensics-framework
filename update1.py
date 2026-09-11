import os
from pathlib import Path

files = {
"README.md": r"""# Hybrid Memory & Disk Forensics Framework

A local, modular digital-forensics framework that combines evidence intake, disk artifact inspection, offline memory analysis through Volatility 3, platform-specific live process/virtual-memory heuristics, timeline correlation, rule-based threat scoring, and offline JSON/HTML reporting.

## Platforms

### Windows
- Native live process + virtual-memory inspection through Win32 APIs (`ctypes`).
- Suspicious memory-region heuristics.
- Optional process MiniDump acquisition through `dbghelp.dll`.
- Optional WinPMEM workflow can be integrated externally for physical-memory acquisition.

### macOS
- Live process enumeration using the built-in `ps` command.
- Per-process virtual-memory inspection using the built-in `vmmap` command.
- Suspicious executable-region heuristics.
- Works on Intel and Apple-silicon Macs as far as the host tools permit.
- Does **not** claim physical-RAM acquisition; macOS permissions, SIP and protected-process restrictions can limit access. For forensic memory images, use Volatility 3.

### Linux
- Live process enumeration from `/proc`.
- Per-process virtual-memory-map inspection using `/proc/<pid>/maps`.
- Suspicious executable-region heuristics.
- Physical RAM acquisition is intentionally not implemented by this project; use a dedicated Linux acquisition method/tool and then analyze the image with Volatility 3.

The framework itself does not need network access.

## Full flow

```text
Evidence
   |
   +--> Intake -> MD5/SHA-256
   |
   +--> Disk -> SYSTEM / Prefetch / filesystem metadata
   |
   +--> Memory image -> Volatility 3 -> process records
   |
   +--> Live platform scanner
           |-- Windows -> Win32 API
           |-- macOS   -> ps + vmmap
           `-- Linux   -> /proc + /proc/<pid>/maps
   |
   +--> Timeline Builder
   |
   +--> Threat Scorer (transparent heuristics)
   |
   `--> JSON + HTML report
```

## Setup

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Run the live platform scanner:

```bash
./run_macos.sh       # macOS
python -m src.main --scan-live   # Linux or macOS
```

### Windows PowerShell (Administrator recommended for live scanning)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
python -m src.main --scan-live
```

## Offline memory analysis

Install Volatility 3 locally and make its launcher available as `vol` (or pass `--volatility`):

```bash
python -m src.main --image /path/to/memdump.raw --type memory
```

## Disk analysis

The disk parser operates on a mounted or already extracted filesystem tree:

```bash
python -m src.main --image /path/to/evidence.img --type disk --disk-root /mnt/evidence
```

## Hybrid analysis

```bash
python -m src.main --image /path/to/memdump.raw --type hybrid --disk-root /mnt/evidence
```

## Current artifact coverage

- Windows SYSTEM Registry hive discovery and metadata collection.
- Windows Prefetch `.pf` discovery and executable-name extraction.
- Filesystem timestamps and sizes.

## Correlation

Disk artifacts and memory observations are normalized into one `CorrelatedEvent` model and sorted chronologically. The current implementation is deliberately transparent: it does not claim advanced PID/path/hash/time-window entity matching.

## Threat heuristics

Windows checks include:
- `PAGE_EXECUTE_READWRITE`
- `PAGE_EXECUTE_WRITECOPY`
- guarded executable regions
- large private executable regions

Linux/macOS checks include suspicious executable/RWX virtual-memory regions. The threat scorer also considers suspicious executable names and path indicators.

Scores are triage heuristics, **not proof of malware**.

## macOS limitation to state in a presentation

The macOS module performs **live process and virtual-memory-map triage**, not a complete physical-RAM acquisition. This is intentional. A complete physical-memory workflow on macOS requires platform-specific acquisition mechanisms and permissions beyond a portable Python script.

## Safety / forensic note

Work on copies where possible and preserve originals and cryptographic hashes. Live process inspection can require elevated privileges and may be restricted by operating-system security controls.
""",
"docs.md": r"""# Platform implementation guide

## Windows

Live analysis uses Python `ctypes` to call Win32 process and virtual-memory APIs. The optional MiniDump module uses `dbghelp.dll`. Protected processes may deny access. A MiniDump is a process dump, not the same thing as a complete physical-RAM image.

## macOS

Live analysis uses built-in `ps` for process enumeration and `vmmap` for virtual-memory-region inspection. These are appropriate for host-side triage and do not constitute full physical-RAM acquisition. macOS security controls can restrict access to protected processes. Apple documents Mach virtual-memory APIs, but using those directly from a portable Python project would require a substantially different native extension and still would not make physical-RAM acquisition equivalent to a traditional forensic RAM image. citeturn739850search7

## Linux

Live analysis uses `/proc` process information and `/proc/<pid>/maps` for virtual-memory mappings. Physical RAM acquisition is intentionally outside the portable framework; the expected workflow is to acquire a forensic memory image with a dedicated acquisition method and then analyze it with Volatility 3.

## Cross-platform design

```text
                    main.py
                       |
             +---------+---------+
             |         |         |
          Windows    macOS     Linux
             |         |         |
          Win32      ps/vmmap   /proc
             |         |         |
             +---------+---------+
                       |
                 common finding
                   structures
                       |
                timeline + score
                       |
                 JSON / HTML
```

## Important accuracy statement

The framework is cross-platform for the analysis workflow and live virtual-memory triage. It is **not** a claim of identical physical-RAM acquisition capability on all three operating systems. Forensic acquisition is platform-specific.
""",
"requirements.txt": r"""rich>=13.0
questionary>=2.0
prompt_toolkit>=3.0
pytest>=8.0
""",
".gitignore": r"""__pycache__/
*.pyc
.pytest_cache/
.venv/
venv/
output/*
*.raw
*.dd
*.img
*.dmp
*.vmem
*.sav
""",
"run_linux.sh": r"""#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
python -m src.main --help
""",
"run_macos.sh": r"""#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m src.main --scan-live
""",
"run_windows.ps1": r"""$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
python -m src.main --help
Write-Host "For live scanning, open an Administrator PowerShell and run:"
Write-Host "python -m src.main --scan-live"
Write-Host "For a saved live triage snapshot:"
Write-Host "python -m src.main --capture-live output\live_snapshot.json"
""",
"src/__init__.py": r"""""",
"src/main.py": r"""from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from src.capture import LinuxLiveAnalyzer, MacOSLiveAnalyzer, NativeLiveRAMAnalyzer, capture_live_snapshot
from src.correlation import TimelineBuilder, ThreatScorer
from src.disk import ArtifactExtractor
from src.intake import EvidenceIntake
from src.memory import ProcessScanner
from src.response import ReportGenerator
from src.config.settings import OUTPUT_DIR


def run_offline(evidence_path: str, evidence_type: str, disk_root: str | None, volatility: str, output_dir: str) -> dict:
    evidence = EvidenceIntake(evidence_path, evidence_type).process_evidence()
    timeline = TimelineBuilder()

    if evidence_type in {"disk", "hybrid"}:
        if not disk_root:
            raise ValueError("--disk-root is required for disk or hybrid analysis.")
        artifacts = ArtifactExtractor(disk_root).extract_all()
        timeline.ingest_disk_artifacts(artifacts)

    if evidence_type in {"memory", "hybrid"}:
        scanner = ProcessScanner(evidence_path, volatility)
        processes = scanner.scan_offline()
        timeline.ingest_memory_processes(processes, evidence.intake_timestamp_utc)

    events = timeline.build_timeline()
    threats = ThreatScorer().evaluate_timeline(events)
    output_path = Path(output_dir) / evidence.evidence_id
    json_path, html_path = ReportGenerator(output_path).generate(evidence, events, threats)
    return {"evidence_id": evidence.evidence_id, "json": json_path, "html": html_path, "events": len(events), "threats": len(threats)}


def live_scan() -> None:
    system = platform.system()
    if system == "Windows":
        analyzer = NativeLiveRAMAnalyzer()
        findings = analyzer.scan()
    elif system == "Darwin":
        analyzer = MacOSLiveAnalyzer()
        findings = analyzer.scan()
    elif system == "Linux":
        analyzer = LinuxLiveAnalyzer()
        findings = analyzer.scan()
    else:
        print(f"Unsupported operating system: {system}")
        return

    payload = [item.to_dict() for item in findings]
    print(json.dumps({
        "platform": system,
        "mode": "live_virtual_memory_triage",
        "findings": payload,
        "count": len(payload),
        "note": "Heuristic triage only; protected processes may be inaccessible and this command does not acquire physical RAM on Linux/macOS."
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Memory & Disk Forensics Framework")
    parser.add_argument("--image", help="Forensic evidence image/file")
    parser.add_argument("--type", choices=["memory", "disk", "hybrid", "generic"], default="generic")
    parser.add_argument("--disk-root", help="Mounted/extracted disk root directory")
    parser.add_argument("--volatility", default="vol", help="Volatility 3 command or full executable path")
    parser.add_argument("--output", default=str(OUTPUT_DIR))
    parser.add_argument("--scan-live", action="store_true", help="Run the platform-appropriate live process/memory heuristic scanner")
    parser.add_argument("--capture-live", metavar="PATH", help="Save a platform-specific live triage snapshot as JSON (not physical RAM)")
    args = parser.parse_args()

    if args.capture_live:
        try:
            print(capture_live_snapshot(args.capture_live))
        except (OSError, EnvironmentError, PermissionError) as exc:
            print(f"LIVE CAPTURE ERROR: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return

    if args.scan_live:
        try:
            live_scan()
        except (OSError, EnvironmentError, PermissionError) as exc:
            print(f"LIVE SCAN ERROR: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return

    if not args.image:
        print(f"Hybrid Forensics Framework ({platform.system()})")
        print("  /scan                         Live platform memory heuristic scan")
        print("  /capture-live <file>          Save live triage snapshot JSON")
        print("  /analyze <file>               Analyze memory/disk evidence")
        print("  /exit                         Quit")
        while True:
            try:
                line = input("forensics> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if line == "/exit":
                return
            if line.startswith("/capture-live "):
                target = line[len("/capture-live "):].strip().strip('"')
                try:
                    print(capture_live_snapshot(target))
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line == "/scan":
                try:
                    live_scan()
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line.startswith("/analyze "):
                file_path = line[len("/analyze "):].strip().strip('"')
                kind = "memory" if Path(file_path).suffix.lower() in {".raw", ".dmp", ".vmem", ".sav", ".mem"} else "disk"
                try:
                    print(run_offline(file_path, kind, None, args.volatility, args.output))
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line in {"/help", "help"}:
                print("/scan | /capture-live <file> | /analyze <file> | /exit")
                continue
            print("Unknown command. Use /help.")
        return

    result = run_offline(args.image, args.type, args.disk_root, args.volatility, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
""",
"src/capture/__init__.py": r"""from .native_ram import NativeLiveRAMAnalyzer, MemoryFinding
from .live_ram import LiveRAMCapturer
from .macos_live import MacOSLiveAnalyzer, MacOSMemoryFinding
from .linux_live import LinuxLiveAnalyzer, LinuxMemoryFinding

from .live_snapshot import capture_live_snapshot
""",
"src/capture/native_ram.py": r"""from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import platform
from dataclasses import dataclass
from typing import Any

from src.config.settings import JIT_WHITELIST, MEMORY_RULES


@dataclass
class MemoryFinding:
    pid: int
    process_name: str
    base_address: int
    region_size: int
    protection: int
    allocation_type: int
    rule: str
    risk_score: int
    details: dict[str, Any]


class NativeLiveRAMAnalyzer:
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", wintypes.LPVOID),
            ("AllocationBase", wintypes.LPVOID),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise OSError("NativeLiveRAMAnalyzer is supported only on Windows.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_api()

    def _configure_api(self) -> None:
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(self.PROCESSENTRY32W)]
        self.kernel32.Process32FirstW.restype = wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(self.PROCESSENTRY32W)]
        self.kernel32.Process32NextW.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(self.MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    def _processes(self):
        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = self.PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = self.kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                yield entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile
                ok = self.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.kernel32.CloseHandle(snapshot)

    @staticmethod
    def _is_executable(protect: int) -> bool:
        return protect in {
            NativeLiveRAMAnalyzer.PAGE_EXECUTE,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_READ,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_READWRITE,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_WRITECOPY,
        }

    def scan(self) -> list[MemoryFinding]:
        findings: list[MemoryFinding] = []
        for pid, _ppid, name in self._processes():
            handle = self.kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ, False, pid
            )
            if not handle:
                continue
            try:
                addr = 0
                while addr < (1 << 47):
                    mbi = self.MEMORY_BASIC_INFORMATION()
                    result = self.kernel32.VirtualQueryEx(
                        handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if not result or mbi.RegionSize == 0:
                        break
                    protect = int(mbi.Protect)
                    region_size = int(mbi.RegionSize)
                    is_private = int(mbi.Type) == self.MEM_PRIVATE
                    rule = None
                    if int(mbi.State) == self.MEM_COMMIT:
                        if protect & self.PAGE_GUARD and self._is_executable(protect & 0xFF):
                            rule = "RWX_GUARD_STAGED_PAYLOAD"
                        elif (protect & 0xFF) == self.PAGE_EXECUTE_READWRITE:
                            rule = "RWX_SHELLCODE_INJECTION"
                        elif (protect & 0xFF) == self.PAGE_EXECUTE_WRITECOPY:
                            rule = "RWX_WRITECOPY_SUSPICIOUS"
                        elif is_private and region_size >= 1024 * 1024 and (protect & 0xFF) in {
                            self.PAGE_EXECUTE, self.PAGE_EXECUTE_READ
                        }:
                            rule = "LARGE_PRIVATE_EXECUTABLE"
                    if rule:
                        risk = MEMORY_RULES[rule]
                        if name.lower() in JIT_WHITELIST:
                            risk = max(10, risk - 30)
                        findings.append(MemoryFinding(
                            pid=int(pid), process_name=name,
                            base_address=int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0),
                            region_size=region_size, protection=protect,
                            allocation_type=int(mbi.Type), rule=rule,
                            risk_score=min(100, risk), details={"jit_whitelisted": name.lower() in JIT_WHITELIST}
                        ))
                    addr = int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr) + region_size
            finally:
                self.kernel32.CloseHandle(handle)
        return findings
""",
"src/capture/live_ram.py": r"""from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import platform
import subprocess
from pathlib import Path


class LiveRAMCapturer:
    \"\"\"Creates Windows process MiniDumps for selected PIDs using dbghelp.dll.\"\"\"

    MiniDumpWithFullMemory = 0x00000002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise OSError("Live RAM capture is supported only on Windows.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.dbghelp.MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
            wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID
        ]
        self.dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

    def dump_process(self, pid: int, output_path: str) -> str:
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        process = self.kernel32.OpenProcess(
            self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ, False, int(pid)
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            kernel32 = self.kernel32
            GENERIC_WRITE = 0x40000000
            CREATE_ALWAYS = 2
            file_handle = kernel32.CreateFileW(
                str(out), GENERIC_WRITE, 0, None, CREATE_ALWAYS, 0, None
            )
            if file_handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                ok = self.dbghelp.MiniDumpWriteDump(
                    process, int(pid), file_handle,
                    self.MiniDumpWithFullMemory, None, None, None
                )
                if not ok:
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel32.CloseHandle(file_handle)
        finally:
            self.kernel32.CloseHandle(process)
        return str(out)
""",
"src/capture/linux_live.py": r"""from __future__ import annotations

import os
import platform
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from src.config.settings import JIT_WHITELIST, LINUX_MEMORY_RULES


@dataclass
class LinuxMemoryFinding:
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


class LinuxLiveAnalyzer:
    \"\"\"Live Linux process and /proc/<pid>/maps heuristic inspection.\"\"\"

    def __init__(self) -> None:
        if platform.system() != "Linux":
            raise OSError("LinuxLiveAnalyzer is supported only on Linux.")

    @staticmethod
    def _read_name(pid_dir: Path) -> str:
        try:
            return (pid_dir / "comm").read_text(errors="replace").strip() or "unknown"
        except OSError:
            return "unknown"

    @staticmethod
    def _read_ppid(pid_dir: Path) -> int:
        try:
            stat = (pid_dir / "stat").read_text(errors="replace")
            close = stat.rfind(")")
            fields = stat[close + 2:].split()
            return int(fields[1]) if len(fields) > 1 else 0
        except (OSError, ValueError):
            return 0

    @staticmethod
    def _read_exe(pid_dir: Path) -> str:
        try:
            return os.readlink(pid_dir / "exe")
        except OSError:
            return ""

    def list_processes(self) -> list[dict[str, Any]]:
        result = []
        proc_root = Path("/proc")
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            result.append({
                "pid": pid,
                "ppid": self._read_ppid(entry),
                "process_name": self._read_name(entry),
                "path": self._read_exe(entry),
            })
        return result

    def inspect_process(self, pid: int, process_name: str) -> list[LinuxMemoryFinding]:
        maps = Path(f"/proc/{pid}/maps")
        try:
            content = maps.read_text(errors="replace")
        except OSError:
            return []

        findings: list[LinuxMemoryFinding] = []
        for line in content.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            try:
                start, end = (int(v, 16) for v in parts[0].split("-", 1))
            except ValueError:
                continue
            perms = parts[1]
            size = max(0, end - start)
            rule = None
            risk = 0
            if perms.startswith("rwx"):
                rule = "RWX_EXECUTABLE_MEMORY"
                risk = LINUX_MEMORY_RULES[rule]
            elif perms.startswith("r-x") and size >= 1024 * 1024 and parts[5:] and "[heap]" not in parts[5]:
                rule = "LARGE_EXECUTABLE_REGION"
                risk = LINUX_MEMORY_RULES[rule]

            if rule:
                whitelisted = process_name.lower() in JIT_WHITELIST
                if whitelisted:
                    risk = max(10, risk - 30)
                findings.append(LinuxMemoryFinding(
                    pid=pid,
                    process_name=process_name,
                    region=parts[0],
                    permissions=perms,
                    size_bytes=size,
                    rule=rule,
                    risk_score=min(100, risk),
                    details={"mapping": parts[5] if len(parts) > 5 else "", "jit_whitelisted": whitelisted},
                ))
        return findings

    def scan(self) -> list[LinuxMemoryFinding]:
        findings: list[LinuxMemoryFinding] = []
        for proc in self.list_processes():
            findings.extend(self.inspect_process(int(proc["pid"]), str(proc["process_name"])))
        return findings
"""
}

project_root = Path("/Users/suryaprakasht/Downloads/hybrid-forensics-framework")
for filename, content in files.items():
    p = project_root / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    print(f"Updated {filename}")

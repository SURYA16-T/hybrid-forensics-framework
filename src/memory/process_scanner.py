from __future__ import annotations

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
        system = platform.system()
        if system == "Windows":
            raise RuntimeError("Use NativeLiveRAMAnalyzer on Windows for live process/memory inspection.")
        if system == "Darwin":
            from src.capture.macos_live import MacOSLiveAnalyzer
            try:
                raw = MacOSLiveAnalyzer().list_processes()
                return [
                    MemoryProcess(
                        pid=int(p["pid"]),
                        ppid=int(p["ppid"]),
                        process_name=str(p["process_name"]),
                        path=str(p.get("path", "")),
                    )
                    for p in raw
                ]
            except Exception:
                return []

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

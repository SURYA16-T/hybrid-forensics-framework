from __future__ import annotations

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
    """Live Linux process and /proc/<pid>/maps heuristic inspection."""

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
            mapping = parts[5] if len(parts) > 5 else ""
            is_anonymous = (len(parts) <= 5) or mapping.startswith("[anon") or "(deleted)" in mapping

            if perms.startswith("rwx"):
                rule = "RWX_EXECUTABLE_MEMORY"
                risk = LINUX_MEMORY_RULES[rule]
            elif perms.startswith("r-x") and size >= 1024 * 1024 and (is_anonymous or "[heap]" in mapping or "[stack]" in mapping):
                rule = "LARGE_EXECUTABLE_REGION"
                risk = LINUX_MEMORY_RULES[rule]

            if rule:
                pname = process_name.lower()
                stem = pname.split()[0] if " " in pname else pname
                whitelisted = (pname in JIT_WHITELIST) or (stem in JIT_WHITELIST)
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
                    details={"mapping": mapping, "jit_whitelisted": whitelisted},
                ))
        return findings

    def scan(self) -> list[LinuxMemoryFinding]:
        findings: list[LinuxMemoryFinding] = []
        for proc in self.list_processes():
            findings.extend(self.inspect_process(int(proc["pid"]), str(proc["process_name"])))
        return findings

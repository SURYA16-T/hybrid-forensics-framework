from __future__ import annotations

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
    """Best-effort live macOS process and virtual-memory inspection.

    Uses built-in macOS tools (ps and vmmap). It does not claim to acquire
    physical RAM. Access to protected processes can be restricted by macOS.
    """

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

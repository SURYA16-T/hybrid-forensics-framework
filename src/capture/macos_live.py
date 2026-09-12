from __future__ import annotations

import concurrent.futures
import os
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
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,comm=,command="],
                capture_output=True, text=True, check=True, timeout=10
            )
            return [
                {"pid": pid, "ppid": ppid, "process_name": name, "path": command}
                for pid, ppid, name, command in self._parse_ps(result.stdout)
            ]
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return []

    @staticmethod
    def _permission_flags(header: str) -> str:
        match = re.search(r"(?:^|\s)([r-][w-][x-])/([r-][w-][x-])(?:\s|$)", header)
        if match:
            return match.group(1)
        fallback = re.search(r"\b([r-][w-][x-])\b", header)
        return fallback.group(1) if fallback else ""

    @staticmethod
    def _size_bytes(text: str) -> int:
        match = re.search(r"\[\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?B?)\b", text.upper())
        if not match:
            match = re.search(r"\b([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?B?)\b", text.upper())
            if not match:
                return 0
        value = float(match.group(1))
        unit = match.group(2)
        multipliers = {
            "": 1, "B": 1,
            "K": 1024, "KB": 1024,
            "M": 1024**2, "MB": 1024**2,
            "G": 1024**3, "GB": 1024**3,
            "T": 1024**4, "TB": 1024**4,
            "P": 1024**5, "PB": 1024**5,
        }
        return int(value * multipliers.get(unit, 1))

    def inspect_process(self, pid: int, process_name: str) -> list[MacOSMemoryFinding]:
        try:
            result = subprocess.run(
                ["vmmap", str(pid)], capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                return []
        except subprocess.TimeoutExpired:
            return []

        findings: list[MacOSMemoryFinding] = []
        for line in result.stdout.splitlines():
            lower = line.lower()
            perms = self._permission_flags(line)
            if not perms or perms == "---":
                continue
            size = self._size_bytes(line)
            rule = None
            risk = 0

            # Current VM permissions: rwx or r-x
            if perms == "rwx":
                rule = "RWX_EXECUTABLE_MEMORY"
                risk = MAC_MEMORY_RULES.get(rule, 85)
            elif "x" in perms and "w" in perms:
                rule = "RWX_REGION"
                risk = MAC_MEMORY_RULES.get(rule, 75)
            elif perms == "r-x" and size >= 1024 * 1024 and "__text" not in lower:
                rule = "LARGE_EXECUTABLE_REGION"
                risk = MAC_MEMORY_RULES.get(rule, 55)

            if rule:
                pname = process_name.lower()
                stem = pname.split()[0] if " " in pname else pname
                whitelisted = (pname in JIT_WHITELIST) or (stem in JIT_WHITELIST)
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
        processes = self.list_processes()

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            current_uid = str(os.getuid())
            try:
                res = subprocess.run(["ps", "-axo", "pid=,uid="], capture_output=True, text=True, timeout=5)
                user_pids = {
                    int(p.split()[0]) for p in res.stdout.splitlines()
                    if len(p.split()) >= 2 and p.split()[1] == current_uid
                }
                processes = [p for p in processes if p["pid"] in user_pids]
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            future_to_pid = {
                executor.submit(self.inspect_process, int(p["pid"]), str(p["process_name"])): p
                for p in processes
            }
            for future in concurrent.futures.as_completed(future_to_pid):
                try:
                    findings.extend(future.result())
                except Exception:
                    continue
        return findings

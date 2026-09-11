from __future__ import annotations

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

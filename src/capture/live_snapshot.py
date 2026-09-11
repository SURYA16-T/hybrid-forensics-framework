from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from .linux_live import LinuxLiveAnalyzer
from .macos_live import MacOSLiveAnalyzer
from .native_ram import NativeLiveRAMAnalyzer


def capture_live_snapshot(output_path: str) -> str:
    """Save a platform-specific live triage snapshot as JSON.

    Windows: native Win32 virtual-memory findings.
    macOS: ps + vmmap findings.
    Linux: /proc process/maps findings.
    This is not a physical RAM image acquisition function.
    """
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

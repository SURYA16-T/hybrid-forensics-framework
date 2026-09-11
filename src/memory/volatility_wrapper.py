from __future__ import annotations

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

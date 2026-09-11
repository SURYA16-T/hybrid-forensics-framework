from __future__ import annotations

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

from __future__ import annotations

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

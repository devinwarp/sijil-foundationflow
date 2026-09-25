"""Model content digest: SHA-256 of the model weights file served by the runtime.

LM Studio's API does not report a content digest, so Sijill computes one from
the GGUF file on disk and caches it keyed by (path, size, mtime). A model whose
weights cannot be located gets an empty digest, which no allowlist contains.
"""

import hashlib
import json
import os
from pathlib import Path


def default_models_dir() -> Path:
    if os.environ.get("SIJILL_MODELS_DIR"):
        return Path(os.environ["SIJILL_MODELS_DIR"]).expanduser()
    settings = Path("~/.lmstudio/settings.json").expanduser()
    try:
        folder = json.loads(settings.read_text()).get("downloadsFolder")
        if folder:
            return Path(folder)
    except (OSError, ValueError):
        pass
    return Path("~/.lmstudio/models").expanduser()


class DigestResolver:
    def __init__(self, models_dir: Path | None = None, cache_path: str | Path = ".sijill_digests.json"):
        self.models_dir = models_dir or default_models_dir()
        self.cache_path = Path(cache_path)
        try:
            self.cache = json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            self.cache = {}
        self.paths: dict[str, Path | None] = {}

    def find_weights(self, model_id: str) -> Path | None:
        stem = model_id.rsplit("/", 1)[-1].lower()
        if not stem or not self.models_dir.is_dir():
            return None
        matches = sorted(p for p in self.models_dir.rglob("*.gguf") if p.name.lower().startswith(stem))
        return matches[0] if matches else None

    def resolve(self, model_id: str) -> str:
        """Blocking: hashes a multi-GB file the first time it is seen. Call from a worker thread.
        Re-stats the file on every call, so a weights file replaced in place gets a new digest."""
        if model_id not in self.paths:
            self.paths[model_id] = self.find_weights(model_id)
        path = self.paths[model_id]
        if not path or not path.exists():
            return ""
        st = path.stat()
        key = f"{path}|{st.st_size}|{st.st_mtime_ns}"
        if key not in self.cache:
            h = hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 22), b""):
                    h.update(chunk)
            self.cache[key] = f"sha256:{h.hexdigest()}"
            self.cache_path.write_text(json.dumps(self.cache, indent=2))
        return self.cache[key]

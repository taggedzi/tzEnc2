# src/mypackage/config.py
import json
from pathlib import Path
from src.tzEnc2 import CONFIG_DIR

CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_CONFIG = { }

def load_config(file_path: Path = CONFIG_FILE) -> dict:
    """Load project config from a JSON file or return defaults."""
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_CONFIG, **data}  # override defaults
        except Exception as e:
            raise RuntimeError(f"Failed to load config: {e}") from e
    return DEFAULT_CONFIG

# Optional: expose a singleton config object
CONFIG = load_config()

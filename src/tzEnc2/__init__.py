# src/mypackage/__init__.py
from pathlib import Path

# Base project path
BASE_DIR = Path(__file__).parent

# Static sub-paths
CONFIG_DIR = BASE_DIR.parent.parent / "config"
DOCS_DIR = BASE_DIR.parent.parent / "docs"
TEST_DIR = BASE_DIR.parent.parent / "test"

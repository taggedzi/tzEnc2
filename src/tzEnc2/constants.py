# src/tzEnc2/__init__.py
import pickle
from pathlib import Path

# Base project path
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASE_DIR = Path(__file__).parent

# Static sub-paths
ASSETS_DIR = PROJECT_ROOT / "assets"
CONFIG_DIR = PROJECT_ROOT / "config"
DOCS_DIR = PROJECT_ROOT / "docs"
LOGS_DIR = PROJECT_ROOT / "logs"
TEST_DIR = PROJECT_ROOT / "test"


# Load Character list
CHARACTER_BLOCK_FILE = ASSETS_DIR / 'character_chunks_256a.pkl'
CHARACTER_BLOCKS = None

with open(CHARACTER_BLOCK_FILE, "rb") as f:
    # Build character (blocks) that are allowed.
    CHARACTER_BLOCKS = pickle.load(f)

# build a single big set allowed characters -> used to test for allowed chars.
CHARACTER_SET = set().union(*CHARACTER_BLOCKS)

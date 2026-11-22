import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Must be set before `app` is imported: Settings reads the environment at import time.
_tmp = tempfile.mkdtemp(prefix="vulnscan-test-")
os.environ["DATA_DIR"] = _tmp
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp}/test.db"

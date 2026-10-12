"""Shared local configuration. No network access or credential handling."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get('NETCHECKER_DATABASE', str(BASE_DIR / 'data/netchecker.db'))).expanduser()
if not DATABASE_PATH.is_absolute():
    DATABASE_PATH = BASE_DIR / DATABASE_PATH


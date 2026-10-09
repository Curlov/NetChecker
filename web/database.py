
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Absoluter Pfad zur bestehenden Datenbank
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "netchecker.db"


@contextmanager
def get_connection():
    # SQLite ausschließlich lesend öffnen
    connection = sqlite3.connect(
        f"file:{DB_PATH.as_posix()}?mode=ro",
        uri=True,
        timeout=5
    )

    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")

        yield connection

    finally:
        connection.close()

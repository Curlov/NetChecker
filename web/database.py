
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from fastapi import HTTPException
from runtime_config import DATABASE_PATH
from schema import SCHEMA_VERSION, validate_schema

# Absoluter Pfad zur bestehenden Datenbank
DB_PATH = DATABASE_PATH


@contextmanager
def get_connection():
    # SQLite ausschließlich lesend öffnen
    try:
        connection = sqlite3.connect(DB_PATH.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail='Inventardatenbank nicht verfügbar') from error

    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        if version != SCHEMA_VERSION:
            raise HTTPException(status_code=503, detail='Datenbankschema muss vor dem API-Betrieb migriert werden')
        try:
            validate_schema(connection)
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail='Inventardatenbankschema unvollständig') from error

        yield connection

    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail='Inventardatenbank konnte nicht gelesen werden') from error

    finally:
        connection.close()


@contextmanager
def get_write_connection():
    """Open the existing inventory database for small, explicit API writes."""
    try:
        connection = sqlite3.connect(
            DB_PATH.resolve().as_uri() + '?mode=rw', uri=True, timeout=5
        )
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail='Inventardatenbank nicht verfügbar') from error

    try:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys = ON')
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        if version != SCHEMA_VERSION:
            raise HTTPException(status_code=503, detail='Datenbankschema muss vor dem API-Betrieb migriert werden')
        try:
            validate_schema(connection)
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail='Inventardatenbankschema unvollständig') from error

        yield connection
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except sqlite3.Error as error:
        connection.rollback()
        raise HTTPException(status_code=503, detail='Änderung konnte nicht gespeichert werden') from error
    finally:
        connection.close()

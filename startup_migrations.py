"""Safe, observable schema upgrades performed before a process starts work."""
from datetime import datetime, timezone
from pathlib import Path
import secrets
import sqlite3

from logging_utils import event
from runtime_lock import inventory_lock
from schema import SCHEMA_VERSION, initialize_database, schema_repair_needed, validate_schema

def _has_application_tables(connection):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' LIMIT 1"
    ).fetchone() is not None


def _backup_path(database_path, from_version):
    now = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    suffix = secrets.token_hex(3)
    return database_path.with_name(
        f'{database_path.name}.pre-migration-v{from_version}-to-v{SCHEMA_VERSION}-'
        f'{now}-{suffix}.bak'
    )


def migrate_connection_for_startup(connection, database_path, *, component):
    """Migrate an existing connection while its database inventory lock is held.

    Existing databases with application tables are backed up and integrity
    checked before schema code can change them. The returned metadata is useful
    to tests and startup logs; a valid current schema creates no backup.
    """
    if connection.in_transaction:
        raise RuntimeError('Startup migration requires a connection without pending writes')

    path = Path(database_path).expanduser().resolve()
    connected_path = connection.execute('PRAGMA database_list').fetchone()[2]
    if connected_path and Path(connected_path).resolve() != path:
        raise RuntimeError('Startup migration path does not match the open SQLite database')

    from_version = connection.execute('PRAGMA user_version').fetchone()[0]
    if from_version > SCHEMA_VERSION:
        raise RuntimeError(
            f'Database schema v{from_version} is newer than this NetChecker version '
            f'(v{SCHEMA_VERSION}); refusing to modify it'
        )
    if from_version == SCHEMA_VERSION:
        try:
            validate_schema(connection)
        except RuntimeError:
            # A database can have a current user_version while a required
            # additive migration was skipped or only partly deployed.
            if not schema_repair_needed(connection):
                raise RuntimeError(
                    f'Database schema v{from_version} is incomplete; required migrations '
                    f'must be completed before {component} can start'
                ) from None
        else:
            return {'from_version': from_version, 'to_version': SCHEMA_VERSION, 'backup_path': None}

    backup_path = None
    if _has_application_tables(connection):
        # Reuse the same SQLite online-backup implementation as the explicit
        # maintenance command. It refuses to overwrite and verifies the copy.
        from maintenance import backup_database

        backup_path = _backup_path(path, from_version)
        event(
            'schema_migration_started', component=component,
            from_version=from_version, to_version=SCHEMA_VERSION,
            backup_path=str(backup_path),
        )
        try:
            backup_database(path, backup_path)
        except Exception as error:
            event(
                'schema_migration_backup_failed', component=component,
                from_version=from_version, to_version=SCHEMA_VERSION,
                backup_path=str(backup_path), error=str(error),
            )
            raise RuntimeError(
                f'Schema migration stopped before changing the database because its '
                f'backup could not be verified: {backup_path}'
            ) from None
    else:
        event(
            'schema_initialization_started', component=component,
            from_version=from_version, to_version=SCHEMA_VERSION,
            empty_database=True,
        )

    try:
        initialize_database(connection)
        applied_version = connection.execute('PRAGMA user_version').fetchone()[0]
        if applied_version != SCHEMA_VERSION:
            raise RuntimeError(
                f'Migration ended at schema v{applied_version}, expected v{SCHEMA_VERSION}'
            )
        validate_schema(connection)
    except Exception as error:
        backup_note = f' Verified pre-migration backup: {backup_path}.' if backup_path else ''
        event(
            'schema_migration_failed', component=component,
            from_version=from_version, to_version=SCHEMA_VERSION,
            backup_path=str(backup_path) if backup_path else None,
            rollback=True, error_type=type(error).__name__, error=str(error),
        )
        raise RuntimeError(
            f'Schema migration/validation from v{from_version} to v{SCHEMA_VERSION} '
            f'failed before {component} could start; the SQLite transaction was '
            f'rolled back.{backup_note} Details: {error}'
        ) from error

    event(
        'schema_migration_completed', component=component,
        from_version=from_version, to_version=SCHEMA_VERSION,
        backup_path=str(backup_path) if backup_path else None,
    )
    return {
        'from_version': from_version,
        'to_version': SCHEMA_VERSION,
        'backup_path': str(backup_path) if backup_path else None,
    }


def migrate_database_for_startup(database_path, *, component):
    """Open and upgrade a database under the shared writer lock.

    Uses mode=rw so a misspelled or missing API database path cannot silently
    create an empty inventory and appear healthy.
    """
    path = Path(database_path).expanduser().resolve()
    with inventory_lock(database_path=path):
        try:
            connection = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=30)
        except sqlite3.Error as error:
            raise RuntimeError(f'Cannot open existing NetChecker database at {path}: {error}') from error
        try:
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA busy_timeout=30000')
            connection.execute('PRAGMA foreign_keys=ON')
            return migrate_connection_for_startup(connection, path, component=component)
        finally:
            connection.close()

"""Explicit local maintenance. No scans, subprocesses or service operations."""
import argparse
import json
import os
import sqlite3
from pathlib import Path
from schema import initialize_database, SCHEMA_VERSION
from runtime_config import DATABASE_PATH
from runtime_lock import inventory_lock


def readonly(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    return connection


def backup_database(source, destination):
    """SQLite backup includes committed WAL contents; existing files are refused."""
    target = Path(destination).resolve()
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        origin = readonly(source)
        archive = sqlite3.connect(target)
        try:
            origin.backup(archive)
            if archive.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Archive integrity check failed')
            if archive.execute('PRAGMA foreign_key_check').fetchone():
                raise RuntimeError('Archive contains foreign key violations')
        finally:
            archive.close()
            origin.close()
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


def export_scope(source, destination, scope_id):
    """Export one customer/site as local JSON Lines with complete scoped history."""
    connection = readonly(source)
    target = Path(destination)
    try:
        connection.execute('BEGIN')
        if not connection.execute('SELECT 1 FROM network_scopes WHERE id=?', (scope_id,)).fetchone():
            raise ValueError('Unknown scope')
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        with target.open('x', encoding='utf-8') as stream:
            os.chmod(target, 0o600)
            stream.write(json.dumps({'format':'netchecker.scope.v1', 'schema_version':connection.execute('PRAGMA user_version').fetchone()[0], 'scope_id':scope_id})+'\n')
            for table in tables:
                columns = {row['name'] for row in connection.execute(f'PRAGMA table_info({table})')}
                if table == 'network_scopes':
                    clause = 'id=?'
                elif 'scope_id' in columns:
                    clause = 'scope_id=?'
                elif 'network_id' in columns:
                    clause = 'network_id IN (SELECT id FROM networks WHERE scope_id=?)'
                elif 'snapshot_id' in columns:
                    clause = 'snapshot_id IN (SELECT s.id FROM topology_snapshots s JOIN networks n ON n.id=s.network_id WHERE n.scope_id=?)'
                elif 'device_id' in columns:
                    clause = 'device_id IN (SELECT id FROM devices WHERE scope_id=?)'
                else:
                    continue
                for row in connection.execute(f'SELECT * FROM {table} WHERE {clause}', (scope_id,)):
                    # Legacy cross-scope identity references must not leak another customer.
                    for field in ('device_id','candidate_device_id','device_id_a','device_id_b','source_device_id','target_device_id','attachment_device_id','router_device_id'):
                        if field in columns and row[field] is not None:
                            owner = connection.execute('SELECT scope_id FROM devices WHERE id=?',(row[field],)).fetchone()
                            if owner is None or owner[0] != scope_id:
                                raise RuntimeError('Cross-scope reference prevents safe export')
                    stream.write(json.dumps({'table':table,'row':dict(row)},ensure_ascii=False)+'\n')
        return target
    except BaseException:
        # Never delete a pre-existing archive on an exclusive-open failure.
        if 'stream' in locals():
            target.unlink(missing_ok=True)
        raise
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['inspect','init','backup','export-scope','create-scope'])
    parser.add_argument('--database', required=True)
    parser.add_argument('--out')
    parser.add_argument('--scope', type=int)
    parser.add_argument('--allow-production', action='store_true')
    parser.add_argument('--customer')
    parser.add_argument('--site')
    parser.add_argument('--name')
    args = parser.parse_args()
    if args.operation in {'init','create-scope'}:
        path = Path(args.database).resolve()
        if path == DATABASE_PATH.resolve() and not args.allow_production:
            parser.error('Produktive Initialisierung/Migration benötigt --allow-production und Betriebsfreigabe')
        if args.operation == 'create-scope' and not all(value and value.strip() for value in (args.customer,args.site,args.name)):
            parser.error('create-scope benötigt --customer, --site und --name')
        with inventory_lock(database_path=path):
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            try:
                initialize_database(connection)
                if args.operation == 'create-scope':
                    with connection:
                        connection.execute('INSERT INTO network_scopes(name,customer,site) VALUES(?,?,?) '
                            'ON CONFLICT(customer,site) DO UPDATE SET name=excluded.name',
                            (args.name.strip(),args.customer.strip(),args.site.strip()))
            finally:
                connection.close()
        print('Bereich bereit' if args.operation == 'create-scope' else f'Schema bereit: {SCHEMA_VERSION}')
    elif args.operation == 'inspect':
        connection = readonly(args.database)
        try:
            print(json.dumps({'schema_version':connection.execute('PRAGMA user_version').fetchone()[0],
                              'foreign_key_errors':len(connection.execute('PRAGMA foreign_key_check').fetchall())}))
        finally:
            connection.close()
    else:
        if not args.out:
            parser.error('--out erforderlich')
        if args.operation == 'export-scope':
            if args.scope is None:
                parser.error('--scope erforderlich')
            export_scope(args.database,args.out,args.scope)
        else:
            backup_database(args.database,args.out)
        print('Lokales Archiv erstellt')


if __name__ == '__main__':
    main()

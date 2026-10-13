"""Central, versioned schema setup. No scanner or network imports."""

def get_table_columns(
    connection,
    table_name
):
    """
    Liefert alle vorhandenen Spalten einer Tabelle.
    """

    return {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table_name})"
        )
    }

def _init_base_tables(connection):
    """
    Erstellt alle Tabellen.

    Bereits vorhandene Datenbanken bleiben erhalten.
    Fehlende ältere Spalten werden automatisch ergänzt.
    """

    execute_script(connection,
        """
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            cidr TEXT NOT NULL,
            interface TEXT NOT NULL,
            gateway TEXT,

            first_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(cidr, interface)
        );


        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            mac TEXT UNIQUE,
            vendor TEXT,
            hostname TEXT,

            identity_status TEXT NOT NULL
                DEFAULT 'provisional',

            first_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        );


        CREATE TABLE IF NOT EXISTS addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,

            ip TEXT NOT NULL,

            first_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(device_id)
                REFERENCES devices(id),

            FOREIGN KEY(network_id)
                REFERENCES networks(id),

            UNIQUE(
                device_id,
                network_id,
                ip
            )
        );


        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER NOT NULL,

            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,

            state TEXT,

            service TEXT,
            product TEXT,
            version TEXT,

            first_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_seen TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(device_id)
                REFERENCES devices(id),

            UNIQUE(
                device_id,
                protocol,
                port
            )
        );


        CREATE TABLE IF NOT EXISTS os_information (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER NOT NULL,

            name TEXT,
            accuracy INTEGER,
            source TEXT,

            observed_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(device_id)
                REFERENCES devices(id)
        );


        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            network_id INTEGER NOT NULL,

            scan_type TEXT NOT NULL,

            status TEXT NOT NULL
                DEFAULT 'running',

            started_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            finished_at TEXT,

            hosts_found INTEGER,
            hosts_processed INTEGER,
            hosts_failed INTEGER,

            error_message TEXT,

            FOREIGN KEY(network_id)
                REFERENCES networks(id)
        );


        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            network_id INTEGER,
            device_id INTEGER,
            scan_run_id INTEGER,

            observation_type TEXT NOT NULL,
            source TEXT,
            data_json TEXT,

            observed_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(network_id)
                REFERENCES networks(id),

            FOREIGN KEY(device_id)
                REFERENCES devices(id),

            FOREIGN KEY(scan_run_id)
                REFERENCES scan_runs(id)
        );


        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            network_id INTEGER NOT NULL,
            device_id INTEGER,
            scan_run_id INTEGER NOT NULL,

            change_type TEXT NOT NULL,

            old_value_json TEXT,
            new_value_json TEXT,

            detected_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(network_id)
                REFERENCES networks(id),

            FOREIGN KEY(device_id)
                REFERENCES devices(id),

            FOREIGN KEY(scan_run_id)
                REFERENCES scan_runs(id)
        );


        CREATE TABLE IF NOT EXISTS device_presence (
            network_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,

            state TEXT NOT NULL
                DEFAULT 'present',

            consecutive_misses INTEGER NOT NULL
                DEFAULT 0,

            last_seen_scan_run_id INTEGER,

            missing_since_scan_run_id INTEGER,

            updated_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY(
                network_id,
                device_id
            ),

            FOREIGN KEY(network_id)
                REFERENCES networks(id),

            FOREIGN KEY(device_id)
                REFERENCES devices(id),

            FOREIGN KEY(last_seen_scan_run_id)
                REFERENCES scan_runs(id),

            FOREIGN KEY(missing_since_scan_run_id)
                REFERENCES scan_runs(id)
        );


        CREATE INDEX IF NOT EXISTS
            idx_devices_mac
        ON devices(mac);


        CREATE INDEX IF NOT EXISTS
            idx_addresses_ip
        ON addresses(ip);


        CREATE INDEX IF NOT EXISTS
            idx_observations_time
        ON observations(observed_at);


        CREATE INDEX IF NOT EXISTS
            idx_changes_time
        ON changes(detected_at);


        CREATE INDEX IF NOT EXISTS
            idx_changes_device
        ON changes(device_id);


        CREATE INDEX IF NOT EXISTS
            idx_changes_scan_run
        ON changes(scan_run_id);


        CREATE INDEX IF NOT EXISTS
            idx_device_presence_state
        ON device_presence(
            network_id,
            state
        );
        """    
    )


    # ======================================================
    # Migration älterer Datenbanken
    # ======================================================

    device_columns = get_table_columns(
        connection,
        "devices"
    )

    if "identity_status" not in device_columns:

        connection.execute(
            """
            ALTER TABLE devices
            ADD COLUMN identity_status TEXT
            NOT NULL DEFAULT 'provisional'
            """
        )


    connection.execute(
        """
        UPDATE devices
        SET identity_status = 'confirmed'
        WHERE mac IS NOT NULL
        """
    )


    observation_columns = get_table_columns(
        connection,
        "observations"
    )

    if "scan_run_id" not in observation_columns:

        connection.execute(
            """
            ALTER TABLE observations
            ADD COLUMN scan_run_id INTEGER
            REFERENCES scan_runs(id)
            """
        )


    scan_run_columns = get_table_columns(
        connection,
        "scan_runs"
    )

    if "hosts_processed" not in scan_run_columns:

        connection.execute(
            """
            ALTER TABLE scan_runs
            ADD COLUMN hosts_processed INTEGER
            """
        )


    if "hosts_failed" not in scan_run_columns:

        connection.execute(
            """
            ALTER TABLE scan_runs
            ADD COLUMN hosts_failed INTEGER
            """
        )


    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_addresses_lookup
        ON addresses(
            network_id,
            ip,
            last_seen
        )
        """
    )


    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_observations_scan_run
        ON observations(scan_run_id)
        """
    )




def init_classification_tables(connection):
    """
    Erstellt:

    device_classifications
        Aktueller Klassifikationsstand.

    classification_history
        Historie aller echten Änderungen.
    """

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS device_classifications (
            network_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,

            category TEXT NOT NULL,
            subtype TEXT,
            confidence INTEGER NOT NULL,
            score INTEGER NOT NULL,

            evidence_json TEXT NOT NULL,

            source TEXT NOT NULL
                DEFAULT 'classifier',

            first_classified_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_classified_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_changed_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (
                network_id,
                device_id
            ),

            FOREIGN KEY (network_id)
                REFERENCES networks(id),

            FOREIGN KEY (device_id)
                REFERENCES devices(id)
        )
        """
    )


    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS classification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            network_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,

            category TEXT NOT NULL,
            subtype TEXT,
            confidence INTEGER NOT NULL,
            score INTEGER NOT NULL,

            evidence_json TEXT NOT NULL,

            source TEXT NOT NULL
                DEFAULT 'classifier',

            classified_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (network_id)
                REFERENCES networks(id),

            FOREIGN KEY (device_id)
                REFERENCES devices(id)
        )
        """
    )


    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_classification_history_device

        ON classification_history (
            network_id,
            device_id,
            classified_at
        )
        """
    )




def init_enrichment_status_table(connection):
    """
    Speichert pro Gerät den bisherigen Enrichment-Zustand.

    So scannen wir Geräte nicht immer wieder neu,
    wenn LIGHT und DEEP bereits erfolglos waren.
    """

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS enrichment_status (
            network_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,

            status TEXT NOT NULL,

            light_attempted INTEGER NOT NULL DEFAULT 0,
            deep_attempted INTEGER NOT NULL DEFAULT 0,

            last_stage TEXT,
            last_result TEXT,

            last_os_name TEXT,
            last_os_accuracy INTEGER,

            last_attempted_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            updated_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (
                network_id,
                device_id
            ),

            FOREIGN KEY (network_id)
                REFERENCES networks(id),

            FOREIGN KEY (device_id)
                REFERENCES devices(id)
        )
        """
    )



def ensure_column(connection, table: str, column: str, definition: str) -> None:
    columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in columns:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )

def init_topology_database(connection) -> None:
    """
    Erweitert die vorhandene NetChecker-Datenbank um die Topologie-Tabellen.

    Die alten Phase-3-Tabellen bleiben erhalten. Zusaetzlich speichern wir
    Rohdaten/Evidenz, Segmente, Interfaces, Beziehungen, Policies und
    Identitaets-Kandidaten.
    """

    execute_script(connection,
        """
        CREATE TABLE IF NOT EXISTS topology_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER NOT NULL,
            interface TEXT NOT NULL,
            gateway TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(network_id) REFERENCES networks(id)
        );

        CREATE TABLE IF NOT EXISTS topology_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            destination TEXT,
            gateway TEXT,
            interface TEXT,
            protocol TEXT,
            scope TEXT,
            metric INTEGER,
            preferred_source TEXT,
            raw_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id)
        );

        CREATE TABLE IF NOT EXISTS topology_neighbors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            device_id INTEGER,
            ip TEXT,
            mac TEXT,
            interface TEXT,
            state TEXT,
            raw_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_routeros_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            router_device_id INTEGER,
            router_ip TEXT NOT NULL,
            dataset TEXT NOT NULL,
            item_index INTEGER NOT NULL,
            raw_json TEXT NOT NULL,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(router_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_segments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            segment_name TEXT,
            cidr TEXT,
            segment_type TEXT NOT NULL,
            bridge_name TEXT,
            gateway_ip TEXT,
            router_device_id INTEGER,
            router_ip TEXT,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            raw_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(router_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            device_id INTEGER,
            owner_ip TEXT,
            interface_name TEXT NOT NULL,
            interface_type TEXT,
            bridge_name TEXT,
            mac TEXT,
            state TEXT,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            raw_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            source_device_id INTEGER,
            source_ip TEXT,
            source_interface TEXT,
            target_device_id INTEGER,
            target_ip TEXT,
            target_mac TEXT,
            target_interface TEXT,
            relation TEXT NOT NULL,
            evidence_source TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            evidence_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(source_device_id) REFERENCES devices(id),
            FOREIGN KEY(target_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            router_device_id INTEGER,
            router_ip TEXT,
            policy_type TEXT NOT NULL,
            rule_order INTEGER,
            chain_name TEXT,
            action TEXT,
            src_cidr TEXT,
            dst_cidr TEXT,
            in_interface TEXT,
            out_interface TEXT,
            comment TEXT,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            raw_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(router_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_endpoint_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            device_id INTEGER,
            hostname TEXT,
            identity_hint TEXT,
            ip TEXT,
            mac TEXT,
            network_cidr TEXT,
            bridge_name TEXT,
            attachment_device_id INTEGER,
            attachment_ip TEXT,
            attachment_interface TEXT,
            state TEXT,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            evidence_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(device_id) REFERENCES devices(id),
            FOREIGN KEY(attachment_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_identity_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            hostname TEXT NOT NULL,
            device_id_a INTEGER,
            ip_a TEXT,
            mac_a TEXT,
            device_id_b INTEGER,
            ip_b TEXT,
            mac_b TEXT,
            confidence INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'candidate',
            evidence_json TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES topology_snapshots(id),
            FOREIGN KEY(device_id_a) REFERENCES devices(id),
            FOREIGN KEY(device_id_b) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS topology_device_hints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            subtype TEXT,
            manufacturer TEXT,
            model TEXT,
            confidence INTEGER NOT NULL,
            source TEXT NOT NULL,
            source_device_id INTEGER,
            source_ip TEXT,
            observed_ip TEXT,
            observed_mac TEXT,
            identity TEXT,
            platform TEXT,
            system_description TEXT,
            evidence_json TEXT,
            first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(device_id) REFERENCES devices(id),
            FOREIGN KEY(network_id) REFERENCES networks(id),
            FOREIGN KEY(source_device_id) REFERENCES devices(id),
            UNIQUE(device_id, network_id, source)
        );

        CREATE TABLE IF NOT EXISTS topology_classification_reconciliations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            hint_id INTEGER,
            old_category TEXT,
            old_subtype TEXT,
            old_confidence INTEGER,
            new_category TEXT NOT NULL,
            new_subtype TEXT,
            new_confidence INTEGER NOT NULL,
            reason TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(device_id) REFERENCES devices(id),
            FOREIGN KEY(network_id) REFERENCES networks(id),
            FOREIGN KEY(hint_id) REFERENCES topology_device_hints(id)
        );

        CREATE INDEX IF NOT EXISTS idx_topology_routeros_snapshot
            ON topology_routeros_records(snapshot_id, dataset);

        CREATE INDEX IF NOT EXISTS idx_topology_segments_snapshot
            ON topology_segments(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_topology_interfaces_snapshot
            ON topology_interfaces(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_topology_links_snapshot
            ON topology_links(snapshot_id, relation);

        CREATE INDEX IF NOT EXISTS idx_topology_policies_snapshot
            ON topology_policies(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_topology_endpoint_snapshot
            ON topology_endpoint_interfaces(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_topology_endpoint_mac
            ON topology_endpoint_interfaces(mac);

        CREATE INDEX IF NOT EXISTS idx_topology_endpoint_ip
            ON topology_endpoint_interfaces(ip);

        CREATE INDEX IF NOT EXISTS idx_topology_identity_snapshot
            ON topology_identity_candidates(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_topology_device_hints_device
            ON topology_device_hints(device_id, network_id, confidence);

        CREATE INDEX IF NOT EXISTS idx_topology_device_hints_seen
            ON topology_device_hints(last_seen);

        CREATE INDEX IF NOT EXISTS idx_topology_reconcile_device
            ON topology_classification_reconciliations(device_id, network_id, applied_at);
        """
    )

    # Migration fuer bereits existierende Phase-3-Datenbanken.
    ensure_column(connection, "topology_snapshots", "status", "TEXT NOT NULL DEFAULT 'running'")
    ensure_column(connection, "topology_snapshots", "completed_at", "TEXT")
    ensure_column(connection, "topology_snapshots", "error_message", "TEXT")
    ensure_column(connection, "topology_snapshots", "source_summary_json", "TEXT")
    ensure_column(connection, "topology_routes", "route_type", "TEXT")
    ensure_column(connection, "topology_routes", "evidence_source", "TEXT")
    ensure_column(connection, "topology_neighbors", "evidence_source", "TEXT")
    ensure_column(
        connection,
        "topology_identity_candidates",
        "candidate_type",
        "TEXT NOT NULL DEFAULT 'same_hostname_different_mac'",
    )



SCHEMA_VERSION = 8

REQUIRED_TABLES = {
    'networks', 'devices', 'addresses', 'ports', 'os_information', 'scan_runs',
    'observations', 'changes', 'device_presence', 'device_classifications',
    'classification_history', 'enrichment_status', 'network_scopes',
    'device_interfaces', 'local_identity_keys', 'topology_history_progress',
    'port_inventory', 'os_claims', 'identity_candidates', 'schema_migrations',
    'topology_snapshots', 'topology_routes', 'topology_neighbors',
    'topology_routeros_records', 'topology_segments', 'topology_interfaces',
    'topology_links', 'topology_policies', 'topology_endpoint_interfaces',
    'topology_identity_candidates', 'topology_device_hints',
    'topology_classification_reconciliations', 'topology_layouts',
    'topology_layout_positions', 'topology_manual_nodes', 'topology_layout_links',
    'topology_rooms', 'topology_room_devices', 'topology_room_manual_nodes',
}


def validate_schema(connection):
    present = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = REQUIRED_TABLES - present
    if missing:
        raise RuntimeError('Incomplete database schema: ' + ', '.join(sorted(missing)))

def init_network_scopes(connection):
    execute_script(connection, """
    CREATE TABLE IF NOT EXISTS network_scopes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        customer TEXT NOT NULL, site TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(customer, site)
    );
    INSERT OR IGNORE INTO network_scopes(id,name,customer,site)
        VALUES(1,'Bestehendes Netzwerk','Bestand','Standard');
    """)
    for table in ('networks', 'devices'):
        ensure_column(connection, table, 'scope_id', 'INTEGER NOT NULL DEFAULT 1 REFERENCES network_scopes(id)')
    execute_script(connection, """
    CREATE TABLE IF NOT EXISTS device_interfaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope_id INTEGER NOT NULL REFERENCES network_scopes(id),
        device_id INTEGER NOT NULL REFERENCES devices(id),
        mac TEXT NOT NULL, source TEXT NOT NULL,
        first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(scope_id,mac)
    );
    CREATE TABLE IF NOT EXISTS local_identity_keys (
        scope_id INTEGER NOT NULL REFERENCES network_scopes(id),
        identity_key TEXT NOT NULL,
        device_id INTEGER NOT NULL REFERENCES devices(id),
        PRIMARY KEY(scope_id,identity_key)
    );
    CREATE TABLE IF NOT EXISTS topology_history_progress (
        source_table TEXT PRIMARY KEY, last_id INTEGER NOT NULL DEFAULT 0,
        rule_version INTEGER NOT NULL DEFAULT 1
    );
    """)

def migrate_scoped_uniqueness(connection):
    """Preserve IDs, columns, indexes and sequences when replacing old keys."""
    import re
    for table in ('networks', 'devices'):
        ddl = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
        new_ddl = re.sub(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?["`\[]?' + table + r'["`\]]?',
                         'CREATE TABLE ' + table + '_scoped', ddl, count=1, flags=re.I)
        if table == 'networks':
            new_ddl, replacements = re.subn(r'UNIQUE\s*\(\s*cidr\s*,\s*interface\s*\)',
                                            'UNIQUE(scope_id,cidr,interface)', new_ddl, flags=re.I)
        else:
            new_ddl, replacements = re.subn(r'\bmac\s+TEXT\s+UNIQUE', 'mac TEXT', new_ddl, flags=re.I)
            new_ddl, table_keys = re.subn(r'UNIQUE\s*\(\s*mac\s*\)', 'UNIQUE(scope_id,mac)', new_ddl, flags=re.I)
            if replacements:
                end = new_ddl.rfind(')')
                new_ddl = new_ddl[:end] + ', UNIQUE(scope_id,mac)' + new_ddl[end:]
            replacements += table_keys
        if not replacements:
            raise RuntimeError(f'Unsupported legacy unique key in {table}; migration rolled back')
        indexes = [row[0] for row in connection.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (table,))]
        triggers = [row[0] for row in connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name=? AND sql IS NOT NULL", (table,))]
        sequence = connection.execute('SELECT seq FROM sqlite_sequence WHERE name=?', (table,)).fetchone()
        connection.execute(new_ddl)
        columns = ','.join('"' + row['name'] + '"' for row in connection.execute(f'PRAGMA table_info({table})'))
        connection.execute(f'INSERT INTO {table}_scoped({columns}) SELECT {columns} FROM {table}')
        connection.execute(f'DROP TABLE {table}')
        connection.execute(f'ALTER TABLE {table}_scoped RENAME TO {table}')
        for index in indexes:
            connection.execute(index)
        for trigger in triggers:
            connection.execute(trigger)
        if sequence:
            connection.execute('UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name=?', (sequence[0],table))
    connection.execute("""INSERT OR IGNORE INTO device_interfaces(scope_id,device_id,mac,source,first_seen,last_seen)
        SELECT scope_id,id,mac,'legacy_mac',first_seen,last_seen FROM devices WHERE mac IS NOT NULL AND mac!=''""")

def init_evidence_tables(connection):
    execute_script(connection, """
    CREATE TABLE IF NOT EXISTS port_inventory (
        network_id INTEGER NOT NULL REFERENCES networks(id),
        device_id INTEGER NOT NULL REFERENCES devices(id),
        protocol TEXT NOT NULL, port INTEGER NOT NULL, state TEXT,
        service TEXT, product TEXT, version TEXT, extrainfo TEXT,
        ostype TEXT, devicetype TEXT, tunnel TEXT, method TEXT, conf TEXT,
        cpe_json TEXT NOT NULL DEFAULT '[]', metadata_json TEXT NOT NULL DEFAULT '{}',
        first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        service_observed_at TEXT, source TEXT, scan_run_id INTEGER REFERENCES scan_runs(id),
        PRIMARY KEY(network_id, device_id, protocol, port)
    );
    CREATE TABLE IF NOT EXISTS os_claims (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network_id INTEGER NOT NULL REFERENCES networks(id),
        device_id INTEGER NOT NULL REFERENCES devices(id),
        scan_run_id INTEGER REFERENCES scan_runs(id), kind TEXT NOT NULL,
        value TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL,
        confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL,
        observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_os_claims_device ON os_claims(network_id, device_id, kind);
    CREATE INDEX IF NOT EXISTS idx_observations_inventory
        ON observations(network_id, device_id, observation_type, id);
    CREATE TABLE IF NOT EXISTS identity_candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network_id INTEGER NOT NULL REFERENCES networks(id),
        device_id INTEGER NOT NULL REFERENCES devices(id),
        candidate_device_id INTEGER NOT NULL REFERENCES devices(id),
        scan_run_id INTEGER REFERENCES scan_runs(id),
        reason TEXT NOT NULL, evidence_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'candidate',
        observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(network_id, device_id, candidate_device_id, reason)
    );
    """)

def backfill_service_inventory(connection):
    import json
    from os_analysis import infer_os_claims
    rows = connection.execute("""
        SELECT * FROM observations
        WHERE network_id IS NOT NULL AND device_id IS NOT NULL
          AND observation_type IN ('tcp_port_scan', 'service_scan', 'enrichment_result', 'os_detection') ORDER BY id
    """)
    for row in rows:
        try:
            payload = json.loads(row['data_json'] or '{}')
            if not isinstance(payload, dict):
                continue
            ports = payload.get('ports') or []
            for port in ports:
                if not isinstance(port, dict) or not port.get('protocol') or port.get('port') is None:
                    continue
                replay_port(connection, row, port)
            from scan_parser import covered_port
            seen = {(p.get('protocol'),p.get('port')) for p in ports if isinstance(p,dict)}
            for current in connection.execute('SELECT protocol,port,scan_run_id FROM port_inventory '
                'WHERE network_id=? AND device_id=? AND state=\'open\'', (row['network_id'],row['device_id'])).fetchall():
                key = (current['protocol'],current['port'])
                if (key not in seen and (current['scan_run_id'] or 0) <= (row['scan_run_id'] or 0)
                        and covered_port(payload.get('scan_metadata') or {}, *key)):
                    connection.execute('UPDATE port_inventory SET state=\'not_open\',scan_run_id=? '
                        'WHERE network_id=? AND device_id=? AND protocol=? AND port=?',
                        (row['scan_run_id'],row['network_id'],row['device_id'],*key))
            for claim in infer_os_claims(payload.get('os'), ports, payload.get('os_classes') or (),
                                        payload.get('host_scripts') or ()):
                evidence = json.dumps(claim['evidence'], ensure_ascii=False, sort_keys=True)
                if connection.execute('SELECT 1 FROM os_claims WHERE network_id=? AND device_id=? '
                    'AND scan_run_id IS ? AND kind=? AND value=? AND source=? AND evidence_json=?',
                    (row['network_id'],row['device_id'],row['scan_run_id'],claim['kind'],claim['value'],claim['source'],evidence)).fetchone():
                    continue
                connection.execute("""INSERT INTO os_claims(network_id,device_id,scan_run_id,
                    kind,value,source,status,confidence,evidence_json,observed_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""", (row['network_id'],row['device_id'],row['scan_run_id'],
                    claim['kind'],claim['value'],claim['source'],claim['status'],claim['confidence'],
                    evidence,row['observed_at']))
        except (ValueError, TypeError, KeyError):
            # Preserve malformed old observations verbatim; do not invent facts.
            continue


def replay_port(connection, observation, port):
    """Fill historical service gaps without reverting a newer scan projection."""
    import json
    key = (observation['network_id'],observation['device_id'],port['protocol'],int(port['port']))
    existing = connection.execute('SELECT * FROM port_inventory WHERE network_id=? AND device_id=? AND protocol=? AND port=?',key).fetchone()
    newer = existing is None or ((observation['scan_run_id'] or 0),observation['observed_at']) >= (
        existing['scan_run_id'] or 0,existing['last_seen'])
    values = dict(existing) if existing else {}
    fields = ('state','service','product','version','extrainfo','ostype','devicetype','tunnel','method','conf')
    for field in fields:
        incoming = port.get(field)
        if incoming not in (None,'') and (newer or not values.get(field)):
            values[field] = incoming
    for field,incoming,empty in (('cpe_json',json.dumps(port.get('cpe') or []),'[]'),
                                 ('metadata_json',json.dumps(port.get('service_metadata') or {}),'{}')):
        if incoming != empty and (newer or values.get(field,empty) == empty):
            values[field] = incoming
        values.setdefault(field,empty)
    if newer:
        values.update(last_seen=observation['observed_at'],source=observation['source'],scan_run_id=observation['scan_run_id'])
    values['first_seen'] = min(values.get('first_seen',observation['observed_at']),observation['observed_at'])
    if any(port.get(field) for field in ('product','version','extrainfo','ostype','cpe')):
        values['service_observed_at'] = max(values.get('service_observed_at') or '',observation['observed_at'])
    columns = (*fields,'cpe_json','metadata_json','first_seen','last_seen','service_observed_at','source','scan_run_id')
    connection.execute('INSERT INTO port_inventory(network_id,device_id,protocol,port,' + ','.join(columns) +
        ') VALUES(' + ','.join('?' for _ in range(4+len(columns))) + ') '
        'ON CONFLICT(network_id,device_id,protocol,port) DO UPDATE SET ' +
        ','.join(f'{column}=excluded.{column}' for column in columns),
        (*key,*(values.get(column) for column in columns)))

def execute_script(connection, script):
    import sqlite3
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        connection.execute(statement)

def initialize_database(connection):
    if connection.in_transaction:
        raise RuntimeError("Schema setup requires a connection without pending writes")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError("Database schema is newer than this NetChecker version")
    if version == SCHEMA_VERSION:
        validate_schema(connection)
        return
    foreign_keys = connection.execute('PRAGMA foreign_keys').fetchone()[0]
    # Foreign keys must be disabled outside the transaction for SQLite's
    # documented table rebuild procedure; integrity is checked before commit.
    if version < 3:
        connection.execute('PRAGMA foreign_keys=OFF')
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            # Re-read after taking SQLite's writer reservation. Another
            # process may have completed this migration while we were waiting.
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError("Database schema is newer than this NetChecker version")
            if version == SCHEMA_VERSION:
                validate_schema(connection)
                return
            if version < 1:
                _init_base_tables(connection)
            init_classification_tables(connection)
            init_enrichment_status_table(connection)
            init_topology_database(connection)
            init_evidence_tables(connection)
            init_network_scopes(connection)
            if version < 2:
                backfill_service_inventory(connection)
            if version < 3:
                migrate_scoped_uniqueness(connection)
            if version < 4:
                execute_script(connection, """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_claims_lookup
                    ON os_claims(network_id,device_id,observed_at,id);
                CREATE INDEX IF NOT EXISTS idx_addresses_device_network
                    ON addresses(device_id,network_id,last_seen,id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_comparison
                    ON observations(scan_run_id) WHERE observation_type='discovery_comparison';
                """)
                backfill_service_inventory(connection)
            if version < 5:
                execute_script(connection, """
                CREATE TABLE IF NOT EXISTS topology_layouts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network_id INTEGER NOT NULL,
                    name TEXT NOT NULL DEFAULT 'Standard'
                        CHECK(length(trim(name)) > 0),
                    is_default INTEGER NOT NULL DEFAULT 0
                        CHECK(is_default IN (0, 1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(network_id) REFERENCES networks(id)
                        ON DELETE CASCADE,
                    UNIQUE(network_id, name)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS
                    idx_topology_layouts_one_default
                ON topology_layouts(network_id)
                WHERE is_default = 1;

                CREATE TABLE IF NOT EXISTS topology_layout_positions (
                    layout_id INTEGER NOT NULL,
                    device_id INTEGER NOT NULL,
                    grid_x INTEGER NOT NULL CHECK(grid_x BETWEEN -1000000 AND 1000000),
                    grid_y INTEGER NOT NULL CHECK(grid_y BETWEEN -1000000 AND 1000000),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(layout_id, device_id),
                    UNIQUE(layout_id, grid_x, grid_y),
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                        ON DELETE RESTRICT
                );

                CREATE INDEX IF NOT EXISTS
                    idx_topology_layout_positions_device
                ON topology_layout_positions(device_id);
                """)
            if version < 6:
                execute_script(connection, """
                CREATE TABLE IF NOT EXISTS topology_manual_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    layout_id INTEGER NOT NULL,
                    node_type TEXT NOT NULL CHECK(node_type IN (
                        'switch','router','firewall','gateway','access_point',
                        'patchpanel','network','internet','generic'
                    )),
                    label TEXT NOT NULL CHECK(length(trim(label)) BETWEEN 1 AND 120),
                    properties_json TEXT NOT NULL DEFAULT '{}',
                    linked_device_id INTEGER,
                    linked_network_id INTEGER,
                    grid_x INTEGER NOT NULL CHECK(grid_x BETWEEN -1000000 AND 1000000),
                    grid_y INTEGER NOT NULL CHECK(grid_y BETWEEN -1000000 AND 1000000),
                    is_hidden INTEGER NOT NULL DEFAULT 0 CHECK(is_hidden IN (0,1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(linked_device_id) REFERENCES devices(id)
                        ON DELETE SET NULL,
                    FOREIGN KEY(linked_network_id) REFERENCES networks(id)
                        ON DELETE SET NULL,
                    CHECK(node_type='network' OR linked_network_id IS NULL)
                );

                CREATE INDEX IF NOT EXISTS idx_topology_manual_nodes_layout
                    ON topology_manual_nodes(layout_id, is_hidden, id);
                CREATE INDEX IF NOT EXISTS idx_topology_manual_nodes_device
                    ON topology_manual_nodes(linked_device_id);
                CREATE INDEX IF NOT EXISTS idx_topology_manual_nodes_network
                    ON topology_manual_nodes(linked_network_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_manual_network_label
                    ON topology_manual_nodes(layout_id, lower(label))
                    WHERE node_type='network';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_manual_linked_device
                    ON topology_manual_nodes(layout_id, linked_device_id)
                    WHERE linked_device_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_manual_linked_network
                    ON topology_manual_nodes(layout_id, linked_network_id)
                    WHERE linked_network_id IS NOT NULL;

                -- Reserved for later connection editing. Endpoints reference
                -- either a scanned device or a manual node without introducing
                -- fake scanner records or a polymorphic, unchecked ID.
                CREATE TABLE IF NOT EXISTS topology_layout_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    layout_id INTEGER NOT NULL,
                    source_device_id INTEGER,
                    source_manual_node_id INTEGER,
                    target_device_id INTEGER,
                    target_manual_node_id INTEGER,
                    relation TEXT NOT NULL DEFAULT 'manual',
                    properties_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CHECK((source_device_id IS NOT NULL) +
                          (source_manual_node_id IS NOT NULL) = 1),
                    CHECK((target_device_id IS NOT NULL) +
                          (target_manual_node_id IS NOT NULL) = 1),
                    CHECK(NOT (source_device_id IS NOT NULL AND
                               target_device_id IS NOT NULL AND
                               source_device_id=target_device_id)),
                    CHECK(NOT (source_manual_node_id IS NOT NULL AND
                               target_manual_node_id IS NOT NULL AND
                               source_manual_node_id=target_manual_node_id)),
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(source_device_id) REFERENCES devices(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(source_manual_node_id) REFERENCES topology_manual_nodes(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(target_device_id) REFERENCES devices(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(target_manual_node_id) REFERENCES topology_manual_nodes(id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_topology_layout_links_layout
                    ON topology_layout_links(layout_id, id);
                """)
            if version < 7:
                # Persist the canvas's cell size with the layout once rooms are
                # introduced. NULL keeps existing layouts on their original
                # device-count-based spacing until their first room is created.
                layout_columns = {
                    row[1] for row in connection.execute('PRAGMA table_info(topology_layouts)')
                }
                if 'grid_cell_width' not in layout_columns:
                    connection.execute(
                        "ALTER TABLE topology_layouts ADD COLUMN grid_cell_width INTEGER "
                        "CHECK(grid_cell_width IS NULL OR grid_cell_width BETWEEN 1 AND 2000)"
                    )
                if 'grid_cell_height' not in layout_columns:
                    connection.execute(
                        "ALTER TABLE topology_layouts ADD COLUMN grid_cell_height INTEGER "
                        "CHECK(grid_cell_height IS NULL OR grid_cell_height BETWEEN 1 AND 2000)"
                    )
                execute_script(connection, """
                CREATE TABLE IF NOT EXISTS topology_rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    layout_id INTEGER NOT NULL,
                    name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 120),
                    description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 2000),
                    grid_x INTEGER NOT NULL CHECK(grid_x BETWEEN -1000000 AND 1000000),
                    grid_y INTEGER NOT NULL CHECK(grid_y BETWEEN -1000000 AND 1000000),
                    grid_width INTEGER NOT NULL CHECK(grid_width BETWEEN 2 AND 10000),
                    grid_height INTEGER NOT NULL CHECK(grid_height BETWEEN 2 AND 10000),
                    move_contents INTEGER NOT NULL DEFAULT 0 CHECK(move_contents IN (0,1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id) ON DELETE CASCADE,
                    UNIQUE(id,layout_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_rooms_layout_name
                    ON topology_rooms(layout_id,lower(name));
                CREATE INDEX IF NOT EXISTS idx_topology_rooms_layout
                    ON topology_rooms(layout_id,id);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_manual_nodes_id_layout
                    ON topology_manual_nodes(id,layout_id);

                CREATE TABLE IF NOT EXISTS topology_room_devices (
                    layout_id INTEGER NOT NULL,
                    room_id INTEGER NOT NULL,
                    device_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(layout_id,device_id),
                    FOREIGN KEY(room_id,layout_id) REFERENCES topology_rooms(id,layout_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id) ON DELETE CASCADE,
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_topology_room_devices_room
                    ON topology_room_devices(room_id,layout_id);

                CREATE TABLE IF NOT EXISTS topology_room_manual_nodes (
                    layout_id INTEGER NOT NULL,
                    room_id INTEGER NOT NULL,
                    manual_node_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(layout_id,manual_node_id),
                    FOREIGN KEY(room_id,layout_id) REFERENCES topology_rooms(id,layout_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(layout_id) REFERENCES topology_layouts(id) ON DELETE CASCADE,
                    FOREIGN KEY(manual_node_id,layout_id)
                        REFERENCES topology_manual_nodes(id,layout_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_topology_room_manual_nodes_room
                    ON topology_room_manual_nodes(room_id,layout_id);

                CREATE TRIGGER IF NOT EXISTS topology_room_devices_validate_insert
                BEFORE INSERT ON topology_room_devices
                WHEN NOT EXISTS (
                    SELECT 1 FROM topology_layouts l
                    JOIN addresses a ON a.network_id=l.network_id
                    WHERE l.id=NEW.layout_id AND a.device_id=NEW.device_id
                )
                BEGIN
                    SELECT RAISE(ABORT,'device does not belong to room layout network');
                END;
                CREATE TRIGGER IF NOT EXISTS topology_room_devices_validate_update
                BEFORE UPDATE OF layout_id,device_id ON topology_room_devices
                WHEN NOT EXISTS (
                    SELECT 1 FROM topology_layouts l
                    JOIN addresses a ON a.network_id=l.network_id
                    WHERE l.id=NEW.layout_id AND a.device_id=NEW.device_id
                )
                BEGIN
                    SELECT RAISE(ABORT,'device does not belong to room layout network');
                END;
                """)
            if version < 8:
                room_columns = {
                    row[1] for row in connection.execute('PRAGMA table_info(topology_rooms)')
                }
                if 'parent_room_id' not in room_columns:
                    connection.execute(
                        "ALTER TABLE topology_rooms ADD COLUMN parent_room_id INTEGER "
                        "REFERENCES topology_rooms(id) ON DELETE SET NULL "
                        "CHECK(parent_room_id IS NULL OR parent_room_id != id)"
                    )
                execute_script(connection, """
                CREATE INDEX IF NOT EXISTS idx_topology_rooms_parent
                    ON topology_rooms(layout_id,parent_room_id,id);

                CREATE TRIGGER IF NOT EXISTS topology_rooms_parent_validate_insert
                BEFORE INSERT ON topology_rooms
                WHEN NEW.parent_room_id IS NOT NULL AND (
                    NOT EXISTS (
                        SELECT 1 FROM topology_rooms p
                        WHERE p.id=NEW.parent_room_id AND p.layout_id=NEW.layout_id
                    ) OR EXISTS (
                        WITH RECURSIVE descendants(id) AS (
                            SELECT id FROM topology_rooms WHERE parent_room_id=NEW.id
                            UNION
                            SELECT r.id FROM topology_rooms r
                            JOIN descendants d ON r.parent_room_id=d.id
                        )
                        SELECT 1 FROM descendants WHERE id=NEW.parent_room_id
                    )
                )
                BEGIN
                    SELECT RAISE(ABORT,'invalid parent room');
                END;

                CREATE TRIGGER IF NOT EXISTS topology_rooms_parent_validate_update
                BEFORE UPDATE OF parent_room_id,layout_id ON topology_rooms
                WHEN NEW.parent_room_id IS NOT NULL AND (
                    NOT EXISTS (
                        SELECT 1 FROM topology_rooms p
                        WHERE p.id=NEW.parent_room_id AND p.layout_id=NEW.layout_id
                    ) OR EXISTS (
                        WITH RECURSIVE descendants(id) AS (
                            SELECT id FROM topology_rooms WHERE parent_room_id=NEW.id
                            UNION
                            SELECT r.id FROM topology_rooms r
                            JOIN descendants d ON r.parent_room_id=d.id
                        )
                        SELECT 1 FROM descendants WHERE id=NEW.parent_room_id
                    )
                )
                BEGIN
                    SELECT RAISE(ABORT,'invalid parent room');
                END;
                """)
            for migration in range(version + 1, SCHEMA_VERSION + 1):
                connection.execute('INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)', (migration,))
            if connection.execute('PRAGMA foreign_key_check').fetchone():
                raise RuntimeError('Foreign key violation; schema migration rolled back')
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            validate_schema(connection)
    finally:
        connection.execute(f'PRAGMA foreign_keys={foreign_keys}')

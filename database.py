import json
import sqlite3
from pathlib import Path


IP_MATCH_WINDOW_MINUTES = 60

# Erst nach so vielen aufeinanderfolgenden fehlenden
# Discovery-Läufen gilt ein Gerät als verschwunden.
MISSING_CONFIRMATION_SCANS = 2


DATABASE_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "netchecker.db"
)


# ==========================================================
# Datenbankverbindung
# ==========================================================

def get_connection():
    """
    Öffnet die SQLite-Datenbank.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    connection.execute(
        "PRAGMA busy_timeout = 5000"
    )

    return connection


# ==========================================================
# Hilfsfunktionen
# ==========================================================

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


# ==========================================================
# Datenbank initialisieren
# ==========================================================

def init_database(connection):
    """
    Erstellt alle Tabellen.

    Bereits vorhandene Datenbanken bleiben erhalten.
    Fehlende ältere Spalten werden automatisch ergänzt.
    """

    connection.executescript(
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


    connection.commit()


# ==========================================================
# Netzwerk
# ==========================================================

def save_network(
    connection,
    cidr,
    interface,
    gateway
):
    """
    Speichert oder aktualisiert ein Netzwerk.
    """

    connection.execute(
        """
        INSERT INTO networks (
            cidr,
            interface,
            gateway
        )
        VALUES (?, ?, ?)

        ON CONFLICT(cidr, interface)
        DO UPDATE SET
            gateway = excluded.gateway,
            last_seen = CURRENT_TIMESTAMP
        """,
        (
            cidr,
            interface,
            gateway
        )
    )

    connection.commit()


    row = connection.execute(
        """
        SELECT id
        FROM networks

        WHERE cidr = ?
          AND interface = ?
        """,
        (
            cidr,
            interface
        )
    ).fetchone()


    return row["id"]


# ==========================================================
# Geräteidentifikation
# ==========================================================

def find_device_by_mac(
    connection,
    mac_address
):
    """
    Sucht ein Gerät anhand seiner MAC-Adresse.
    """

    if not mac_address:
        return None


    return connection.execute(
        """
        SELECT *
        FROM devices
        WHERE mac = ?
        """,
        (mac_address,)
    ).fetchone()


def get_recent_ip_candidates(
    connection,
    network_id,
    ip_address
):
    """
    Sucht Geräte, die dieselbe IP kürzlich
    im selben Netzwerk benutzt haben.
    """

    if not ip_address:
        return []


    time_window = (
        f"-{IP_MATCH_WINDOW_MINUTES} minutes"
    )


    return connection.execute(
        """
        SELECT
            devices.*,

            addresses.last_seen
                AS address_last_seen

        FROM devices

        JOIN addresses
          ON addresses.device_id = devices.id

        WHERE addresses.network_id = ?
          AND addresses.ip = ?
          AND addresses.last_seen >=
              datetime('now', ?)

        ORDER BY
            addresses.last_seen DESC
        """,
        (
            network_id,
            ip_address,
            time_window
        )
    ).fetchall()


def hostnames_match(
    stored_hostname,
    observed_hostname
):
    """
    Prüft, ob zwei Hostnamen miteinander vereinbar sind.
    """

    if not stored_hostname:
        return True

    if not observed_hostname:
        return True


    return (
        stored_hostname.lower()
        == observed_hostname.lower()
    )


def identify_device(
    connection,
    network_id,
    ip_address,
    mac_address,
    hostname
):
    """
    Ordnet eine Beobachtung einem bekannten Gerät zu.
    """

    if mac_address:

        device = find_device_by_mac(
            connection,
            mac_address
        )

        if device is not None:
            return device, "mac"


        candidates = get_recent_ip_candidates(
            connection,
            network_id,
            ip_address
        )


        provisional_candidates = [
            device
            for device in candidates
            if (
                device["mac"] is None
                and hostnames_match(
                    device["hostname"],
                    hostname
                )
            )
        ]


        if len(provisional_candidates) == 1:

            return (
                provisional_candidates[0],
                "ip_upgrade_to_mac"
            )


        return None, "new_mac"


    candidates = get_recent_ip_candidates(
        connection,
        network_id,
        ip_address
    )


    candidates = [
        device
        for device in candidates
        if hostnames_match(
            device["hostname"],
            hostname
        )
    ]


    if len(candidates) == 1:

        device = candidates[0]

        if device["mac"]:
            return device, "recent_ip"

        return device, "provisional_ip"


    if hostname:

        hostname_matches = [
            device
            for device in candidates
            if (
                device["hostname"]
                and device["hostname"].lower()
                == hostname.lower()
            )
        ]


        if len(hostname_matches) == 1:

            return (
                hostname_matches[0],
                "ip_hostname"
            )


    return None, "new_provisional"


# ==========================================================
# Discovery speichern
# ==========================================================

def save_discovery_host(
    connection,
    network_id,
    scan_run_id,
    host
):
    """
    Speichert einen während Discovery gefundenen Host.
    """

    ip_address = host.get("ip")
    mac_address = host.get("mac")
    vendor = host.get("vendor")
    hostname = host.get("hostname")


    if mac_address:
        mac_address = mac_address.upper()


    with connection:

        device, match_method = identify_device(
            connection,
            network_id,
            ip_address,
            mac_address,
            hostname
        )


        if device is None:

            identity_status = (
                "confirmed"
                if mac_address
                else "provisional"
            )


            cursor = connection.execute(
                """
                INSERT INTO devices (
                    mac,
                    vendor,
                    hostname,
                    identity_status
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    mac_address,
                    vendor,
                    hostname,
                    identity_status
                )
            )


            device_id = cursor.lastrowid


        else:

            device_id = device["id"]


            if (
                device["mac"] is None
                and mac_address
            ):

                connection.execute(
                    """
                    UPDATE devices

                    SET mac = ?,
                        identity_status = 'confirmed'

                    WHERE id = ?
                    """,
                    (
                        mac_address,
                        device_id
                    )
                )


            connection.execute(
                """
                UPDATE devices

                SET vendor = COALESCE(?, vendor),
                    hostname = COALESCE(?, hostname),
                    last_seen = CURRENT_TIMESTAMP

                WHERE id = ?
                """,
                (
                    vendor,
                    hostname,
                    device_id
                )
            )


        if ip_address:

            connection.execute(
                """
                INSERT INTO addresses (
                    device_id,
                    network_id,
                    ip
                )
                VALUES (?, ?, ?)

                ON CONFLICT(
                    device_id,
                    network_id,
                    ip
                )
                DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP
                """,
                (
                    device_id,
                    network_id,
                    ip_address
                )
            )


        observation = {
            "ip": ip_address,
            "mac": mac_address,
            "vendor": vendor,
            "hostname": hostname,
            "match_method": match_method
        }


        connection.execute(
            """
            INSERT INTO observations (
                network_id,
                device_id,
                scan_run_id,
                observation_type,
                source,
                data_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                network_id,
                device_id,
                scan_run_id,
                "host_discovery",
                "nmap",
                json.dumps(
                    observation,
                    ensure_ascii=False
                )
            )
        )


    return device_id


# ==========================================================
# Portscan speichern
# ==========================================================

def save_port_scan(
    connection,
    network_id,
    scan_run_id,
    host
):
    """
    Speichert einen erfolgreichen TCP-Portscan.
    """

    device_id = host.get("device_id")
    ip_address = host.get("ip")
    ports = host.get("ports", [])


    with connection:

        if device_id is not None:

            for port in ports:

                connection.execute(
                    """
                    INSERT INTO ports (
                        device_id,
                        protocol,
                        port,
                        state,
                        service,
                        product,
                        version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)

                    ON CONFLICT(
                        device_id,
                        protocol,
                        port
                    )
                    DO UPDATE SET
                        state = excluded.state,
                        service = excluded.service,
                        product = excluded.product,
                        version = excluded.version,
                        last_seen = CURRENT_TIMESTAMP
                    """,
                    (
                        device_id,
                        port.get("protocol"),
                        port.get("port"),
                        port.get("state"),
                        port.get("service"),
                        port.get("product"),
                        port.get("version")
                    )
                )


        connection.execute(
            """
            INSERT INTO observations (
                network_id,
                device_id,
                scan_run_id,
                observation_type,
                source,
                data_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                network_id,
                device_id,
                scan_run_id,
                "tcp_port_scan",
                "nmap",
                json.dumps(
                    {
                        "ip": ip_address,
                        "ports": ports
                    },
                    ensure_ascii=False
                )
            )
        )


# ==========================================================
# Betriebssystem speichern
# ==========================================================

def save_os_information(
    connection,
    network_id,
    scan_run_id,
    host
):
    """
    Speichert eine OS-Erkennung.
    """

    device_id = host.get("device_id")
    ip_address = host.get("ip")
    os_info = host.get("os")


    with connection:

        if (
            device_id is not None
            and os_info is not None
        ):

            connection.execute(
                """
                INSERT INTO os_information (
                    device_id,
                    name,
                    accuracy,
                    source
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    device_id,
                    os_info.get("name"),
                    os_info.get("accuracy"),
                    os_info.get("source")
                )
            )


        connection.execute(
            """
            INSERT INTO observations (
                network_id,
                device_id,
                scan_run_id,
                observation_type,
                source,
                data_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                network_id,
                device_id,
                scan_run_id,
                "os_detection",
                "nmap",
                json.dumps(
                    {
                        "ip": ip_address,
                        "os": os_info
                    },
                    ensure_ascii=False
                )
            )
        )


# ==========================================================
# Scanläufe
# ==========================================================

def start_scan_run(
    connection,
    network_id,
    scan_type
):
    """
    Startet einen neuen Scanlauf.
    """

    cursor = connection.execute(
        """
        INSERT INTO scan_runs (
            network_id,
            scan_type,
            status
        )
        VALUES (?, ?, 'running')
        """,
        (
            network_id,
            scan_type
        )
    )


    connection.commit()


    return cursor.lastrowid


def finish_scan_run(
    connection,
    scan_run_id,
    hosts_found=None,
    hosts_processed=None,
    hosts_failed=0
):
    """
    Beendet einen Scanlauf.
    """

    status = (
        "completed"
        if hosts_failed == 0
        else "completed_with_errors"
    )


    connection.execute(
        """
        UPDATE scan_runs

        SET status = ?,
            finished_at = CURRENT_TIMESTAMP,
            hosts_found = ?,
            hosts_processed = ?,
            hosts_failed = ?

        WHERE id = ?
        """,
        (
            status,
            hosts_found,
            hosts_processed,
            hosts_failed,
            scan_run_id
        )
    )


    connection.commit()


def abort_scan_run(
    connection,
    scan_run_id
):
    """
    Markiert einen Scan als abgebrochen.
    """

    connection.execute(
        """
        UPDATE scan_runs

        SET status = 'aborted',
            finished_at = CURRENT_TIMESTAMP

        WHERE id = ?
        """,
        (scan_run_id,)
    )


    connection.commit()


def fail_scan_run(
    connection,
    scan_run_id,
    error_message
):
    """
    Markiert einen Scan als fehlgeschlagen.
    """

    connection.execute(
        """
        UPDATE scan_runs

        SET status = 'failed',
            finished_at = CURRENT_TIMESTAMP,
            error_message = ?

        WHERE id = ?
        """,
        (
            str(error_message),
            scan_run_id
        )
    )


    connection.commit()


def recover_interrupted_scan_runs(
    connection
):
    """
    Markiert beim Neustart alte running-Scans
    als interrupted.
    """

    connection.execute(
        """
        UPDATE scan_runs

        SET status = 'interrupted',
            finished_at = COALESCE(
                finished_at,
                CURRENT_TIMESTAMP
            )

        WHERE status = 'running'
        """
    )


    connection.commit()


# ==========================================================
# Discovery-Snapshots
# ==========================================================

def get_discovery_snapshot(
    connection,
    scan_run_id
):
    """
    Liefert alle Geräte eines Discovery-Laufs.
    """

    rows = connection.execute(
        """
        SELECT
            device_id,
            data_json

        FROM observations

        WHERE scan_run_id = ?
          AND observation_type = 'host_discovery'

        ORDER BY id
        """,
        (scan_run_id,)
    ).fetchall()


    snapshot = {}


    for row in rows:

        if row["device_id"] is None:
            continue

        if not row["data_json"]:
            continue


        try:

            data = json.loads(
                row["data_json"]
            )

        except json.JSONDecodeError:
            continue


        snapshot[
            row["device_id"]
        ] = data


    return snapshot


def get_previous_completed_discovery_run(
    connection,
    network_id,
    current_scan_run_id
):
    """
    Liefert den vorherigen erfolgreichen Discovery-Lauf.
    """

    return connection.execute(
        """
        SELECT *

        FROM scan_runs

        WHERE network_id = ?
          AND scan_type = 'discovery'

          AND status IN (
              'completed',
              'completed_with_errors'
          )

          AND id < ?

        ORDER BY id DESC

        LIMIT 1
        """,
        (
            network_id,
            current_scan_run_id
        )
    ).fetchone()


def get_last_discovery_observation_before(
    connection,
    device_id,
    scan_run_id
):
    """
    Liefert die letzte Discovery-Beobachtung eines
    Gerätes vor dem aktuellen Scan.
    """

    row = connection.execute(
        """
        SELECT
            observations.data_json

        FROM observations

        JOIN scan_runs
          ON scan_runs.id =
             observations.scan_run_id

        WHERE observations.device_id = ?

          AND observations.observation_type =
              'host_discovery'

          AND observations.scan_run_id < ?

          AND scan_runs.scan_type =
              'discovery'

          AND scan_runs.status IN (
              'completed',
              'completed_with_errors'
          )

        ORDER BY
            observations.scan_run_id DESC,
            observations.id DESC

        LIMIT 1
        """,
        (
            device_id,
            scan_run_id
        )
    ).fetchone()


    if row is None:
        return None

    if not row["data_json"]:
        return None


    try:

        return json.loads(
            row["data_json"]
        )

    except json.JSONDecodeError:

        return None


# ==========================================================
# Presence-State
# ==========================================================

def get_presence_states(
    connection,
    network_id
):
    """
    Liefert den Anwesenheitsstatus aller bekannten Geräte.
    """

    rows = connection.execute(
        """
        SELECT *

        FROM device_presence

        WHERE network_id = ?
        """,
        (network_id,)
    ).fetchall()


    return {
        row["device_id"]: dict(row)
        for row in rows
    }


def set_device_present(
    connection,
    network_id,
    device_id,
    scan_run_id
):
    """
    Markiert ein Gerät als vorhanden.
    """

    connection.execute(
        """
        INSERT INTO device_presence (
            network_id,
            device_id,
            state,
            consecutive_misses,
            last_seen_scan_run_id,
            missing_since_scan_run_id,
            updated_at
        )
        VALUES (
            ?,
            ?,
            'present',
            0,
            ?,
            NULL,
            CURRENT_TIMESTAMP
        )

        ON CONFLICT(
            network_id,
            device_id
        )
        DO UPDATE SET
            state = 'present',
            consecutive_misses = 0,
            last_seen_scan_run_id =
                excluded.last_seen_scan_run_id,
            missing_since_scan_run_id = NULL,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            network_id,
            device_id,
            scan_run_id
        )
    )


def set_device_miss(
    connection,
    network_id,
    device_id,
    misses,
    state,
    missing_since_scan_run_id=None
):
    """
    Aktualisiert den Missing-Zustand eines Gerätes.
    """

    connection.execute(
        """
        UPDATE device_presence

        SET consecutive_misses = ?,
            state = ?,
            missing_since_scan_run_id = ?,
            updated_at = CURRENT_TIMESTAMP

        WHERE network_id = ?
          AND device_id = ?
        """,
        (
            misses,
            state,
            missing_since_scan_run_id,
            network_id,
            device_id
        )
    )


def seed_presence_from_snapshot(
    connection,
    network_id,
    scan_run_id,
    snapshot
):
    """
    Initialisiert Presence aus einem Discovery-Snapshot.
    """

    for device_id in snapshot:

        set_device_present(
            connection,
            network_id,
            device_id,
            scan_run_id
        )


# ==========================================================
# Änderungen speichern
# ==========================================================

def save_change(
    connection,
    network_id,
    device_id,
    scan_run_id,
    change_type,
    old_value=None,
    new_value=None
):
    """
    Speichert ein erkanntes Netzwerkereignis.
    """

    cursor = connection.execute(
        """
        INSERT INTO changes (
            network_id,
            device_id,
            scan_run_id,
            change_type,
            old_value_json,
            new_value_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            network_id,
            device_id,
            scan_run_id,
            change_type,

            (
                json.dumps(
                    old_value,
                    ensure_ascii=False
                )
                if old_value is not None
                else None
            ),

            (
                json.dumps(
                    new_value,
                    ensure_ascii=False
                )
                if new_value is not None
                else None
            )
        )
    )


    return {
        "id": cursor.lastrowid,
        "network_id": network_id,
        "device_id": device_id,
        "scan_run_id": scan_run_id,
        "change_type": change_type,
        "old": old_value,
        "new": new_value
    }


# ==========================================================
# Discovery-Änderungen
# ==========================================================

def detect_discovery_changes(
    connection,
    network_id,
    scan_run_id
):
    """
    Erkennt:

    NEW_DEVICE
    DEVICE_MISSING
    DEVICE_RETURNED
    IP_CHANGED
    """

    current_snapshot = get_discovery_snapshot(
        connection,
        scan_run_id
    )


    previous_run = (
        get_previous_completed_discovery_run(
            connection,
            network_id,
            scan_run_id
        )
    )


    changes = []
    pending_missing = []


    with connection:

        presence_states = get_presence_states(
            connection,
            network_id
        )


        if not presence_states:

            if previous_run is None:

                seed_presence_from_snapshot(
                    connection,
                    network_id,
                    scan_run_id,
                    current_snapshot
                )


                return {
                    "baseline": True,
                    "previous_scan_run_id": None,
                    "current_scan_run_id": scan_run_id,
                    "changes": [],
                    "pending_missing": []
                }


            previous_scan_run_id = (
                previous_run["id"]
            )


            previous_snapshot = (
                get_discovery_snapshot(
                    connection,
                    previous_scan_run_id
                )
            )


            seed_presence_from_snapshot(
                connection,
                network_id,
                previous_scan_run_id,
                previous_snapshot
            )


            presence_states = get_presence_states(
                connection,
                network_id
            )


        previous_scan_run_id = (
            previous_run["id"]
            if previous_run is not None
            else None
        )


        current_ids = set(
            current_snapshot.keys()
        )


        # ==================================================
        # Aktuell vorhandene Geräte
        # ==================================================

        for device_id in sorted(
            current_ids
        ):

            current_data = (
                current_snapshot[
                    device_id
                ]
            )


            old_data = (
                get_last_discovery_observation_before(
                    connection,
                    device_id,
                    scan_run_id
                )
            )


            presence = presence_states.get(
                device_id
            )


            if presence is None:

                if old_data is None:

                    changes.append(
                        save_change(
                            connection,
                            network_id,
                            device_id,
                            scan_run_id,
                            "NEW_DEVICE",
                            old_value=None,
                            new_value=current_data
                        )
                    )


            elif presence["state"] == "missing":

                changes.append(
                    save_change(
                        connection,
                        network_id,
                        device_id,
                        scan_run_id,
                        "DEVICE_RETURNED",
                        old_value=old_data,
                        new_value=current_data
                    )
                )


            if old_data is not None:

                old_ip = old_data.get(
                    "ip"
                )

                new_ip = current_data.get(
                    "ip"
                )


                if (
                    old_ip
                    and new_ip
                    and old_ip != new_ip
                ):

                    changes.append(
                        save_change(
                            connection,
                            network_id,
                            device_id,
                            scan_run_id,
                            "IP_CHANGED",
                            old_value=old_data,
                            new_value=current_data
                        )
                    )


            set_device_present(
                connection,
                network_id,
                device_id,
                scan_run_id
            )


        # ==================================================
        # Fehlende Geräte
        # ==================================================

        presence_states = get_presence_states(
            connection,
            network_id
        )


        for device_id, presence in (
            presence_states.items()
        ):

            if device_id in current_ids:
                continue


            previous_misses = (
                presence[
                    "consecutive_misses"
                ]
            )


            new_misses = (
                previous_misses + 1
            )


            old_data = (
                get_last_discovery_observation_before(
                    connection,
                    device_id,
                    scan_run_id
                )
            )


            if presence["state"] == "missing":

                set_device_miss(
                    connection,
                    network_id,
                    device_id,
                    new_misses,
                    "missing",
                    presence[
                        "missing_since_scan_run_id"
                    ]
                )

                continue


            if (
                new_misses
                < MISSING_CONFIRMATION_SCANS
            ):

                set_device_miss(
                    connection,
                    network_id,
                    device_id,
                    new_misses,
                    "present",
                    None
                )


                pending_missing.append(
                    {
                        "device_id": device_id,
                        "misses": new_misses,
                        "data": old_data
                    }
                )


                continue


            set_device_miss(
                connection,
                network_id,
                device_id,
                new_misses,
                "missing",
                scan_run_id
            )


            changes.append(
                save_change(
                    connection,
                    network_id,
                    device_id,
                    scan_run_id,
                    "DEVICE_MISSING",
                    old_value=old_data,
                    new_value=None
                )
            )


    return {
        "baseline": False,
        "previous_scan_run_id":
            previous_scan_run_id,
        "current_scan_run_id":
            scan_run_id,
        "changes":
            changes,
        "pending_missing":
            pending_missing
    }


# ==========================================================
# Portscan-Historie
# ==========================================================

def get_current_port_scan_observations(
    connection,
    scan_run_id
):
    """
    Liefert alle erfolgreichen Portscan-Beobachtungen
    eines Detail-Laufs.
    """

    return connection.execute(
        """
        SELECT
            device_id,
            data_json

        FROM observations

        WHERE scan_run_id = ?
          AND observation_type = 'tcp_port_scan'
          AND device_id IS NOT NULL

        ORDER BY id
        """,
        (scan_run_id,)
    ).fetchall()


def get_previous_port_scan_before(
    connection,
    device_id,
    scan_run_id
):
    """
    Liefert den letzten erfolgreichen Portscan
    desselben Geräts vor dem aktuellen Detail-Lauf.
    """

    row = connection.execute(
        """
        SELECT
            observations.data_json,
            observations.scan_run_id

        FROM observations

        JOIN scan_runs
          ON scan_runs.id =
             observations.scan_run_id

        WHERE observations.device_id = ?

          AND observations.observation_type =
              'tcp_port_scan'

          AND observations.scan_run_id < ?

          AND scan_runs.scan_type = 'detail'

          AND scan_runs.status IN (
              'completed',
              'completed_with_errors'
          )

        ORDER BY
            observations.scan_run_id DESC,
            observations.id DESC

        LIMIT 1
        """,
        (
            device_id,
            scan_run_id
        )
    ).fetchone()


    if row is None:
        return None


    if not row["data_json"]:
        return None


    try:

        data = json.loads(
            row["data_json"]
        )

    except json.JSONDecodeError:

        return None


    return {
        "scan_run_id": row["scan_run_id"],
        "data": data
    }


def build_port_map(
    ports
):
    """
    Wandelt eine Portliste in ein Dictionary um.

    Schlüssel:
        (protocol, port)

    Beispiel:
        ("tcp", 22)
    """

    port_map = {}


    for port in ports:

        protocol = (
            port.get("protocol")
            or ""
        )

        port_number = port.get(
            "port"
        )


        if port_number is None:
            continue


        key = (
            protocol,
            int(port_number)
        )


        port_map[key] = port


    return port_map


def service_signature(
    port
):
    """
    Liefert genau die Werte, anhand derer wir
    SERVICE_CHANGED erkennen.
    """

    return (
        port.get("service") or "",
        port.get("product") or "",
        port.get("version") or ""
    )


# ==========================================================
# Detail-Änderungen erkennen
# ==========================================================

def detect_detail_changes(
    connection,
    network_id,
    scan_run_id
):
    """
    Vergleicht jeden erfolgreichen Portscan des
    aktuellen Detail-Laufs mit dem vorherigen
    erfolgreichen Portscan desselben Gerätes.

    Erkennt:

    PORT_OPENED
    PORT_CLOSED
    SERVICE_CHANGED

    Geräte ohne früheren Portscan dienen nur als Baseline.
    """

    current_rows = (
        get_current_port_scan_observations(
            connection,
            scan_run_id
        )
    )


    changes = []

    compared_devices = 0
    baseline_devices = 0


    with connection:

        # Falls die Funktion für denselben Run erneut
        # ausgeführt wird, keine Duplikate erzeugen.
        connection.execute(
            """
            DELETE FROM changes

            WHERE scan_run_id = ?

              AND change_type IN (
                  'PORT_OPENED',
                  'PORT_CLOSED',
                  'SERVICE_CHANGED'
              )
            """,
            (scan_run_id,)
        )


        for row in current_rows:

            device_id = row[
                "device_id"
            ]


            if not row["data_json"]:
                continue


            try:

                current_data = json.loads(
                    row["data_json"]
                )

            except json.JSONDecodeError:

                continue


            previous = (
                get_previous_port_scan_before(
                    connection,
                    device_id,
                    scan_run_id
                )
            )


            # Noch kein älterer Detail-Scan:
            # Dies ist lediglich die Baseline.
            if previous is None:

                baseline_devices += 1
                continue


            compared_devices += 1


            previous_data = previous[
                "data"
            ]


            old_ip = previous_data.get(
                "ip"
            )

            new_ip = current_data.get(
                "ip"
            )


            old_ports = build_port_map(
                previous_data.get(
                    "ports",
                    []
                )
            )


            new_ports = build_port_map(
                current_data.get(
                    "ports",
                    []
                )
            )


            old_keys = set(
                old_ports.keys()
            )

            new_keys = set(
                new_ports.keys()
            )


            # ==================================================
            # Neu geöffnete Ports
            # ==================================================

            for key in sorted(
                new_keys - old_keys
            ):

                new_port = new_ports[
                    key
                ]


                changes.append(
                    save_change(
                        connection,
                        network_id,
                        device_id,
                        scan_run_id,
                        "PORT_OPENED",

                        old_value=None,

                        new_value={
                            "ip": new_ip,
                            "port": new_port
                        }
                    )
                )


            # ==================================================
            # Nicht mehr offene Ports
            # ==================================================

            for key in sorted(
                old_keys - new_keys
            ):

                old_port = old_ports[
                    key
                ]


                changes.append(
                    save_change(
                        connection,
                        network_id,
                        device_id,
                        scan_run_id,
                        "PORT_CLOSED",

                        old_value={
                            "ip": old_ip,
                            "port": old_port
                        },

                        new_value=None
                    )
                )


            # ==================================================
            # Dienstinformationen verändert
            # ==================================================

            for key in sorted(
                old_keys & new_keys
            ):

                old_port = old_ports[
                    key
                ]

                new_port = new_ports[
                    key
                ]


                if (
                    service_signature(
                        old_port
                    )
                    !=
                    service_signature(
                        new_port
                    )
                ):

                    changes.append(
                        save_change(
                            connection,
                            network_id,
                            device_id,
                            scan_run_id,
                            "SERVICE_CHANGED",

                            old_value={
                                "ip": old_ip,
                                "port": old_port
                            },

                            new_value={
                                "ip": new_ip,
                                "port": new_port
                            }
                        )
                    )


    return {
        "scan_run_id": scan_run_id,
        "compared_devices": compared_devices,
        "baseline_devices": baseline_devices,
        "changes": changes
    }


# ==========================================================
# Inventar
# ==========================================================

def get_inventory(
    connection,
    device_id=None
):
    """
    Liest den aktuellen bekannten Gerätestand aus SQLite.
    """

    where_clause = ""
    parameters = ()


    if device_id is not None:

        where_clause = (
            "WHERE devices.id = ?"
        )

        parameters = (
            device_id,
        )


    rows = connection.execute(
        f"""
        SELECT
            devices.id,
            devices.mac,
            devices.vendor,
            devices.hostname,
            devices.identity_status,
            devices.first_seen,
            devices.last_seen,

            (
                SELECT addresses.ip

                FROM addresses

                WHERE addresses.device_id =
                      devices.id

                ORDER BY
                    addresses.last_seen DESC,
                    addresses.id DESC

                LIMIT 1
            ) AS ip,


            (
                SELECT observations.data_json

                FROM observations

                WHERE observations.device_id =
                      devices.id

                  AND observations.observation_type =
                      'tcp_port_scan'

                ORDER BY
                    observations.observed_at DESC,
                    observations.id DESC

                LIMIT 1
            ) AS port_scan_json,


            (
                SELECT observations.observed_at

                FROM observations

                WHERE observations.device_id =
                      devices.id

                  AND observations.observation_type =
                      'tcp_port_scan'

                ORDER BY
                    observations.observed_at DESC,
                    observations.id DESC

                LIMIT 1
            ) AS port_scan_at,


            (
                SELECT observations.data_json

                FROM observations

                WHERE observations.device_id =
                      devices.id

                  AND observations.observation_type =
                      'os_detection'

                ORDER BY
                    observations.observed_at DESC,
                    observations.id DESC

                LIMIT 1
            ) AS os_scan_json,


            (
                SELECT observations.observed_at

                FROM observations

                WHERE observations.device_id =
                      devices.id

                  AND observations.observation_type =
                      'os_detection'

                ORDER BY
                    observations.observed_at DESC,
                    observations.id DESC

                LIMIT 1
            ) AS os_scan_at

        FROM devices

        {where_clause}
        """,
        parameters
    ).fetchall()


    inventory = []


    for row in rows:

        device = dict(
            row
        )


        port_scan_json = device.pop(
            "port_scan_json"
        )

        os_scan_json = device.pop(
            "os_scan_json"
        )


        device["ports"] = []
        device["os"] = None


        if port_scan_json:

            try:

                port_scan = json.loads(
                    port_scan_json
                )

                device["ports"] = (
                    port_scan.get(
                        "ports",
                        []
                    )
                )

            except json.JSONDecodeError:

                device["ports"] = []


        if os_scan_json:

            try:

                os_scan = json.loads(
                    os_scan_json
                )

                device["os"] = (
                    os_scan.get(
                        "os"
                    )
                )

            except json.JSONDecodeError:

                device["os"] = None


        inventory.append(
            device
        )


    return inventory
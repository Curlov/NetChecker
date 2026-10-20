from transactions import atomic
from logging_utils import event
import json
import os
import sqlite3
from pathlib import Path
from mac_analysis import normalize_mac, analyze_mac
from scan_parser import covered_port
from os_analysis import infer_os_claims, summarize_claims, select_os

IP_MATCH_WINDOW_MINUTES = 60

# Erst nach so vielen aufeinanderfolgenden fehlenden
# Discovery-Läufen gilt ein Gerät als verschwunden.
MISSING_CONFIRMATION_SCANS = 2


from runtime_config import DATABASE_PATH


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
    """Compatibility entry point for the central schema coordinator."""
    from schema import initialize_database
    initialize_database(connection)


# ==========================================================
# Netzwerk
# ==========================================================

def save_network(
    connection,
    cidr,
    interface,
    gateway,
    scope_id=None,
):
    """
    Speichert oder aktualisiert ein Netzwerk.
    """

    scope_id = get_scope_id(connection, scope_id)
    connection.execute(
        """
        INSERT INTO networks (
            scope_id,
            cidr,
            interface,
            gateway
        )
        VALUES (?, ?, ?, ?)

        ON CONFLICT(scope_id, cidr, interface)
        DO UPDATE SET
            gateway = excluded.gateway,
            last_seen = CURRENT_TIMESTAMP
        """,
        (
            scope_id,
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
          AND scope_id = ?
        """,
        (
            cidr,
            interface,
            scope_id,
        )
    ).fetchone()


    return row["id"]


# ==========================================================
# Geräteidentifikation
# ==========================================================

def get_scope_id(connection, scope_id=None):
    scope_id = int(scope_id if scope_id is not None else os.environ.get('NETCHECKER_SCOPE_ID', '1'))
    if not connection.execute('SELECT 1 FROM network_scopes WHERE id=?', (scope_id,)).fetchone():
        raise ValueError('Unknown network scope; select an explicitly created customer/site')
    return scope_id


def network_scope_id(connection, network_id):
    row = connection.execute('SELECT scope_id FROM networks WHERE id=?', (network_id,)).fetchone()
    if row is None:
        raise ValueError('Unknown network')
    return row['scope_id']


def find_device_by_mac(
    connection,
    mac_address,
    network_id=None,
):
    """
    Sucht ein Gerät anhand seiner MAC-Adresse.
    """

    mac_address = normalize_mac(mac_address)
    if not mac_address:
        return None


    return connection.execute(
        """
        SELECT d.* FROM devices d
        LEFT JOIN device_interfaces i ON i.device_id=d.id AND i.scope_id=d.scope_id
        WHERE (d.mac = ? OR i.mac = ?) AND d.scope_id=?
        LIMIT 1
        """,
        (mac_address, mac_address, network_scope_id(connection, network_id) if network_id is not None else get_scope_id(connection))
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
            mac_address,
            network_id=network_id,
        )

        if device is not None:
            return device, "mac"


        # A newly observed MAC does not prove ownership of a formerly MAC-less IP.
        # Preserve the old identity and record a candidate instead of merging it.
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
        mac_address = normalize_mac(mac_address)
        if mac_address is None:
            raise ValueError('Invalid MAC address')
    scope_id = network_scope_id(connection, network_id)


    with atomic(connection):

        local_key = host.get('local_identity_key')
        anchor = connection.execute('SELECT d.* FROM devices d JOIN local_identity_keys k ON k.device_id=d.id WHERE k.scope_id=? AND k.identity_key=?',
                                    (scope_id,local_key)).fetchone() if local_key else None

        device, match_method = identify_device(
            connection,
            network_id,
            ip_address,
            mac_address,
            hostname
        )
        if anchor is not None:
            if device is not None and device['id'] != anchor['id']:
                raise ValueError('Local identity conflicts with a known MAC identity')
            device, match_method = anchor, 'local_identity'


        if device is None:

            identity_status = (
                "confirmed"
                if mac_address
                else "provisional"
            )


            cursor = connection.execute(
                """
                INSERT INTO devices (
                    scope_id,
                    mac,
                    vendor,
                    hostname,
                    identity_status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scope_id,
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


        if mac_address:
            connection.execute("""INSERT INTO device_interfaces(scope_id,device_id,mac,source)
                VALUES(?,?,?,?) ON CONFLICT(scope_id,mac) DO UPDATE SET last_seen=CURRENT_TIMESTAMP""",
                (scope_id,device_id,mac_address,'local_interface' if local_key else 'nmap'))
        if local_key:
            connection.execute('INSERT OR IGNORE INTO local_identity_keys(scope_id,identity_key,device_id) VALUES(?,?,?)',
                               (scope_id,local_key,device_id))
        if host.get('local_os_claims'):
            save_os_claims(connection, network_id, scan_run_id, device_id, host['local_os_claims'])
        if match_method in {'new_provisional','new_mac'} and ip_address:
            candidates = connection.execute('SELECT DISTINCT d.id,d.mac,d.hostname FROM devices d JOIN addresses a ON a.device_id=d.id WHERE a.network_id=? AND a.ip=? AND d.id!=?',
                                            (network_id,ip_address,device_id)).fetchall()
            for candidate in candidates:
                connection.execute("""INSERT OR IGNORE INTO identity_candidates(network_id,device_id,candidate_device_id,scan_run_id,reason,evidence_json)
                    VALUES(?,?,?,?,?,?)""", (network_id,device_id,candidate['id'],scan_run_id,
                    'historical_ip_reuse',json.dumps({'ip':ip_address,'observed_mac':mac_address,
                    'previous_mac':candidate['mac'],'note':'IP alone is not proof of identity'})))
        observation = {
            "ip": ip_address,
            "mac": mac_address,
            "vendor": vendor,
            "hostname": hostname,
            "match_method": match_method
        }
        observation['identity_confidence'] = 100 if match_method in {'mac','local_identity'} else (
            95 if mac_address else 40)
        observation['identity_evidence_status'] = 'confirmed' if mac_address else 'suspected'


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
    host,
    source="nmap",
    observation_type="tcp_port_scan",
    infer_os=True,
):
    """
    Speichert einen erfolgreichen TCP-Portscan.
    """

    device_id = host.get("device_id")
    ip_address = host.get("ip")
    ports = host.get("ports", [])


    with atomic(connection):

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
                        service = COALESCE(NULLIF(excluded.service, ''), ports.service),
                        product = COALESCE(NULLIF(excluded.product, ''), ports.product),
                        version = COALESCE(NULLIF(excluded.version, ''), ports.version),
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
                observation_type,
                source,
                json.dumps(
                    {
                        "ip": ip_address,
                        "ports": ports,
                        "scan_metadata": host.get("scan_metadata", {}),
                    },
                    ensure_ascii=False
                )
            )
        )
        if device_id is not None:
            update_port_inventory(connection, network_id, scan_run_id, host, source)
            if infer_os:
                save_os_claims(connection, network_id, scan_run_id, device_id,
                               infer_os_claims(ports=ports))


def update_port_inventory(connection, network_id, scan_run_id, host, source):
    device_id = host["device_id"]
    ports = host.get("ports") or []
    seen = {(p["protocol"], p["port"]) for p in ports}
    for port in ports:
        service_known = any(port.get(k) for k in ("product", "version", "extrainfo", "ostype", "cpe"))
        columns = ("state", "service", "product", "version", "extrainfo", "ostype",
                   "devicetype", "tunnel", "method", "conf")
        assignments = ", ".join(f"{col}=COALESCE(NULLIF(excluded.{col}, ''), port_inventory.{col})"
                                for col in columns[1:])
        connection.execute(f"""
            INSERT INTO port_inventory(network_id,device_id,protocol,port,{','.join(columns)},
                ever_open,cpe_json,metadata_json,service_observed_at,source,scan_run_id)
            VALUES(?,?,?,?,{','.join('?' for _ in columns)},?,?,?,
                   CASE WHEN ? THEN CURRENT_TIMESTAMP END,?,?)
            ON CONFLICT(network_id,device_id,protocol,port) DO UPDATE SET
                state=excluded.state,
                ever_open=MAX(port_inventory.ever_open,excluded.ever_open), {assignments},
                cpe_json=CASE WHEN excluded.cpe_json != '[]' THEN excluded.cpe_json ELSE port_inventory.cpe_json END,
                metadata_json=CASE WHEN ? THEN excluded.metadata_json ELSE port_inventory.metadata_json END,
                service_observed_at=COALESCE(excluded.service_observed_at,port_inventory.service_observed_at),
                last_seen=CURRENT_TIMESTAMP,
                source=CASE WHEN ? THEN excluded.source ELSE port_inventory.source END,
                scan_run_id=excluded.scan_run_id
        """, (network_id,device_id,port['protocol'],port['port'],
              *(port.get(col) for col in columns), int(port.get('state') == 'open'),
              json.dumps(port.get('cpe') or []),
              json.dumps(port.get('service_metadata') or {}), service_known,source,scan_run_id,
              service_known,service_known))
    for row in connection.execute("SELECT protocol,port FROM port_inventory WHERE network_id=? AND device_id=? AND state IN ('open','filtered')",
                                  (network_id,device_id)).fetchall():
        key = (row['protocol'], row['port'])
        if key not in seen and covered_port(host.get('scan_metadata') or {}, *key):
            connection.execute("UPDATE port_inventory SET state='not_open', scan_run_id=? WHERE network_id=? AND device_id=? AND protocol=? AND port=?",
                               (scan_run_id,network_id,device_id,*key))


def get_port_inventory(connection, network_id, device_id):
    rows = connection.execute("SELECT * FROM port_inventory WHERE network_id=? AND device_id=? ORDER BY protocol,port",
                              (network_id,device_id)).fetchall()
    result = []
    for row in rows:
        port = dict(row)
        port['cpe'] = json.loads(port.pop('cpe_json'))
        port['service_metadata'] = json.loads(port.pop('metadata_json'))
        result.append(port)
    return result


def get_historically_open_tcp_ports(connection, network_id, device_id):
    """Return TCP ports ever observed open, using the inventory projection."""
    return [row['port'] for row in connection.execute("""SELECT port FROM port_inventory
        WHERE network_id=? AND device_id=? AND protocol='tcp'
          AND (ever_open=1 OR state='open') ORDER BY port""", (network_id,device_id))]


def get_current_known_port_scan_observations(connection, scan_run_id):
    return connection.execute("""SELECT device_id,data_json FROM observations
        WHERE scan_run_id=? AND observation_type='known_tcp_port_scan'
          AND device_id IS NOT NULL ORDER BY id""", (scan_run_id,)).fetchall()


def _previous_port_states(connection, network_id, device_id, before_scan_run_id, requested):
    """Find the latest definitive state per requested port across scan kinds."""
    states = {}
    if not requested:
        return states
    rows = connection.execute("""SELECT observation_type,data_json FROM observations
        WHERE network_id=? AND device_id=? AND scan_run_id<?
          AND observation_type IN ('tcp_port_scan','known_tcp_port_scan',
                                   'service_scan','enrichment_result')
        ORDER BY scan_run_id DESC,id DESC""", (network_id,device_id,before_scan_run_id))
    for row in rows:
        try:
            data = json.loads(row['data_json'] or '{}')
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(data,dict):
            continue
        metadata = data.get('scan_metadata') or {}
        if not metadata.get('complete'):
            continue
        observed = {}
        for port in data.get('ports') or ():
            if port.get('protocol') != 'tcp':
                continue
            try:
                number = int(port.get('port'))
            except (TypeError, ValueError):
                continue
            if number in requested:
                observed[number] = port
        for number in requested - states.keys():
            if not covered_port(metadata, 'tcp', number):
                continue
            port = observed.get(number)
            state = (port or {}).get('state')
            if state == 'open':
                states[number] = {'state':'open','port':port,'ip':data.get('ip')}
            elif state == 'closed' or (port is None and row['observation_type'] == 'tcp_port_scan'):
                # Regular detail uses --open, so a complete covered omission
                # means closed. Filtered and ambiguous states stay non-definitive.
                states[number] = {'state':'closed','port':port,'ip':data.get('ip')}
        if len(states) == len(requested):
            break
    return states


def detect_known_port_changes(connection, network_id, scan_run_id):
    """Record only confirmed open/closed transitions from targeted checks."""
    rows = get_current_known_port_scan_observations(connection, scan_run_id)
    changes = []
    with atomic(connection):
        connection.execute("""DELETE FROM changes WHERE scan_run_id=?
            AND change_type IN ('PORT_OPENED','PORT_CLOSED','PORT_NOT_OPEN')""", (scan_run_id,))
        for row in rows:
            try:
                current = json.loads(row['data_json'] or '{}')
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(current,dict):
                continue
            metadata = current.get('scan_metadata') or {}
            if not metadata.get('complete'):
                continue
            current_ports = {}
            for port in current.get('ports') or ():
                if port.get('protocol') != 'tcp' or port.get('state') not in {'open','closed'}:
                    continue
                try:
                    number = int(port.get('port'))
                except (TypeError, ValueError):
                    continue
                if covered_port(metadata,'tcp',number):
                    current_ports[number] = port
            if not current_ports:
                continue
            previous = _previous_port_states(connection,network_id,row['device_id'],
                                             scan_run_id,set(current_ports))
            for number, port in current_ports.items():
                old = previous.get(number)
                if old is None or old['state'] == port['state']:
                    continue
                event_type = 'PORT_OPENED' if port['state'] == 'open' else 'PORT_NOT_OPEN'
                changes.append(save_change(connection,network_id,row['device_id'],scan_run_id,
                    event_type,
                    old_value={'ip':old.get('ip'),'port':old.get('port') or {
                        'protocol':'tcp','port':number,'state':old['state']}},
                    new_value={'ip':current.get('ip'),'port':port}))
    return changes


def save_os_claims(connection, network_id, scan_run_id, device_id, claims):
    for claim in claims:
        evidence = json.dumps(claim['evidence'], ensure_ascii=False, sort_keys=True)
        existing = connection.execute("""SELECT 1 FROM os_claims WHERE network_id=? AND device_id=?
            AND scan_run_id IS ? AND kind=? AND value=? AND source=? AND evidence_json=?""",
            (network_id,device_id,scan_run_id,claim['kind'],claim['value'],claim['source'],evidence)).fetchone()
        if existing:
            continue
        connection.execute("""INSERT INTO os_claims(network_id,device_id,scan_run_id,kind,value,source,status,confidence,evidence_json)
            VALUES(?,?,?,?,?,?,?,?,?)""", (network_id,device_id,scan_run_id,claim['kind'],claim['value'],
            claim['source'],claim['status'],claim['confidence'],evidence))


def get_os_claims(connection, network_id, device_id):
    return get_os_claims_for_devices(connection, [(network_id,device_id)]).get((network_id,device_id), [])


def get_os_claims_for_devices(connection, pairs):
    """Fetch latest distinct evidence for a page in bounded batches, not N queries."""
    pairs = list(dict.fromkeys(pairs))
    result = {pair:[] for pair in pairs}
    for offset in range(0,len(pairs),400):
        batch = pairs[offset:offset+400]
        placeholders = ','.join('(?,?)' for _ in batch)
        rows = connection.execute(f"""WITH ranked AS (
            SELECT *,ROW_NUMBER() OVER (
                PARTITION BY network_id,device_id,kind,value,source,status,evidence_json
                ORDER BY observed_at DESC,id DESC) AS position
            FROM os_claims WHERE (network_id,device_id) IN (VALUES {placeholders})
        ) SELECT * FROM ranked WHERE position=1 ORDER BY observed_at DESC,id DESC""",
            tuple(value for pair in batch for value in pair))
        for row in rows:
            group = result[(row['network_id'],row['device_id'])]
            if len(group) >= 1000:
                continue
            claim = dict(row)
            claim.pop('position')
            try:
                claim['evidence'] = json.loads(row['evidence_json'])
            except (ValueError,TypeError):
                claim['evidence'] = {'raw':row['evidence_json'], 'parse_error':True}
            group.append(claim)
    return result


def get_os_history(connection, network_id, device_id):
    rows = connection.execute("""SELECT id,data_json,observed_at FROM observations WHERE network_id=? AND device_id=?
        AND observation_type='os_detection' ORDER BY observed_at DESC,id DESC LIMIT 200""", (network_id,device_id)).fetchall()
    history = []
    for row in rows:
        try:
            os_result = json.loads(row['data_json'] or '{}').get('os')
            if os_result and os_result.get('name'):
                history.append(dict(os_result, id=row['id'], observed_at=row['observed_at']))
        except (ValueError, TypeError, AttributeError):
            continue
    return history


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

    if not os_info or not str(os_info.get("name") or "").strip():
        return


    with atomic(connection):

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
        if device_id is not None:
            save_os_claims(connection, network_id, scan_run_id, device_id,
                           infer_os_claims(os_info, os_classes=host.get('os_classes') or []))


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


    event('scan_started', scan_run_id=cursor.lastrowid, network_id=network_id, scan_type=scan_type)
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
    event('scan_finished', scan_run_id=scan_run_id, status=status,
          hosts_processed=hosts_processed, hosts_failed=hosts_failed)


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
    event('scan_failed', scan_run_id=scan_run_id, error_type=type(error_message).__name__)


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
    scan_run_id,
    network_id=None
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
          AND (? IS NULL OR observations.network_id = ?)

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
            network_id, network_id,
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

    run = connection.execute('SELECT status, hosts_failed FROM scan_runs WHERE id=? AND network_id=?',
                             (scan_run_id, network_id)).fetchone()
    if run is None or run['status'] not in {'completed', 'completed_with_errors'}:
        raise ValueError('Discovery comparison requires a finished run in this network')
    allow_missing = not run['hosts_failed']
    prior_comparison = connection.execute("SELECT data_json FROM observations WHERE scan_run_id=? AND observation_type='discovery_comparison'",
                                          (scan_run_id,)).fetchone()
    if prior_comparison:
        return json.loads(prior_comparison['data_json'])


    previous_run = (
        get_previous_completed_discovery_run(
            connection,
            network_id,
            scan_run_id
        )
    )


    changes = []
    pending_missing = []


    with atomic(connection):

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


                result = {
                    "baseline": True,
                    "previous_scan_run_id": None,
                    "current_scan_run_id": scan_run_id,
                    "changes": [],
                    "pending_missing": []
                }
                connection.execute("INSERT INTO observations(network_id,scan_run_id,observation_type,source,data_json) VALUES(?,?,'discovery_comparison','inventory',?)",
                                   (network_id,scan_run_id,json.dumps(result,ensure_ascii=False)))
                return result


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
                    scan_run_id, network_id=network_id
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

            if not allow_missing:
                continue

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
                    scan_run_id, network_id=network_id
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


        result = {
            'baseline':False, 'previous_scan_run_id':previous_scan_run_id,
            'current_scan_run_id':scan_run_id, 'changes':changes, 'pending_missing':pending_missing,
        }
        connection.execute("INSERT INTO observations(network_id,scan_run_id,observation_type,source,data_json) VALUES(?,?,'discovery_comparison','inventory',?)",
                           (network_id,scan_run_id,json.dumps(result,ensure_ascii=False)))

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
    scan_run_id,
    network_id=None
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
          AND (? IS NULL OR observations.network_id = ?)

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
            network_id, network_id,
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

        if port.get('state') != 'open':
            continue

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


    with atomic(connection):

        # Falls die Funktion für denselben Run erneut
        # ausgeführt wird, keine Duplikate erzeugen.
        connection.execute(
            """
            DELETE FROM changes

            WHERE scan_run_id = ?

              AND change_type IN (
                  'PORT_OPENED',
                  'PORT_CLOSED',
                  'PORT_NOT_OPEN',
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
                    scan_run_id, network_id=network_id
                )
            )


            # The per-port baseline can come from an earlier discovery check,
            # even when no prior detail scan exists.
            if previous is None:
                baseline_devices += 1
                previous_data = {}
            else:
                compared_devices += 1
                previous_data = previous["data"]


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

            prior_open_ports = set(get_historically_open_tcp_ports(
                connection,network_id,device_id))
            prior_open_ports.update(port for protocol,port in new_keys if protocol == 'tcp')
            prior_states = _previous_port_states(connection,network_id,device_id,
                scan_run_id,prior_open_ports)
            current_metadata = current_data.get('scan_metadata') or {}

            for key, new_port in sorted(new_ports.items()):
                if not covered_port(current_metadata,*key):
                    continue
                prior = prior_states.get(key[1]) if key[0] == 'tcp' else None
                if prior is None or prior['state'] != 'closed':
                    continue
                changes.append(save_change(connection,network_id,device_id,scan_run_id,
                    'PORT_OPENED',old_value={'ip':prior.get('ip'),'port':prior.get('port') or {
                        'protocol':key[0],'port':key[1],'state':'closed'}},
                    new_value={'ip':new_ip,'port':new_port}))


            # ==================================================
            # Nicht mehr offene Ports
            # ==================================================

            for number, prior in prior_states.items():
                key = ('tcp',number)
                if (prior['state'] != 'open' or key in new_keys
                        or not covered_port(current_metadata,*key)):
                    continue
                old_port = prior.get('port') or {'protocol':'tcp','port':number,'state':'open'}
                changes.append(save_change(connection,network_id,device_id,scan_run_id,
                    'PORT_NOT_OPEN',old_value={'ip':prior.get('ip') or old_ip,'port':old_port},
                    new_value=None))


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


                if any(new_port.get(field) and new_port.get(field) != old_port.get(field)
                       for field in ('service', 'product', 'version')):

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
    device_id=None,
    network_id=None,
):
    """
    Liest den aktuellen bekannten Gerätestand aus SQLite.
    """

    where_clause = "WHERE (:device_id IS NULL OR devices.id=:device_id) AND (:network_id IS NULL OR EXISTS (SELECT 1 FROM addresses a WHERE a.device_id=devices.id AND a.network_id=:network_id))"
    parameters = {"device_id": device_id, "network_id": network_id}
    where_clause += ' AND devices.scope_id=:scope_id'
    parameters['scope_id'] = network_scope_id(connection,network_id) if network_id is not None else get_scope_id(connection)




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
                  AND (:network_id IS NULL OR addresses.network_id=:network_id)

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
                  AND (:network_id IS NULL OR observations.network_id=:network_id)

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
                  AND (:network_id IS NULL OR observations.network_id=:network_id)

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
                  AND (:network_id IS NULL OR observations.network_id=:network_id)

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
                  AND (:network_id IS NULL OR observations.network_id=:network_id)

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


        if network_id is not None:
            device['ports'] = [p for p in get_port_inventory(connection, network_id, device['id']) if p['state'] == 'open']
            history = get_os_history(connection, network_id, device['id'])
            if history:
                device['os'] = select_os(history)
            device['os_summary'] = summarize_claims(get_os_claims(connection, network_id, device['id']))
        device['mac_analysis'] = analyze_mac(device.get('mac'))
        inventory.append(
            device
        )


    return inventory

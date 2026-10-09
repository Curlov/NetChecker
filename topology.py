#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from database import get_connection, init_database


ROUTEROS_DATASETS = {
    "ip_address": "/ip/address/print as-value",
    "ip_route": "/ip/route/print as-value",
    "bridge": "/interface/bridge/print as-value",
    "bridge_port": "/interface/bridge/port/print as-value",
    "bridge_host": "/interface/bridge/host/print as-value",
    "arp": "/ip/arp/print as-value",
    "dhcp_network": "/ip/dhcp-server/network/print as-value",
    "dhcp_lease": "/ip/dhcp-server/lease/print as-value",
    "ip_pool": "/ip/pool/print as-value",
    "neighbor": "/ip/neighbor/print as-value",
    "firewall_filter": "/ip/firewall/filter/print as-value",
    "firewall_nat": "/ip/firewall/nat/print as-value",
}

INFRASTRUCTURE_CATEGORIES = {
    "firewall_router",
    "network_device",
}

# Produktionsschutz: RouterOS wird ausschliesslich mit explizit erlaubten
# Lese-Kommandos abgefragt. NetChecker fuehrt hier KEIN add/set/remove/enable/
# disable/reboot o.ae. auf Produktionsgeraeten aus.
ROUTEROS_FORBIDDEN_TOKENS = (
    " add ", " set ", " remove ", " enable ", " disable ",
    " reset ", " reboot", " shutdown", " import ", " export ",
    " move ", " make-static", " release", " renew",
)

DEFAULT_JSON_EXPORT = Path(__file__).resolve().parent / "data" / "topology_latest.json"


# -----------------------------------------------------------------------------
# Allgemeine Hilfsfunktionen
# -----------------------------------------------------------------------------


def run_json_command(command: list[str]) -> Any:
    """Fuehrt einen lokalen Befehl aus und erwartet JSON auf stdout."""
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    return mac.strip().upper().replace("-", ":")


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"yes", "true", "1", "enabled"}


def first_text(value: Any) -> str | None:
    """Liefert bei RouterOS-Listen den ersten brauchbaren Textwert."""
    if isinstance(value, (list, tuple)):
        for item in value:
            text = clean_text(item)
            if text:
                return text
        return None
    return clean_text(value)


def primary_interface(value: Any) -> str | None:
    """Normalisiert RouterOS interface-Felder, die String oder Liste sein koennen."""
    if isinstance(value, (list, tuple)):
        return first_text(value)

    text = clean_text(value)
    if not text:
        return None

    return text.split(",", 1)[0].strip() or None


def normalize_hostname(value: Any) -> str | None:
    """Vergleicht Hostnamen robust: Service1 und Service1.example.local gelten als gleicher Hinweis."""
    text = clean_text(value)
    if not text:
        return None
    return text.rstrip(".").lower().split(".", 1)[0]


def print_header(title: str) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def ensure_column(connection, table: str, column: str, definition: str) -> None:
    columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in columns:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


# -----------------------------------------------------------------------------
# Datenbankschema fuer Phase 3
# -----------------------------------------------------------------------------


def init_topology_database(connection) -> None:
    """
    Erweitert die vorhandene NetChecker-Datenbank um die Topologie-Tabellen.

    Die alten Phase-3-Tabellen bleiben erhalten. Zusaetzlich speichern wir
    Rohdaten/Evidenz, Segmente, Interfaces, Beziehungen, Policies und
    Identitaets-Kandidaten.
    """

    connection.executescript(
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

    connection.commit()


# -----------------------------------------------------------------------------
# Lokale Netzwerkinformationen des NetChecker-Pi
# -----------------------------------------------------------------------------


def collect_local_routes() -> list[dict[str, Any]]:
    return run_json_command(["ip", "-j", "route", "show", "table", "main"])


def get_default_route(routes: list[dict[str, Any]]) -> dict[str, Any]:
    for route in routes:
        if route.get("dst") == "default":
            return route
    raise RuntimeError("Keine Default-Route gefunden.")


def collect_interface_addresses(interface: str) -> list[dict[str, Any]]:
    return run_json_command(["ip", "-j", "address", "show", "dev", interface])


def get_local_ipv4_network(interface: str) -> tuple[str, str]:
    data = collect_interface_addresses(interface)

    for interface_data in data:
        for addr in interface_data.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            if addr.get("scope") != "global":
                continue

            local = addr.get("local")
            prefixlen = addr.get("prefixlen")
            if local is None or prefixlen is None:
                continue

            iface = ipaddress.ip_interface(f"{local}/{prefixlen}")
            return str(iface.network), str(iface.ip)

    raise RuntimeError(f"Keine globale IPv4-Adresse auf {interface} gefunden.")


def collect_local_neighbors(interface: str) -> list[dict[str, Any]]:
    try:
        return run_json_command(["ip", "-j", "neigh", "show", "dev", interface])
    except subprocess.CalledProcessError:
        return []


def classify_route(destination: str | None, gateway: str | None, local_cidr: str) -> str:
    if destination == "default":
        return "default"

    if not destination:
        return "unknown"

    try:
        if "/" not in destination:
            ipaddress.ip_address(destination)
            return "host_route"

        network = ipaddress.ip_network(destination, strict=False)
        local_network = ipaddress.ip_network(local_cidr, strict=False)

        if network.prefixlen in {32, 128}:
            return "host_route"

        if network == local_network:
            return "local_network"

        if gateway:
            return "routed_network"

        return "connected_network"

    except ValueError:
        return "unknown"


def route_label(route_type: str) -> str:
    return {
        "default": "DEFAULT",
        "host_route": "HOST-ROUTE",
        "local_network": "LOKALES NETZ",
        "routed_network": "GEROUTETES NETZ",
        "connected_network": "DIREKTES NETZ",
        "unknown": "UNBEKANNT",
    }.get(route_type, route_type.upper())


# -----------------------------------------------------------------------------
# NetChecker-Datenbank-Zuordnung
# -----------------------------------------------------------------------------


def resolve_network_id(connection, cidr: str, interface: str, gateway: str | None) -> int:
    row = connection.execute(
        """
        SELECT id
        FROM networks
        WHERE cidr = ? AND interface = ?
        ORDER BY last_seen DESC
        LIMIT 1
        """,
        (cidr, interface),
    ).fetchone()

    if row:
        connection.execute(
            """
            UPDATE networks
            SET gateway = ?, last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (gateway, row["id"]),
        )
        connection.commit()
        return int(row["id"])

    cursor = connection.execute(
        """
        INSERT INTO networks (cidr, interface, gateway)
        VALUES (?, ?, ?)
        """,
        (cidr, interface, gateway),
    )
    connection.commit()
    return int(cursor.lastrowid)


def find_device_id_by_mac(connection, mac: str | None) -> int | None:
    mac = normalize_mac(mac)
    if not mac:
        return None

    row = connection.execute(
        "SELECT id FROM devices WHERE UPPER(mac) = ? LIMIT 1",
        (mac,),
    ).fetchone()
    return int(row["id"]) if row else None


def find_device_by_ip(connection, ip: str | None):
    if not ip:
        return None

    return connection.execute(
        """
        SELECT d.id, d.mac, d.vendor, d.hostname, a.ip
        FROM addresses a
        JOIN devices d ON d.id = a.device_id
        WHERE a.ip = ?
        ORDER BY a.last_seen DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()


def find_device_id_by_ip(connection, ip: str | None) -> int | None:
    row = find_device_by_ip(connection, ip)
    return int(row["id"]) if row else None


def get_device_row(connection, device_id: int | None):
    if device_id is None:
        return None
    return connection.execute(
        """
        SELECT id, mac, vendor, hostname
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()


def device_is_infrastructure(connection, device_id: int | None) -> bool:
    if device_id is None:
        return False

    table_exists = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = 'device_classifications'
        """
    ).fetchone()
    if not table_exists:
        return False

    row = connection.execute(
        """
        SELECT 1
        FROM device_classifications
        WHERE device_id = ?
          AND category IN ('firewall_router', 'network_device')
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    return row is not None


def find_device_id(connection, ip: str | None = None, mac: str | None = None) -> int | None:
    """
    Ordnet Evidenz konservativ einem NetChecker-Geraet zu.

    MAC hat Vorrang. Wenn eine unbekannte beobachtete MAC zu einer bereits
    bekannten IP gehoert, wird NICHT nur wegen der IP zusammengefuehrt.
    Solche Faelle werden separat als Identitaets-Kandidaten gespeichert.
    """
    normalized_mac = normalize_mac(mac)

    if normalized_mac:
        device_id = find_device_id_by_mac(connection, normalized_mac)
        if device_id is not None:
            return device_id

        ip_row = find_device_by_ip(connection, ip)
        if ip_row:
            known_mac = normalize_mac(ip_row["mac"])
            if known_mac and known_mac != normalized_mac:
                return None
            return int(ip_row["id"])

        return None

    return find_device_id_by_ip(connection, ip)


def record_same_ip_mac_candidate(
    connection,
    snapshot_id: int,
    ip: str | None,
    observed_mac: str | None,
    source: str,
    evidence: dict[str, Any],
    observed_hostname: str | None = None,
) -> None:
    """
    Speichert gleiche IP mit unterschiedlicher MAC als Identitaetshinweis.

    Bei LLDP/CDP/MNDP-Infrastruktur kann eine Management-IP eine andere
    Chassis-/Port-MAC melden. Das wird deshalb nicht automatisch als harter
    Konflikt bezeichnet, sondern als moegliche Mehr-MAC-Identitaet.
    """
    observed_mac = normalize_mac(observed_mac)
    if not ip or not observed_mac:
        return

    known = find_device_by_ip(connection, ip)
    if not known:
        return

    known_mac = normalize_mac(known["mac"])
    if not known_mac or known_mac == observed_mac:
        return

    hostname = clean_text(observed_hostname) or clean_text(known["hostname"]) or ip

    discovery_source = source in {
        "routeros_neighbor_discovery",
        "routeros_lldp",
        "routeros_cdp",
        "routeros_mndp",
    }
    caps = str(evidence.get("system-caps-enabled") or evidence.get("system-caps") or "").lower()
    platform = clean_text(evidence.get("platform"))
    # Neighbor-Discovery-Protokolle koennen bewusst eine andere Chassis-/
    # Port-MAC als die Management-MAC melden. Daher wird ein solcher Fund
    # nie als harter IP/MAC-Widerspruch gewertet.
    infrastructure_hint = discovery_source or (
        "bridge" in caps
        or bool(platform)
        or device_is_infrastructure(connection, int(known["id"]))
    )

    if infrastructure_hint:
        candidate_type = "infrastructure_multiple_macs"
        confidence = 80
        reason = "same_ip_multiple_infrastructure_macs"
        note = (
            "Moegliche Chassis-/Management-/Port-MAC desselben Infrastrukturgeraets; "
            "nicht automatisch zusammengefuehrt"
        )
    else:
        candidate_type = "same_ip_different_mac"
        confidence = 65
        reason = "same_ip_different_mac"
        note = "Widerspruch gespeichert, nicht automatisch zusammengefuehrt"

    existing = connection.execute(
        """
        SELECT 1
        FROM topology_identity_candidates
        WHERE snapshot_id = ?
          AND candidate_type = ?
          AND ip_a = ?
          AND mac_a = ?
          AND mac_b = ?
        LIMIT 1
        """,
        (snapshot_id, candidate_type, ip, known_mac, observed_mac),
    ).fetchone()
    if existing:
        return

    payload = {
        "reason": reason,
        "source": source,
        "known_device": {
            "device_id": int(known["id"]),
            "ip": ip,
            "mac": known_mac,
            "hostname": known["hostname"],
        },
        "observation": evidence,
        "note": note,
    }

    connection.execute(
        """
        INSERT INTO topology_identity_candidates (
            snapshot_id,
            hostname,
            device_id_a,
            ip_a,
            mac_a,
            device_id_b,
            ip_b,
            mac_b,
            confidence,
            status,
            evidence_json,
            candidate_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            snapshot_id,
            hostname,
            int(known["id"]),
            ip,
            known_mac,
            find_device_id_by_mac(connection, observed_mac),
            ip,
            observed_mac,
            confidence,
            "candidate",
            json.dumps(payload, ensure_ascii=False),
            candidate_type,
        ),
    )


def get_device_display(connection, device_id: int | None) -> str:
    if device_id is None:
        return "nicht in NetChecker bekannt"

    row = connection.execute(
        """
        SELECT id, mac, vendor, hostname
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    if not row:
        return f"Device-ID {device_id}"

    parts = [f"ID {row['id']}"]
    if row["hostname"]:
        parts.append(row["hostname"])
    if row["vendor"]:
        parts.append(row["vendor"])
    return " | ".join(parts)


def get_infrastructure_devices(connection, network_id: int) -> list[dict[str, Any]]:
    table_exists = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = 'device_classifications'
        """
    ).fetchone()

    if not table_exists:
        return []

    rows = connection.execute(
        """
        SELECT
            d.id,
            d.mac,
            d.vendor,
            d.hostname,
            (
                SELECT a.ip
                FROM addresses a
                WHERE a.device_id = d.id
                  AND a.network_id = dc.network_id
                ORDER BY a.last_seen DESC
                LIMIT 1
            ) AS ip,
            dc.category,
            dc.subtype,
            dc.confidence
        FROM device_classifications dc
        JOIN devices d ON d.id = dc.device_id
        WHERE dc.network_id = ?
          AND dc.category IN ('firewall_router', 'network_device')
        ORDER BY ip, d.id
        """,
        (network_id,),
    ).fetchall()

    return [dict(row) for row in rows]


def create_snapshot(connection, network_id: int, interface: str, gateway: str | None) -> int:
    cursor = connection.execute(
        """
        INSERT INTO topology_snapshots (network_id, interface, gateway)
        VALUES (?, ?, ?)
        """,
        (network_id, interface, gateway),
    )
    connection.commit()
    return int(cursor.lastrowid)


def update_snapshot_status(
    connection,
    snapshot_id: int,
    status: str,
    error_message: str | None = None,
    source_summary: dict[str, Any] | None = None,
) -> None:
    """Markiert einen Snapshot als complete/partial/failed.

    Das ist wichtig, weil ein Produktionsgeraet eine Abfrage ablehnen oder
    wegen Authentifizierung/Timeout abbrechen kann. Die lokale Evidenz bleibt
    trotzdem wertvoll und wird nicht verworfen.
    """
    connection.execute(
        """
        UPDATE topology_snapshots
        SET status = ?,
            completed_at = CURRENT_TIMESTAMP,
            error_message = ?,
            source_summary_json = ?
        WHERE id = ?
        """,
        (
            status,
            error_message,
            json.dumps(source_summary or {}, ensure_ascii=False),
            snapshot_id,
        ),
    )
    connection.commit()


def save_local_routes(connection, snapshot_id: int, routes: list[dict[str, Any]], local_cidr: str) -> None:
    for route in routes:
        destination = route.get("dst")
        gateway = route.get("gateway")
        route_type = classify_route(destination, gateway, local_cidr)

        connection.execute(
            """
            INSERT INTO topology_routes (
                snapshot_id,
                destination,
                gateway,
                interface,
                protocol,
                scope,
                metric,
                preferred_source,
                raw_json,
                route_type,
                evidence_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                destination,
                gateway,
                route.get("dev"),
                route.get("protocol"),
                route.get("scope"),
                route.get("metric"),
                route.get("prefsrc"),
                json.dumps(route, ensure_ascii=False),
                route_type,
                "local_route_table",
            ),
        )

    connection.commit()


def save_local_neighbors(connection, snapshot_id: int, neighbors: list[dict[str, Any]]) -> None:
    for neighbor in neighbors:
        ip = neighbor.get("dst")
        mac = normalize_mac(neighbor.get("lladdr"))

        record_same_ip_mac_candidate(
            connection,
            snapshot_id,
            ip,
            mac,
            "linux_neighbor_table",
            neighbor,
        )

        device_id = find_device_id(connection, ip=ip, mac=mac)

        state = neighbor.get("state")
        if isinstance(state, list):
            state = ",".join(state)

        connection.execute(
            """
            INSERT INTO topology_neighbors (
                snapshot_id,
                device_id,
                ip,
                mac,
                interface,
                state,
                raw_json,
                evidence_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                device_id,
                ip,
                mac,
                neighbor.get("dev"),
                state,
                json.dumps(neighbor, ensure_ascii=False),
                "linux_neighbor_table",
            ),
        )

    connection.commit()


# -----------------------------------------------------------------------------
# RouterOS ueber SSH lesen
# -----------------------------------------------------------------------------


def validate_routeros_read_only_commands() -> None:
    """Bricht ab, falls versehentlich ein schreibender RouterOS-Befehl hinterlegt wurde."""
    for dataset, command in ROUTEROS_DATASETS.items():
        normalized = f" {command.strip().lower()} "
        if "/print" not in normalized or " as-value" not in normalized:
            raise RuntimeError(
                f"Produktionsschutz: RouterOS-Datensatz '{dataset}' ist kein reiner print/as-value-Befehl."
            )
        for token in ROUTEROS_FORBIDDEN_TOKENS:
            if token in normalized:
                raise RuntimeError(
                    f"Produktionsschutz: unerlaubtes RouterOS-Schluesselwort in '{dataset}': {token.strip()}"
                )


def build_routeros_export_command() -> str:
    validate_routeros_read_only_commands()
    parts: list[str] = []

    for dataset, command in ROUTEROS_DATASETS.items():
        marker = f"___NETCHECKER_{dataset}___"
        parts.append(f':put "{marker}"')
        parts.append(
            ":put [:serialize "
            f"value=[{command}] "
            "to=json options=json.no-string-conversion]"
        )

    return "; ".join(parts)


def collect_routeros_via_ssh(host: str, user: str) -> dict[str, list[dict[str, Any]]]:
    """
    Liest RouterOS ausschliesslich lesend ueber SSH aus.

    Das Passwort wird von OpenSSH direkt am Terminal abgefragt, wenn noch keine
    SSH-Key-Anmeldung eingerichtet ist. NetChecker speichert das Passwort nicht.
    """

    remote_command = build_routeros_export_command()

    print()
    print(f"RouterOS READ-ONLY: {user}@{host}")
    print("Produktionsschutz aktiv: ausschliesslich print/as-value-Abfragen, keine Konfigurationsbefehle.")
    print("Falls kein SSH-Key eingerichtet ist, fragt SSH jetzt nach dem Passwort.")

    result = subprocess.run(
        [
            "ssh",
            "-o", "ConnectTimeout=8",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "StrictHostKeyChecking=accept-new",
            f"{user}@{host}",
            remote_command,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"RouterOS-SSH-Abfrage fehlgeschlagen (Exit-Code {result.returncode})."
        )

    return parse_routeros_export(result.stdout)


def parse_routeros_export(output: str) -> dict[str, list[dict[str, Any]]]:
    datasets: dict[str, list[dict[str, Any]]] = {}
    current_dataset: str | None = None
    buffer: list[str] = []

    marker_re = re.compile(r"^___NETCHECKER_([a-z0-9_]+)___$")

    def flush() -> None:
        nonlocal buffer, current_dataset
        if current_dataset is None:
            buffer = []
            return

        payload = "\n".join(buffer).strip()
        buffer = []

        if not payload:
            datasets[current_dataset] = []
            return

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"RouterOS-Datensatz '{current_dataset}' ist kein gueltiges JSON: {exc}"
            ) from exc

        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            parsed = []

        datasets[current_dataset] = [
            item for item in parsed if isinstance(item, dict)
        ]

    for raw_line in output.splitlines():
        line = raw_line.strip()
        marker_match = marker_re.match(line)

        if marker_match:
            flush()
            current_dataset = marker_match.group(1)
            continue

        if current_dataset is not None:
            buffer.append(raw_line)

    flush()

    for dataset in ROUTEROS_DATASETS:
        datasets.setdefault(dataset, [])

    return datasets


def save_routeros_raw_records(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    for dataset, records in datasets.items():
        for index, record in enumerate(records):
            connection.execute(
                """
                INSERT INTO topology_routeros_records (
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    dataset,
                    item_index,
                    raw_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    dataset,
                    index,
                    json.dumps(record, ensure_ascii=False),
                ),
            )

    connection.commit()


# -----------------------------------------------------------------------------
# RouterOS-Rohdaten -> Topologie-Evidenz
# -----------------------------------------------------------------------------


def insert_segment(
    connection,
    snapshot_id: int,
    segment_name: str | None,
    cidr: str | None,
    segment_type: str,
    bridge_name: str | None,
    gateway_ip: str | None,
    router_device_id: int | None,
    router_ip: str,
    source: str,
    confidence: int,
    raw: dict[str, Any],
) -> None:
    connection.execute(
        """
        INSERT INTO topology_segments (
            snapshot_id,
            segment_name,
            cidr,
            segment_type,
            bridge_name,
            gateway_ip,
            router_device_id,
            router_ip,
            source,
            confidence,
            raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            snapshot_id,
            segment_name,
            cidr,
            segment_type,
            bridge_name,
            gateway_ip,
            router_device_id,
            router_ip,
            source,
            confidence,
            json.dumps(raw, ensure_ascii=False),
        ),
    )


def derive_routeros_segments(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    # Jede Bridge ist zunaechst ein echtes Layer-2-Segment - auch ohne IP-Netz.
    for bridge in datasets.get("bridge", []):
        name = clean_text(bridge.get("name"))
        if not name:
            continue

        insert_segment(
            connection,
            snapshot_id,
            name,
            None,
            "l2_bridge",
            name,
            None,
            router_device_id,
            router_ip,
            "routeros_bridge_config",
            100,
            bridge,
        )

    # Eine konfigurierte Router-IP belegt ein IP-Netz auf einem Interface/Bridge.
    for address in datasets.get("ip_address", []):
        address_value = clean_text(address.get("address"))
        interface = clean_text(address.get("actual-interface") or address.get("interface"))
        comment = clean_text(address.get("comment"))

        if not address_value:
            continue

        try:
            ip_iface = ipaddress.ip_interface(address_value)
            cidr = str(ip_iface.network)
            gateway_ip = str(ip_iface.ip)
        except ValueError:
            continue

        insert_segment(
            connection,
            snapshot_id,
            comment or interface or cidr,
            cidr,
            "ip_network",
            interface,
            gateway_ip,
            router_device_id,
            router_ip,
            "routeros_ip_address",
            100,
            address,
        )

    # Auch Netze, die der Router nur ueber seine Routing-Tabelle kennt,
    # bleiben als eigene Evidenz erhalten. So koennen spaeter weitere
    # angrenzende Netze entdeckt werden, selbst wenn der NetChecker-Pi
    # selbst keine Route dorthin besitzt.
    for route in datasets.get("ip_route", []):
        destination = clean_text(route.get("dst-address"))
        if not destination or destination in {"0.0.0.0/0", "::/0"}:
            continue

        try:
            routed_cidr = str(ipaddress.ip_network(destination, strict=False))
        except ValueError:
            continue

        insert_segment(
            connection,
            snapshot_id,
            routed_cidr,
            routed_cidr,
            "router_route",
            clean_text(route.get("gateway")),
            clean_text(route.get("local-address")),
            router_device_id,
            router_ip,
            "routeros_route",
            98,
            route,
        )


def derive_routeros_interfaces(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    for port in datasets.get("bridge_port", []):
        interface = clean_text(port.get("interface"))
        bridge = clean_text(port.get("bridge"))
        if not interface:
            continue

        inactive = truthy(port.get("inactive"))
        disabled = truthy(port.get("disabled"))

        if disabled:
            state = "disabled"
        elif inactive:
            state = "inactive"
        else:
            state = "active"

        connection.execute(
            """
            INSERT INTO topology_interfaces (
                snapshot_id,
                device_id,
                owner_ip,
                interface_name,
                interface_type,
                bridge_name,
                mac,
                state,
                source,
                confidence,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                router_device_id,
                router_ip,
                interface,
                "bridge_port",
                bridge,
                None,
                state,
                "routeros_bridge_port",
                100,
                json.dumps(port, ensure_ascii=False),
            ),
        )


def insert_link(
    connection,
    snapshot_id: int,
    source_device_id: int | None,
    source_ip: str | None,
    source_interface: str | None,
    target_device_id: int | None,
    target_ip: str | None,
    target_mac: str | None,
    target_interface: str | None,
    relation: str,
    evidence_source: str,
    confidence: int,
    evidence: dict[str, Any],
) -> None:
    connection.execute(
        """
        INSERT INTO topology_links (
            snapshot_id,
            source_device_id,
            source_ip,
            source_interface,
            target_device_id,
            target_ip,
            target_mac,
            target_interface,
            relation,
            evidence_source,
            confidence,
            evidence_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            snapshot_id,
            source_device_id,
            source_ip,
            source_interface,
            target_device_id,
            target_ip,
            normalize_mac(target_mac),
            target_interface,
            relation,
            evidence_source,
            confidence,
            json.dumps(evidence, ensure_ascii=False),
        ),
    )


def derive_routeros_links(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    # Bridge Host Table:
    # Eine MAC ist ueber einen Port erreichbar. Das ist NICHT automatisch
    # ein direkter physischer Kabel-Link, weil hinter dem Port ein Switch liegen kann.
    for host in datasets.get("bridge_host", []):
        if truthy(host.get("local")):
            continue

        target_mac = normalize_mac(host.get("mac-address"))
        source_interface = clean_text(host.get("on-interface") or host.get("interface"))
        if not target_mac or not source_interface:
            continue

        target_device_id = find_device_id_by_mac(connection, target_mac)

        insert_link(
            connection,
            snapshot_id,
            router_device_id,
            router_ip,
            source_interface,
            target_device_id,
            None,
            target_mac,
            None,
            "reachable_via_port",
            "routeros_bridge_host",
            95,
            host,
        )

    # ARP ist eine IP<->MAC-Beobachtung auf einem Router-Interface.
    for arp in datasets.get("arp", []):
        target_ip = clean_text(arp.get("address"))
        target_mac = normalize_mac(arp.get("mac-address"))
        interface = clean_text(arp.get("interface"))
        if not target_ip or not target_mac:
            continue

        record_same_ip_mac_candidate(
            connection,
            snapshot_id,
            target_ip,
            target_mac,
            "routeros_arp",
            arp,
        )
        target_device_id = find_device_id(connection, ip=target_ip, mac=target_mac)

        insert_link(
            connection,
            snapshot_id,
            router_device_id,
            router_ip,
            interface,
            target_device_id,
            target_ip,
            target_mac,
            None,
            "arp_binding",
            "routeros_arp",
            90,
            arp,
        )

    # DHCP bound ist eine sehr starke aktuelle IP/MAC/Hostname-Zuordnung.
    for lease in datasets.get("dhcp_lease", []):
        target_ip = clean_text(lease.get("active-address") or lease.get("address"))
        target_mac = normalize_mac(lease.get("active-mac-address") or lease.get("mac-address"))
        if not target_ip or not target_mac:
            continue

        record_same_ip_mac_candidate(
            connection,
            snapshot_id,
            target_ip,
            target_mac,
            "routeros_dhcp_lease",
            lease,
            clean_text(lease.get("host-name")),
        )
        target_device_id = find_device_id(connection, ip=target_ip, mac=target_mac)
        status = clean_text(lease.get("status"))
        confidence = 98 if status == "bound" else 85

        insert_link(
            connection,
            snapshot_id,
            router_device_id,
            router_ip,
            clean_text(lease.get("server")),
            target_device_id,
            target_ip,
            target_mac,
            None,
            "dhcp_lease",
            "routeros_dhcp_lease",
            confidence,
            lease,
        )

    # LLDP/MNDP/CDP kann einen echten direkten Infrastruktur-Nachbarn belegen.
    for neighbor in datasets.get("neighbor", []):
        target_ip = first_text(neighbor.get("address4") or neighbor.get("address"))
        target_mac = normalize_mac(first_text(neighbor.get("mac-address")))
        source_interface = primary_interface(neighbor.get("interface"))
        target_interface = first_text(
            neighbor.get("interface-name")
            or neighbor.get("port-id")
            or neighbor.get("port")
        )
        discovered_by = (first_text(neighbor.get("discovered-by")) or "").lower()

        record_same_ip_mac_candidate(
            connection,
            snapshot_id,
            target_ip,
            target_mac,
            "routeros_neighbor_discovery",
            neighbor,
            first_text(neighbor.get("identity")),
        )
        target_device_id = find_device_id(connection, ip=target_ip, mac=target_mac)

        if "lldp" in discovered_by:
            evidence_source = "routeros_lldp"
            confidence = 100
        elif "cdp" in discovered_by:
            evidence_source = "routeros_cdp"
            confidence = 98
        elif "mndp" in discovered_by:
            evidence_source = "routeros_mndp"
            confidence = 95
        else:
            evidence_source = "routeros_neighbor_discovery"
            confidence = 90

        insert_link(
            connection,
            snapshot_id,
            router_device_id,
            router_ip,
            source_interface,
            target_device_id,
            target_ip,
            target_mac,
            target_interface,
            "physical_neighbor",
            evidence_source,
            confidence,
            neighbor,
        )


def build_routeros_attachment_maps(
    datasets: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, str], dict[str, str], dict[str, tuple[str, str]]]:
    """
    Liefert:
      port_to_bridge: physischer Port -> Bridge
      bridge_to_cidr: Bridge/Interface -> direkt konfiguriertes IP-Netz
      mac_to_attachment: MAC -> (Port, Bridge) aus der Bridge-Host-Tabelle
    """
    port_to_bridge: dict[str, str] = {}
    bridge_to_cidr: dict[str, str] = {}
    mac_to_attachment: dict[str, tuple[str, str]] = {}

    for port in datasets.get("bridge_port", []):
        interface = clean_text(port.get("interface"))
        bridge = clean_text(port.get("bridge"))
        if interface and bridge:
            port_to_bridge[interface] = bridge

    for address in datasets.get("ip_address", []):
        address_value = clean_text(address.get("address"))
        interface = clean_text(address.get("actual-interface") or address.get("interface"))
        if not address_value or not interface:
            continue
        try:
            bridge_to_cidr[interface] = str(ipaddress.ip_interface(address_value).network)
        except ValueError:
            continue

    for host in datasets.get("bridge_host", []):
        if truthy(host.get("local")):
            continue
        mac = normalize_mac(host.get("mac-address"))
        port = clean_text(host.get("on-interface") or host.get("interface"))
        bridge = clean_text(host.get("bridge")) or (port_to_bridge.get(port) if port else None)
        if mac and port:
            mac_to_attachment[mac] = (port, bridge or "")

    return port_to_bridge, bridge_to_cidr, mac_to_attachment


def save_endpoint_interface_observation(
    connection,
    snapshot_id: int,
    device_id: int | None,
    hostname: str | None,
    ip: str | None,
    mac: str | None,
    network_cidr: str | None,
    bridge_name: str | None,
    attachment_device_id: int | None,
    attachment_ip: str | None,
    attachment_interface: str | None,
    state: str | None,
    source: str,
    confidence: int,
    evidence: dict[str, Any],
) -> None:
    """
    Fuehrt mehrere Evidenzquellen fuer dasselbe beobachtete Interface zusammen.

    Es wird absichtlich KEIN Eintrag in devices erzeugt. Unbekannte MACs duerfen
    hier existieren, bis spaeter genuegend Evidenz fuer eine echte Geraeteidentitaet
    vorhanden ist.
    """
    mac = normalize_mac(mac)

    if device_id is not None and not hostname:
        device_row = get_device_row(connection, device_id)
        if device_row:
            hostname = clean_text(device_row["hostname"])

    identity_hint = normalize_hostname(hostname)

    if not mac and not ip:
        return

    if mac:
        if ip:
            # Gleiche MAC + gleiche IP bevorzugen. Falls die MAC bereits nur
            # als Layer-2-Beobachtung ohne IP existiert, wird diese Zeile
            # spaeter mit der IP angereichert.
            existing = connection.execute(
                """
                SELECT *
                FROM topology_endpoint_interfaces
                WHERE snapshot_id = ?
                  AND mac = ?
                  AND (ip = ? OR ip IS NULL)
                ORDER BY CASE WHEN ip = ? THEN 0 ELSE 1 END, id
                LIMIT 1
                """,
                (snapshot_id, mac, ip, ip),
            ).fetchone()
        else:
            # LLDP/Bridge-Host kennt manchmal nur die MAC. Dann an eine
            # bereits vorhandene IP/MAC-Beobachtung derselben NIC anhaengen.
            existing = connection.execute(
                """
                SELECT *
                FROM topology_endpoint_interfaces
                WHERE snapshot_id = ? AND mac = ?
                ORDER BY CASE WHEN ip IS NOT NULL THEN 0 ELSE 1 END, id
                LIMIT 1
                """,
                (snapshot_id, mac),
            ).fetchone()
    else:
        existing = connection.execute(
            """
            SELECT *
            FROM topology_endpoint_interfaces
            WHERE snapshot_id = ? AND mac IS NULL AND ip = ?
            ORDER BY id
            LIMIT 1
            """,
            (snapshot_id, ip),
        ).fetchone()

    evidence_entry = {
        "source": source,
        "confidence": confidence,
        "data": evidence,
    }

    if existing:
        try:
            payload = json.loads(existing["evidence_json"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        evidence_list = payload.get("evidence")
        if not isinstance(evidence_list, list):
            evidence_list = []
        evidence_list.append(evidence_entry)
        payload["evidence"] = evidence_list

        existing_confidence = int(existing["confidence"] or 0)
        best_source = source if confidence >= existing_confidence else existing["source"]

        connection.execute(
            """
            UPDATE topology_endpoint_interfaces
            SET device_id = COALESCE(?, device_id),
                hostname = COALESCE(?, hostname),
                ip = COALESCE(ip, ?),
                identity_hint = COALESCE(?, identity_hint),
                network_cidr = COALESCE(?, network_cidr),
                bridge_name = COALESCE(?, bridge_name),
                attachment_device_id = COALESCE(?, attachment_device_id),
                attachment_ip = COALESCE(?, attachment_ip),
                attachment_interface = COALESCE(?, attachment_interface),
                state = COALESCE(?, state),
                source = ?,
                confidence = MAX(confidence, ?),
                evidence_json = ?
            WHERE id = ?
            """,
            (
                device_id, hostname, ip, identity_hint, network_cidr, bridge_name,
                attachment_device_id, attachment_ip, attachment_interface, state,
                best_source, confidence, json.dumps(payload, ensure_ascii=False),
                existing["id"],
            ),
        )
        return

    payload = {"evidence": [evidence_entry]}
    connection.execute(
        """
        INSERT INTO topology_endpoint_interfaces (
            snapshot_id, device_id, hostname, identity_hint, ip, mac,
            network_cidr, bridge_name, attachment_device_id, attachment_ip,
            attachment_interface, state, source, confidence, evidence_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            snapshot_id, device_id, hostname, identity_hint, ip, mac,
            network_cidr, bridge_name, attachment_device_id, attachment_ip,
            attachment_interface, state, source, confidence,
            json.dumps(payload, ensure_ascii=False),
        ),
    )


def derive_routeros_endpoint_interfaces(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    port_to_bridge, bridge_to_cidr, mac_to_attachment = build_routeros_attachment_maps(datasets)

    leases_by_mac: dict[str, dict[str, Any]] = {}
    leases_by_ip: dict[str, dict[str, Any]] = {}
    for lease in datasets.get("dhcp_lease", []):
        mac = normalize_mac(lease.get("active-mac-address") or lease.get("mac-address"))
        ip = clean_text(lease.get("active-address") or lease.get("address"))
        if mac:
            leases_by_mac[mac] = lease
        if ip:
            leases_by_ip[ip] = lease

    # ARP liefert IP<->MAC und das Layer-3-Interface. Bridge-Host liefert
    # dazu, falls noch gelernt, den physischen Ausgangsport.
    for arp in datasets.get("arp", []):
        ip = clean_text(arp.get("address"))
        mac = normalize_mac(arp.get("mac-address"))
        if not ip or not mac:
            continue

        bridge = clean_text(arp.get("interface"))
        attachment = mac_to_attachment.get(mac)
        attachment_port = attachment[0] if attachment else None
        if attachment and attachment[1]:
            bridge = attachment[1]

        lease = leases_by_mac.get(mac) or leases_by_ip.get(ip)
        hostname = clean_text(lease.get("host-name")) if lease else None
        device_id = find_device_id(connection, ip=ip, mac=mac)
        network_cidr = bridge_to_cidr.get(bridge or "")

        save_endpoint_interface_observation(
            connection, snapshot_id, device_id, hostname, ip, mac,
            network_cidr, bridge, router_device_id, router_ip, attachment_port,
            clean_text(arp.get("status")), "routeros_arp", 90, arp,
        )

    # DHCP kann auch Interfaces sichtbar machen, die NetChecker selbst nie
    # erreichen konnte (z.B. Service1 im isolierten LAB).
    for lease in datasets.get("dhcp_lease", []):
        ip = clean_text(lease.get("active-address") or lease.get("address"))
        mac = normalize_mac(lease.get("active-mac-address") or lease.get("mac-address"))
        if not ip or not mac:
            continue

        attachment = mac_to_attachment.get(mac)
        attachment_port = attachment[0] if attachment else None
        bridge = attachment[1] if attachment and attachment[1] else None

        if not bridge:
            for arp in datasets.get("arp", []):
                if clean_text(arp.get("address")) == ip and normalize_mac(arp.get("mac-address")) == mac:
                    bridge = clean_text(arp.get("interface"))
                    break

        device_id = find_device_id(connection, ip=ip, mac=mac)
        status = clean_text(lease.get("status"))
        confidence = 98 if status == "bound" else 85

        save_endpoint_interface_observation(
            connection, snapshot_id, device_id, clean_text(lease.get("host-name")),
            ip, mac, bridge_to_cidr.get(bridge or ""), bridge,
            router_device_id, router_ip, attachment_port, status,
            "routeros_dhcp_lease", confidence, lease,
        )

    # Neighbor Discovery liefert besonders starke Port-/Chassis-Evidenz.
    for neighbor in datasets.get("neighbor", []):
        ip = first_text(neighbor.get("address4") or neighbor.get("address"))
        mac = normalize_mac(first_text(neighbor.get("mac-address")))
        if not ip and not mac:
            continue

        attachment_port = primary_interface(neighbor.get("interface"))
        bridge = port_to_bridge.get(attachment_port or "")
        device_id = find_device_id(connection, ip=ip, mac=mac)
        discovered_by = (first_text(neighbor.get("discovered-by")) or "").lower()
        confidence = 100 if "lldp" in discovered_by else 95 if "mndp" in discovered_by else 90

        save_endpoint_interface_observation(
            connection, snapshot_id, device_id, first_text(neighbor.get("identity")),
            ip, mac, bridge_to_cidr.get(bridge or ""), bridge,
            router_device_id, router_ip, attachment_port, clean_text(neighbor.get("age")),
            "routeros_neighbor_discovery", confidence, neighbor,
        )

    # Bridge-Host-Eintraege ohne ARP/DHCP bleiben trotzdem wertvolle
    # Layer-2-Interface-Beobachtungen.
    known_pairs = {
        (normalize_mac(row["mac"]), clean_text(row["ip"]))
        for row in connection.execute(
            """
            SELECT mac, ip
            FROM topology_endpoint_interfaces
            WHERE snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchall()
    }

    for host in datasets.get("bridge_host", []):
        if truthy(host.get("local")):
            continue
        mac = normalize_mac(host.get("mac-address"))
        if not mac:
            continue
        if any(pair[0] == mac for pair in known_pairs):
            continue

        port = clean_text(host.get("on-interface") or host.get("interface"))
        bridge = clean_text(host.get("bridge")) or port_to_bridge.get(port or "")
        device_id = find_device_id_by_mac(connection, mac)
        save_endpoint_interface_observation(
            connection, snapshot_id, device_id, None, None, mac,
            bridge_to_cidr.get(bridge or ""), bridge, router_device_id, router_ip,
            port, None, "routeros_bridge_host", 95, host,
        )


def derive_routeros_policies(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    for dataset_name, policy_type in (
        ("firewall_filter", "filter"),
        ("firewall_nat", "nat"),
    ):
        for index, rule in enumerate(datasets.get(dataset_name, [])):
            connection.execute(
                """
                INSERT INTO topology_policies (
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    policy_type,
                    rule_order,
                    chain_name,
                    action,
                    src_cidr,
                    dst_cidr,
                    in_interface,
                    out_interface,
                    comment,
                    source,
                    confidence,
                    raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    policy_type,
                    index,
                    clean_text(rule.get("chain")),
                    clean_text(rule.get("action")),
                    clean_text(rule.get("src-address")),
                    clean_text(rule.get("dst-address")),
                    clean_text(rule.get("in-interface")),
                    clean_text(rule.get("out-interface")),
                    clean_text(rule.get("comment")),
                    f"routeros_firewall_{policy_type}",
                    100,
                    json.dumps(rule, ensure_ascii=False),
                ),
            )


def derive_identity_candidates(
    connection,
    snapshot_id: int,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    """
    Sucht Hinweise auf Multi-Homing.

    Ein gleicher Kurz-Hostname (z.B. Service1 und Service1.barucom.local)
    mit unterschiedlichen MAC-Adressen ist ein starker Hinweis, aber noch
    kein Beweis fuer dasselbe physische Geraet. Deshalb wird nur ein Kandidat
    gespeichert und niemals automatisch zusammengefuehrt.
    """

    device_rows = connection.execute(
        """
        SELECT
            d.id,
            d.mac,
            d.hostname,
            (
                SELECT a.ip
                FROM addresses a
                WHERE a.device_id = d.id
                ORDER BY a.last_seen DESC
                LIMIT 1
            ) AS ip
        FROM devices d
        WHERE d.hostname IS NOT NULL
          AND TRIM(d.hostname) != ''
        """
    ).fetchall()

    for lease in datasets.get("dhcp_lease", []):
        hostname = clean_text(lease.get("host-name"))
        hostname_key = normalize_hostname(hostname)
        ip_b = clean_text(lease.get("active-address") or lease.get("address"))
        mac_b = normalize_mac(lease.get("active-mac-address") or lease.get("mac-address"))

        if not hostname or not hostname_key or not ip_b or not mac_b:
            continue

        for row in device_rows:
            if normalize_hostname(row["hostname"]) != hostname_key:
                continue

            device_id_a = int(row["id"])
            mac_a = normalize_mac(row["mac"])
            ip_a = clean_text(row["ip"])

            if not mac_a or mac_a == mac_b:
                continue

            existing = connection.execute(
                """
                SELECT 1
                FROM topology_identity_candidates
                WHERE snapshot_id = ?
                  AND candidate_type = 'same_hostname_different_mac'
                  AND device_id_a = ?
                  AND mac_b = ?
                LIMIT 1
                """,
                (snapshot_id, device_id_a, mac_b),
            ).fetchone()
            if existing:
                continue

            evidence = {
                "reason": "same_hostname_different_mac",
                "hostname_routeros": hostname,
                "hostname_netchecker": row["hostname"],
                "normalized_hostname": hostname_key,
                "netchecker_device": {
                    "device_id": device_id_a,
                    "ip": ip_a,
                    "mac": mac_a,
                },
                "routeros_dhcp": lease,
                "note": "Multi-Homing-Kandidat, nicht automatisch zusammengefuehrt",
            }

            connection.execute(
                """
                INSERT INTO topology_identity_candidates (
                    snapshot_id,
                    hostname,
                    device_id_a,
                    ip_a,
                    mac_a,
                    device_id_b,
                    ip_b,
                    mac_b,
                    confidence,
                    status,
                    evidence_json,
                    candidate_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    hostname,
                    device_id_a,
                    ip_a,
                    mac_a,
                    find_device_id_by_mac(connection, mac_b),
                    ip_b,
                    mac_b,
                    85,
                    "candidate",
                    json.dumps(evidence, ensure_ascii=False),
                    "same_hostname_different_mac",
                ),
            )


def derive_routeros_topology(
    connection,
    snapshot_id: int,
    router_device_id: int | None,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    derive_routeros_segments(
        connection, snapshot_id, router_device_id, router_ip, datasets
    )
    derive_routeros_interfaces(
        connection, snapshot_id, router_device_id, router_ip, datasets
    )
    derive_routeros_links(
        connection, snapshot_id, router_device_id, router_ip, datasets
    )
    derive_routeros_endpoint_interfaces(
        connection, snapshot_id, router_device_id, router_ip, datasets
    )
    derive_routeros_policies(
        connection, snapshot_id, router_device_id, router_ip, datasets
    )
    derive_identity_candidates(connection, snapshot_id, datasets)
    connection.commit()



# -----------------------------------------------------------------------------
# Persistente Topologie-Hinweise fuer die Geraeteklassifikation
# -----------------------------------------------------------------------------


def table_columns(connection, table: str) -> set[str]:
    """Liefert vorhandene Spalten, damit Migrationen abwaertskompatibel bleiben."""
    return {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _normalized_evidence_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _evidence_field(payload: Any, *names: str) -> Any:
    """Findet ein Feld auch in aelteren/verschachtelten Evidenzformaten.

    RouterOS-Exporte aus verschiedenen Entwicklungsstaenden koennen Schluessel
    mit Bindestrich, Unterstrich oder in eingebetteten Dictionaries enthalten.
    Fuer die historische Auswertung normalisieren wir deshalb nur die
    Schluesselnamen; die eigentliche Evidenz bleibt unveraendert gespeichert.
    """
    wanted = {_normalized_evidence_key(name) for name in names}

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            for key, item in value.items():
                if _normalized_evidence_key(key) in wanted:
                    return item
            for item in value.values():
                found = walk(item)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = walk(item)
                if found is not None:
                    return found
        elif isinstance(value, str):
            text = value.strip()
            if text.startswith("{") or text.startswith("["):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    parsed = None
                if parsed is not None:
                    found = walk(parsed)
                    if found is not None:
                        return found
        return None

    return walk(payload)


def _evidence_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(_evidence_text(item) for item in value if item is not None)
    if isinstance(value, dict):
        return " ".join(
            f"{key}={_evidence_text(item)}" for key, item in value.items()
        )
    return str(value).strip()


def _neighbor_ipv4(neighbor: dict[str, Any]) -> str | None:
    value = _evidence_field(neighbor, "address4", "address", "target_ip", "ip")
    text = _evidence_text(value)
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue

    # Letzte Rueckfallebene fuer alte eingebettete JSON-Strukturen.
    blob = _evidence_text(neighbor)
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", blob):
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def _neighbor_mac(neighbor: dict[str, Any]) -> str | None:
    value = _evidence_field(neighbor, "mac-address", "mac_address", "target_mac", "mac")
    text = _evidence_text(value)
    match = re.search(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text)
    if match:
        return normalize_mac(match.group(0))

    blob = _evidence_text(neighbor)
    match = re.search(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", blob)
    return normalize_mac(match.group(0)) if match else None


def _neighbor_discovered_by(neighbor: dict[str, Any]) -> str:
    return _evidence_text(
        _evidence_field(neighbor, "discovered-by", "discovered_by", "protocol")
    ).lower()


def _network_vendor_model_from_neighbor(
    neighbor: dict[str, Any],
) -> tuple[str | None, str | None, str]:
    """Leitet Hersteller/Modell/Subtyp nur aus selbst gemeldeter Discovery-Evidenz ab."""
    platform = _evidence_text(_evidence_field(neighbor, "platform"))
    description = _evidence_text(
        _evidence_field(neighbor, "system-description", "system_description", "description")
    )
    identity = _evidence_text(_evidence_field(neighbor, "identity", "system-name", "system_name"))
    blob = _evidence_text(neighbor)
    text = " ".join((platform, description, identity, blob)).lower()

    if "aruba instant on 1930" in text or ("aruba" in text and "jl683b" in text):
        model_match = re.search(r"\b(JL\d{3,4}[A-Z]?)\b", description or blob, re.IGNORECASE)
        model_code = model_match.group(1).upper() if model_match else None
        model = "Instant On 1930" + (f" {model_code}" if model_code else "")
        return "Aruba", model, f"Aruba {model}"

    if "aruba" in text or "hewlett packard enterprise" in text or "hpe" in text:
        return "Aruba/HPE", None, "Aruba/HPE Netzwerkgeraet"

    if "ubiquiti" in text or "unifi" in text:
        return "Ubiquiti", None, "Ubiquiti Netzwerkgeraet"

    if "mikrotik" in text or "routeros" in text or "routerboard" in text:
        return "MikroTik", None, "MikroTik / RouterBOARD"

    if "cisco" in text:
        return "Cisco", None, "Cisco Netzwerkgeraet"

    return clean_text(platform), None, "Netzwerkgeraet (Neighbor Discovery)"


def _neighbor_is_infrastructure(neighbor: dict[str, Any]) -> bool:
    """Akzeptiert nur starke Infrastruktur-Evidenz; station-only bleibt Endgeraet."""
    enabled = _evidence_text(
        _evidence_field(neighbor, "system-caps-enabled", "system_caps_enabled")
    ).lower()
    advertised = _evidence_text(
        _evidence_field(neighbor, "system-caps", "system_caps")
    ).lower()
    platform = _evidence_text(_evidence_field(neighbor, "platform")).lower()
    description = _evidence_text(
        _evidence_field(neighbor, "system-description", "system_description", "description")
    ).lower()
    blob = _evidence_text(neighbor).lower()

    enabled_caps = {part.strip() for part in re.split(r"[,; ]+", enabled) if part.strip()}
    if enabled_caps & {"bridge", "router", "wlan-ap", "wlanap"}:
        return True

    infrastructure_words = (
        "switch", "aruba", "instant on", "jl683b", "cisco",
        "ubiquiti", "unifi", "mikrotik", "routeros",
        "routerboard", "firewall",
    )
    if any(
        word in platform or word in description or word in blob
        for word in infrastructure_words
    ):
        return True

    # Wenn explizit nur station-only aktiv ist, duerfen die breit annoncierten
    # Capabilities eines Endgeraets nicht zur Infrastrukturklassifikation fuehren.
    if enabled and "station-only" in enabled and not (enabled_caps & {"bridge", "router", "wlan-ap", "wlanap"}):
        return False

    if not enabled:
        advertised_caps = {
            part.strip() for part in re.split(r"[,; ]+", advertised) if part.strip()
        }
        if advertised_caps & {"bridge", "router", "wlan-ap", "wlanap"}:
            return True

    return False


def _device_context_confirms_network_infrastructure(
    connection,
    device_id: int | None,
) -> tuple[bool, str | None]:
    """Bestaetigt Infrastruktur nur durch bereits lokal gespeicherte Zusatzsignale.

    Das ist eine Rueckfallebene fuer alte Neighbor-Datensaetze, denen RouterOS
    nicht alle LLDP-Detailfelder mitgegeben hat. Ein LLDP-Nachbar allein reicht
    nicht, weil auch Workstations `station-only` per LLDP erscheinen koennen.
    """
    if device_id is None:
        return False, None

    row = connection.execute(
        "SELECT vendor FROM devices WHERE id = ?",
        (device_id,),
    ).fetchone()
    vendor = (clean_text(row["vendor"]) if row else "") or ""

    classification = None
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_classifications'"
    ).fetchone():
        classification_columns = table_columns(connection, "device_classifications")
        order_column = next(
            (
                column
                for column in (
                    "updated_at",
                    "classified_at",
                    "last_updated",
                    "created_at",
                    "id",
                )
                if column in classification_columns
            ),
            None,
        )
        order_clause = f"ORDER BY {order_column} DESC" if order_column else ""
        classification = connection.execute(
            f"""
            SELECT category, subtype
            FROM device_classifications
            WHERE device_id = ?
            {order_clause}
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()

    current_text = ""
    if classification:
        current_text = " ".join(
            filter(None, (clean_text(classification["category"]), clean_text(classification["subtype"])))
        ).lower()
        if classification["category"] in {"network_device", "firewall_router"}:
            return True, "existing_network_classification"

    os_row = connection.execute(
        """
        SELECT name
        FROM os_information
        WHERE device_id = ?
        ORDER BY observed_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    ).fetchone() if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='os_information'"
    ).fetchone() else None

    os_name = ((clean_text(os_row["name"]) if os_row else "") or "").lower()
    network_words = (
        " switch", "switch ", "router", "firewall",
        "access point", "wireless ap", "network switch",
    )
    if any(word in os_name for word in network_words):
        return True, "stored_os_fingerprint_indicates_network_device"

    vendor_lower = vendor.lower()
    dedicated_network_vendors = (
        "ubiquiti", "routerboard", "mikrotik", "aruba networks",
        "cisco meraki", "juniper", "fortinet",
    )
    if any(word in vendor_lower for word in dedicated_network_vendors):
        return True, "dedicated_network_vendor"

    return False, None


def upsert_topology_device_hint(
    connection,
    *,
    device_id: int,
    network_id: int,
    category: str,
    subtype: str | None,
    manufacturer: str | None,
    model: str | None,
    confidence: int,
    source: str,
    source_device_id: int | None,
    source_ip: str | None,
    observed_ip: str | None,
    observed_mac: str | None,
    identity: str | None,
    platform: str | None,
    system_description: str | None,
    evidence: dict[str, Any],
    observed_at: str | None = None,
) -> None:
    """Speichert einen langlebigen, auditierbaren Klassifikationshinweis."""
    connection.execute(
        """
        INSERT INTO topology_device_hints (
            device_id, network_id, category, subtype, manufacturer, model,
            confidence, source, source_device_id, source_ip, observed_ip,
            observed_mac, identity, platform, system_description, evidence_json,
            first_seen, last_seen
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            COALESCE(?, CURRENT_TIMESTAMP), COALESCE(?, CURRENT_TIMESTAMP)
        )
        ON CONFLICT(device_id, network_id, source)
        DO UPDATE SET
            category = excluded.category,
            subtype = excluded.subtype,
            manufacturer = COALESCE(excluded.manufacturer, topology_device_hints.manufacturer),
            model = COALESCE(excluded.model, topology_device_hints.model),
            confidence = MAX(topology_device_hints.confidence, excluded.confidence),
            source_device_id = COALESCE(excluded.source_device_id, topology_device_hints.source_device_id),
            source_ip = COALESCE(excluded.source_ip, topology_device_hints.source_ip),
            observed_ip = COALESCE(excluded.observed_ip, topology_device_hints.observed_ip),
            observed_mac = COALESCE(excluded.observed_mac, topology_device_hints.observed_mac),
            identity = COALESCE(excluded.identity, topology_device_hints.identity),
            platform = COALESCE(excluded.platform, topology_device_hints.platform),
            system_description = COALESCE(excluded.system_description, topology_device_hints.system_description),
            evidence_json = excluded.evidence_json,
            last_seen = CASE
                WHEN excluded.last_seen > topology_device_hints.last_seen
                    THEN excluded.last_seen
                ELSE topology_device_hints.last_seen
            END
        """,
        (
            device_id, network_id, category, subtype, manufacturer, model,
            confidence, source, source_device_id, source_ip, observed_ip,
            normalize_mac(observed_mac), identity, platform, system_description,
            json.dumps(evidence, ensure_ascii=False), observed_at, observed_at,
        ),
    )


def derive_neighbor_classification_hint(
    connection,
    *,
    network_id: int,
    source_device_id: int | None,
    source_ip: str | None,
    neighbor: dict[str, Any],
    observed_at: str | None = None,
) -> bool:
    """Erzeugt nur bei starker oder sauber korrelierter Infrastruktur-Evidenz einen Hint."""
    target_ip = _neighbor_ipv4(neighbor)
    target_mac = _neighbor_mac(neighbor)
    discovered_by = _neighbor_discovered_by(neighbor)

    # Normalerweise gilt MAC-first. Bei Infrastruktur darf eine LLDP-Chassis-MAC
    # von der Management-MAC abweichen. Deshalb versuchen wir nach einem
    # MAC-Konflikt zusaetzlich die beobachtete Management-IP. Die MACs selbst
    # werden dadurch NICHT fusioniert.
    device_id = find_device_id(connection, ip=target_ip, mac=target_mac)
    if device_id is None and target_ip:
        device_id = find_device_id_by_ip(connection, target_ip)
    if device_id is None:
        return False

    direct_infrastructure = _neighbor_is_infrastructure(neighbor)
    corroborated, corroboration_reason = _device_context_confirms_network_infrastructure(
        connection, device_id
    )
    if not direct_infrastructure and not corroborated:
        return False

    if "lldp" in discovered_by:
        source = "routeros_lldp"
        confidence = 99 if direct_infrastructure else 94
    elif "cdp" in discovered_by:
        source = "routeros_cdp"
        confidence = 98 if direct_infrastructure else 93
    elif "mndp" in discovered_by:
        source = "routeros_mndp"
        confidence = 95 if direct_infrastructure else 92
    else:
        source = "routeros_neighbor_discovery"
        confidence = 92 if direct_infrastructure else 90

    manufacturer, model, subtype = _network_vendor_model_from_neighbor(neighbor)

    if subtype == "Netzwerkgeraet (Neighbor Discovery)" and corroborated:
        device_row = get_device_row(connection, device_id)
        vendor = clean_text(device_row["vendor"]) if device_row else None
        vendor_lower = (vendor or "").lower()
        if "hewlett packard enterprise" in vendor_lower or vendor_lower.startswith("hpe"):
            manufacturer = manufacturer or "Aruba/HPE"
            subtype = "Aruba/HPE Netzwerkgeraet"
        elif vendor:
            manufacturer = manufacturer or vendor
            subtype = f"{vendor} Netzwerkgeraet"

    if model:
        confidence = min(100, confidence + 1)

    enriched_evidence = dict(neighbor)
    if corroboration_reason:
        enriched_evidence["netchecker-corroboration"] = corroboration_reason

    upsert_topology_device_hint(
        connection,
        device_id=device_id,
        network_id=network_id,
        category="network_device",
        subtype=subtype,
        manufacturer=manufacturer,
        model=model,
        confidence=confidence,
        source=source,
        source_device_id=source_device_id,
        source_ip=source_ip,
        observed_ip=target_ip,
        observed_mac=target_mac,
        identity=clean_text(_evidence_text(_evidence_field(neighbor, "identity", "system-name", "system_name"))),
        platform=clean_text(_evidence_text(_evidence_field(neighbor, "platform"))),
        system_description=clean_text(_evidence_text(_evidence_field(neighbor, "system-description", "system_description", "description"))),
        evidence=enriched_evidence,
        observed_at=observed_at,
    )
    return True


def derive_topology_device_hints(
    connection,
    network_id: int,
    source_device_id: int | None,
    source_ip: str | None,
    datasets: dict[str, list[dict[str, Any]]],
    observed_at: str | None = None,
) -> int:
    count = 0
    for neighbor in datasets.get("neighbor", []):
        if derive_neighbor_classification_hint(
            connection,
            network_id=network_id,
            source_device_id=source_device_id,
            source_ip=source_ip,
            neighbor=neighbor,
            observed_at=observed_at,
        ):
            count += 1
    connection.commit()
    return count


def _json_object(value: Any) -> dict[str, Any] | None:
    """Dekodiert historische JSON-Evidenz robust.

    In fruehen Entwicklungsstaenden konnten JSON-Objekte bereits als String
    serialisiert sein und anschliessend erneut per json.dumps() gespeichert
    werden. Deshalb dekodieren wir begrenzt rekursiv. Auch eine Liste mit genau
    einem Objekt wird akzeptiert.
    """
    current = value

    for _ in range(4):
        if isinstance(current, dict):
            return current

        if isinstance(current, list):
            dict_items = [item for item in current if isinstance(item, dict)]
            if len(dict_items) == 1:
                return dict_items[0]
            return None

        if isinstance(current, bytes):
            try:
                current = current.decode("utf-8", errors="replace")
            except Exception:
                return None
            continue

        if not isinstance(current, str):
            return None

        text = current.strip()
        if not text:
            return None

        try:
            current = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return None

    return current if isinstance(current, dict) else None


def _neighbor_history_key(
    network_id: int,
    source_ip: str | None,
    neighbor: dict[str, Any],
) -> tuple[Any, ...]:
    """Dedupliziert dieselbe Neighbor-Evidenz aus mehreren Historientabellen."""
    return (
        network_id,
        clean_text(source_ip),
        _neighbor_ipv4(neighbor),
        _neighbor_mac(neighbor),
        clean_text(_evidence_text(_evidence_field(neighbor, "identity", "system-name", "system_name"))),
        clean_text(_evidence_text(_evidence_field(neighbor, "platform"))),
        clean_text(_evidence_text(_evidence_field(neighbor, "system-description", "system_description", "description"))),
        _neighbor_discovered_by(neighbor),
    )


def backfill_topology_device_hints_from_history(connection) -> int:
    """
    Baut langlebige Klassifikations-Hints aus bereits gespeicherter Topologie auf.

    Es werden drei rein lokale historische Quellen ausgewertet:
      1. RouterOS-Rohdaten (dataset=neighbor)
      2. physische Neighbor-Links aus topology_links
      3. eingebettete Neighbor-Evidenz in topology_endpoint_interfaces

    Dadurch bleibt ein alter LLDP-Treffer nutzbar, selbst wenn eine der
    Historientabellen in einer frueheren Phase noch unvollstaendig war.
    Es findet KEINE Netzwerkabfrage statt.
    """
    seen: set[tuple[Any, ...]] = set()
    count = 0

    def process(
        *,
        network_id: int,
        source_device_id: int | None,
        source_ip: str | None,
        neighbor: dict[str, Any],
        observed_at: str | None,
    ) -> None:
        nonlocal count
        key = _neighbor_history_key(network_id, source_ip, neighbor)
        if key in seen:
            return
        seen.add(key)
        if derive_neighbor_classification_hint(
            connection,
            network_id=network_id,
            source_device_id=source_device_id,
            source_ip=source_ip,
            neighbor=neighbor,
            observed_at=observed_at,
        ):
            count += 1

    # 1) Originale RouterOS-Neighbor-Rohdaten.
    raw_rows = connection.execute(
        """
        SELECT
            r.router_device_id,
            r.router_ip,
            r.raw_json,
            s.network_id,
            s.created_at
        FROM topology_routeros_records r
        JOIN topology_snapshots s ON s.id = r.snapshot_id
        WHERE r.dataset = 'neighbor'
        ORDER BY s.created_at, r.item_index
        """
    ).fetchall()

    for row in raw_rows:
        neighbor = _json_object(row["raw_json"])
        if neighbor is None:
            continue
        process(
            network_id=int(row["network_id"]),
            source_device_id=(
                int(row["router_device_id"])
                if row["router_device_id"] is not None
                else None
            ),
            source_ip=clean_text(row["router_ip"]),
            neighbor=neighbor,
            observed_at=clean_text(row["created_at"]),
        )

    # 2) Bereits abgeleitete physische Neighbor-Links. Deren evidence_json
    # enthaelt beim RouterOS-Collector den originalen Neighbor-Datensatz.
    link_rows = connection.execute(
        """
        SELECT
            l.source_device_id,
            l.source_ip,
            l.target_ip,
            l.target_mac,
            l.evidence_source,
            l.evidence_json,
            s.network_id,
            s.created_at
        FROM topology_links l
        JOIN topology_snapshots s ON s.id = l.snapshot_id
        WHERE l.relation = 'physical_neighbor'
          AND l.evidence_source IN (
              'routeros_neighbor_discovery',
              'routeros_lldp',
              'routeros_cdp',
              'routeros_mndp'
          )
        ORDER BY s.created_at, l.id
        """
    ).fetchall()

    for row in link_rows:
        neighbor = _json_object(row["evidence_json"])
        if neighbor is None:
            neighbor = {}
        neighbor = dict(neighbor)
        if not _neighbor_ipv4(neighbor) and row["target_ip"]:
            neighbor["address4"] = row["target_ip"]
        if not _neighbor_mac(neighbor) and row["target_mac"]:
            neighbor["mac-address"] = row["target_mac"]
        if not _neighbor_discovered_by(neighbor):
            source_name = clean_text(row["evidence_source"]) or ""
            if source_name.startswith("routeros_"):
                neighbor["discovered-by"] = source_name.removeprefix("routeros_").replace("neighbor_discovery", "") or "neighbor"
        process(
            network_id=int(row["network_id"]),
            source_device_id=(
                int(row["source_device_id"])
                if row["source_device_id"] is not None
                else None
            ),
            source_ip=clean_text(row["source_ip"]),
            neighbor=neighbor,
            observed_at=clean_text(row["created_at"]),
        )

    # 3) Interface-Sicht. Hier kann evidence_json mehrere Quellen enthalten.
    endpoint_rows = connection.execute(
        """
        SELECT
            e.attachment_device_id,
            e.attachment_ip,
            e.ip AS endpoint_ip,
            e.mac AS endpoint_mac,
            e.hostname AS endpoint_hostname,
            e.evidence_json,
            s.network_id,
            s.created_at
        FROM topology_endpoint_interfaces e
        JOIN topology_snapshots s ON s.id = e.snapshot_id
        WHERE e.evidence_json IS NOT NULL
          AND e.evidence_json LIKE '%routeros_%'
        ORDER BY s.created_at, e.id
        """
    ).fetchall()

    discovery_sources = {
        "routeros_neighbor_discovery",
        "routeros_lldp",
        "routeros_cdp",
        "routeros_mndp",
    }

    for row in endpoint_rows:
        payload = _json_object(row["evidence_json"])
        if payload is None:
            continue

        evidence_entries = payload.get("evidence")
        if not isinstance(evidence_entries, list):
            continue

        for entry in evidence_entries:
            if not isinstance(entry, dict):
                continue
            if clean_text(entry.get("source")) not in discovery_sources:
                continue
            neighbor = entry.get("data")
            if not isinstance(neighbor, dict):
                neighbor = {}
            neighbor = dict(neighbor)
            if not _neighbor_ipv4(neighbor) and row["endpoint_ip"]:
                neighbor["address4"] = row["endpoint_ip"]
            if not _neighbor_mac(neighbor) and row["endpoint_mac"]:
                neighbor["mac-address"] = row["endpoint_mac"]
            if not clean_text(_evidence_text(_evidence_field(neighbor, "identity"))) and row["endpoint_hostname"]:
                neighbor["identity"] = row["endpoint_hostname"]
            if not _neighbor_discovered_by(neighbor):
                source_name = clean_text(entry.get("source")) or ""
                if source_name.startswith("routeros_"):
                    neighbor["discovered-by"] = source_name.removeprefix("routeros_").replace("neighbor_discovery", "") or "neighbor"
            process(
                network_id=int(row["network_id"]),
                source_device_id=(
                    int(row["attachment_device_id"])
                    if row["attachment_device_id"] is not None
                    else None
                ),
                source_ip=clean_text(row["attachment_ip"]),
                neighbor=neighbor,
                observed_at=clean_text(row["created_at"]),
            )

    connection.commit()
    return count


def analyze_routeros_neighbor_history(connection) -> dict[str, Any]:
    """Erklaert, warum historische RouterOS-Neighbor-Daten nutzbar oder unbrauchbar sind."""
    stats: dict[str, Any] = {
        "total": 0,
        "parseable": 0,
        "with_ip": 0,
        "mapped_device": 0,
        "direct_infrastructure": 0,
        "corroborated_infrastructure": 0,
        "samples": [],
    }

    rows = connection.execute(
        """
        SELECT r.raw_json, r.router_ip, s.network_id
        FROM topology_routeros_records r
        JOIN topology_snapshots s ON s.id = r.snapshot_id
        WHERE r.dataset = 'neighbor'
        ORDER BY s.created_at DESC, r.item_index
        """
    ).fetchall()

    stats["total"] = len(rows)

    for row in rows:
        neighbor = _json_object(row["raw_json"])
        if neighbor is None:
            continue
        stats["parseable"] += 1

        target_ip = _neighbor_ipv4(neighbor)
        target_mac = _neighbor_mac(neighbor)
        if target_ip:
            stats["with_ip"] += 1

        device_id = find_device_id(connection, ip=target_ip, mac=target_mac)
        if device_id is None and target_ip:
            device_id = find_device_id_by_ip(connection, target_ip)
        if device_id is not None:
            stats["mapped_device"] += 1

        direct = _neighbor_is_infrastructure(neighbor)
        if direct:
            stats["direct_infrastructure"] += 1

        corroborated, reason = _device_context_confirms_network_infrastructure(
            connection, device_id
        )
        if corroborated:
            stats["corroborated_infrastructure"] += 1

        if len(stats["samples"]) < 4:
            description = clean_text(
                _evidence_text(
                    _evidence_field(
                        neighbor,
                        "system-description",
                        "system_description",
                        "description",
                    )
                )
            )
            if description and len(description) > 100:
                description = description[:97] + "..."
            stats["samples"].append(
                {
                    "ip": target_ip,
                    "mac": target_mac,
                    "identity": clean_text(
                        _evidence_text(
                            _evidence_field(neighbor, "identity", "system-name", "system_name")
                        )
                    ),
                    "platform": clean_text(
                        _evidence_text(_evidence_field(neighbor, "platform"))
                    ),
                    "caps_enabled": clean_text(
                        _evidence_text(
                            _evidence_field(neighbor, "system-caps-enabled", "system_caps_enabled")
                        )
                    ),
                    "description": description,
                    "device_id": device_id,
                    "direct_infrastructure": direct,
                    "corroboration": reason,
                    "keys": sorted(str(key) for key in neighbor.keys()),
                }
            )

    return stats


def topology_reconcile_diagnostics(connection) -> dict[str, int]:
    """Zaehlt die lokalen Historienquellen fuer eine nachvollziehbare Diagnose."""
    def scalar(query: str) -> int:
        row = connection.execute(query).fetchone()
        return int(row[0] if row else 0)

    return {
        "raw_neighbors": scalar(
            "SELECT COUNT(*) FROM topology_routeros_records WHERE dataset='neighbor'"
        ),
        "physical_neighbors": scalar(
            """
            SELECT COUNT(*) FROM topology_links
            WHERE relation='physical_neighbor'
              AND evidence_source IN (
                  'routeros_neighbor_discovery','routeros_lldp','routeros_cdp','routeros_mndp'
              )
            """
        ),
        "endpoint_evidence": scalar(
            """
            SELECT COUNT(*) FROM topology_endpoint_interfaces
            WHERE evidence_json IS NOT NULL AND evidence_json LIKE '%routeros_%'
            """
        ),
        "device_hints": scalar(
            "SELECT COUNT(*) FROM topology_device_hints"
        ),
        "strong_hints": scalar(
            "SELECT COUNT(*) FROM topology_device_hints WHERE confidence >= 90"
        ),
    }


def _classification_should_accept_hint(current, hint) -> bool:
    current_category = (clean_text(current["category"]) or "").lower()
    current_subtype = clean_text(current["subtype"])
    current_confidence = int(current["confidence"] or 0)
    hint_confidence = int(hint["confidence"] or 0)

    if hint_confidence < 90:
        return False

    if current_category in {"", "unknown", "unbekannt"}:
        return True

    # Selbst gemeldete LLDP/CDP/MNDP-Infrastruktur ist staerker als ein
    # Nmap-Fingerprint oder eine generische Dienstheuristik.
    if hint["category"] == "network_device" and hint_confidence >= 95:
        if current_category not in {"firewall_router", "network_device"}:
            return True

    if current_category == hint["category"]:
        if hint_confidence > current_confidence:
            return True
        if hint_confidence >= current_confidence and hint["subtype"] and hint["subtype"] != current_subtype:
            return True

    return False


def reconcile_topology_classification_hints(
    connection,
    network_id: int | None = None,
    *,
    verbose: bool = True,
) -> dict[str, int]:
    """
    Legt starke Topologie-Evidenz als Overlay auf die bestehende Klassifikation.

    Die Funktion erzeugt keine neuen Netzwerkabfragen. Sie arbeitet nur auf
    SQLite und kann deshalb nach jedem normalen Klassifikationslauf erneut
    angewendet werden.
    """
    if not connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_classifications'"
    ).fetchone():
        return {"hints": 0, "applied": 0}

    columns = table_columns(connection, "device_classifications")
    required = {"device_id", "network_id", "category", "subtype", "confidence"}
    if not required.issubset(columns):
        return {"hints": 0, "applied": 0}

    params: tuple[Any, ...] = ()
    network_where = ""
    if network_id is not None:
        network_where = "AND h.network_id = ?"
        params = (network_id,)

    hints = connection.execute(
        f"""
        SELECT h.*
        FROM topology_device_hints h
        WHERE h.confidence >= 90
          {network_where}
          AND h.id = (
              SELECT h2.id
              FROM topology_device_hints h2
              WHERE h2.device_id = h.device_id
                AND h2.network_id = h.network_id
              ORDER BY h2.confidence DESC, h2.last_seen DESC, h2.id DESC
              LIMIT 1
          )
        ORDER BY h.network_id, h.device_id
        """,
        params,
    ).fetchall()

    applied = 0
    for hint in hints:
        current = connection.execute(
            """
            SELECT rowid AS classification_rowid, *
            FROM device_classifications
            WHERE device_id = ? AND network_id = ?
            LIMIT 1
            """,
            (hint["device_id"], hint["network_id"]),
        ).fetchone()
        if current is None or not _classification_should_accept_hint(current, hint):
            continue

        assignments = ["category = ?", "subtype = ?", "confidence = ?"]
        values: list[Any] = [hint["category"], hint["subtype"], hint["confidence"]]

        for timestamp_column in ("updated_at", "classified_at", "last_updated"):
            if timestamp_column in columns:
                assignments.append(f"{timestamp_column} = CURRENT_TIMESTAMP")
                break

        values.append(current["classification_rowid"])
        connection.execute(
            f"UPDATE device_classifications SET {', '.join(assignments)} WHERE rowid = ?",
            values,
        )

        connection.execute(
            """
            INSERT INTO topology_classification_reconciliations (
                device_id, network_id, hint_id,
                old_category, old_subtype, old_confidence,
                new_category, new_subtype, new_confidence, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hint["device_id"], hint["network_id"], hint["id"],
                current["category"], current["subtype"], current["confidence"],
                hint["category"], hint["subtype"], hint["confidence"],
                f"starke Topologie-Evidenz via {hint['source']}",
            ),
        )
        applied += 1

        if verbose:
            ip_row = connection.execute(
                """
                SELECT ip FROM addresses
                WHERE device_id = ? AND network_id = ?
                ORDER BY last_seen DESC, id DESC LIMIT 1
                """,
                (hint["device_id"], hint["network_id"]),
            ).fetchone()
            ip = ip_row["ip"] if ip_row else "-"
            print(
                f"  Klassifikation korrigiert: {ip} | "
                f"{current['category']} -> {hint['category']} | "
                f"{hint['subtype'] or '-'} [{hint['confidence']} %; {hint['source']}]"
            )

    connection.commit()
    return {"hints": len(hints), "applied": applied}


# -----------------------------------------------------------------------------
# Ausgabe
# -----------------------------------------------------------------------------


def print_infrastructure(connection, network_id: int, gateway: str | None) -> None:
    print_header("Erkannte Netzwerkinfrastruktur")

    if gateway:
        gateway_device_id = find_device_id_by_ip(connection, gateway)
        print(f"Gateway......: {gateway}")
        print(f"Gateway-Gerät: {get_device_display(connection, gateway_device_id)}")
        print()

    infrastructure = get_infrastructure_devices(connection, network_id)
    if not infrastructure:
        print("Keine klassifizierten Infrastrukturgeraete gefunden.")
        return

    for device in infrastructure:
        ip = device.get("ip") or "-"
        subtype = device.get("subtype") or device.get("category") or "Netzwerkgeraet"
        confidence = device.get("confidence")
        confidence_text = f"{confidence} %" if confidence is not None else "-"
        print(
            f"{ip:<15}  ID {device['id']:>3}  "
            f"{subtype}  [{confidence_text}]"
        )


def print_routes(connection, snapshot_id: int) -> None:
    print_header("Bekannte Routen")

    rows = connection.execute(
        """
        SELECT destination, gateway, interface, protocol, route_type
        FROM topology_routes
        WHERE snapshot_id = ?
        ORDER BY CASE WHEN destination = 'default' THEN 0 ELSE 1 END, destination
        """,
        (snapshot_id,),
    ).fetchall()

    for row in rows:
        destination = row["destination"] or "-"
        gateway = row["gateway"] or "-"
        interface = row["interface"] or "-"
        route_type = row["route_type"] or "unknown"
        protocol = row["protocol"] or "-"

        print(
            f"{destination:<20} via {gateway:<15} dev {interface:<8} "
            f"<{route_label(route_type)}> proto={protocol}"
        )


def print_local_neighbors(connection, snapshot_id: int) -> None:
    print_header("Layer-2 / Neighbor-Beobachtungen des NetChecker")

    rows = connection.execute(
        """
        SELECT ip, mac, state, device_id
        FROM topology_neighbors
        WHERE snapshot_id = ?
        ORDER BY ip
        """,
        (snapshot_id,),
    ).fetchall()

    mapped = 0
    for row in rows:
        if row["device_id"] is not None:
            mapped += 1
        device_text = (
            f"Device-ID: {row['device_id']}"
            if row["device_id"] is not None
            else "Device-ID: -"
        )
        print(
            f"{(row['ip'] or '-'):<15} "
            f"{(row['mac'] or '-'):<17} "
            f"{(row['state'] or '-'):<12} {device_text}"
        )

    print()
    print(f"Neighbor-Eintraege....: {len(rows)}")
    print(f"NetChecker-Zuordnung..: {mapped}")


def print_routeros_summary(
    connection,
    snapshot_id: int,
    router_ip: str,
    datasets: dict[str, list[dict[str, Any]]],
) -> None:
    print_header(f"RouterOS-Topologie {router_ip}")

    print("Datensaetze:")
    for name in ROUTEROS_DATASETS:
        print(f"  {name:<18}: {len(datasets.get(name, []))}")

    print()
    print("Segmente:")
    segment_rows = connection.execute(
        """
        SELECT segment_name, cidr, segment_type, bridge_name, gateway_ip, source
        FROM topology_segments
        WHERE snapshot_id = ? AND router_ip = ?
        ORDER BY segment_type, segment_name, cidr
        """,
        (snapshot_id, router_ip),
    ).fetchall()

    for row in segment_rows:
        cidr = row["cidr"] or "kein IP-Netz"
        gateway = row["gateway_ip"] or "-"
        print(
            f"  {row['segment_type']:<10} "
            f"{(row['segment_name'] or '-'):<22} "
            f"{cidr:<18} Gateway {gateway:<15} "
            f"[{row['source']}]"
        )

    print()
    print("Physische/Discovery-Nachbarn:")
    neighbor_rows = connection.execute(
        """
        SELECT
            source_interface,
            target_ip,
            target_mac,
            target_interface,
            target_device_id,
            evidence_source,
            confidence
        FROM topology_links
        WHERE snapshot_id = ?
          AND source_ip = ?
          AND relation = 'physical_neighbor'
        ORDER BY source_interface, target_ip, target_mac
        """,
        (snapshot_id, router_ip),
    ).fetchall()

    if not neighbor_rows:
        print("  keine")
    else:
        for row in neighbor_rows:
            target = row["target_ip"] or row["target_mac"] or "-"
            remote_port = row["target_interface"] or "?"
            device = get_device_display(connection, row["target_device_id"])
            print(
                f"  {row['source_interface'] or '?'} <-> {target} "
                f"Remote-Port {remote_port} | {device} "
                f"[{row['evidence_source']}, {row['confidence']} %]"
            )

    print()
    print("Beobachtete Endpunkt-Interfaces:")
    endpoint_rows = connection.execute(
        """
        SELECT
            device_id, hostname, identity_hint, ip, mac, network_cidr,
            bridge_name, attachment_interface, state, source, confidence
        FROM topology_endpoint_interfaces
        WHERE snapshot_id = ?
          AND attachment_ip = ?
        ORDER BY COALESCE(identity_hint, hostname, ip, mac), network_cidr, ip, mac
        """,
        (snapshot_id, router_ip),
    ).fetchall()

    if not endpoint_rows:
        print("  keine")
    else:
        for row in endpoint_rows:
            name = row["hostname"]
            if not name and row["device_id"] is not None:
                device_row = get_device_row(connection, row["device_id"])
                if device_row:
                    name = device_row["hostname"]
            name = name or "-"
            print(
                f"  {name:<24} "
                f"{(row['ip'] or '-'):<15} "
                f"{(row['mac'] or '-'):<17} "
                f"Netz {(row['network_cidr'] or '-'):<18} "
                f"Port {(row['attachment_interface'] or '-'):<8} "
                f"Bridge {(row['bridge_name'] or '-'):<18} "
                f"[{row['source']}, {row['confidence']} %]"
            )

    # Kandidaten mit gleichem Identity-Hinweis werden zusaetzlich als
    # Host-Sicht zusammengefasst, ohne sie in devices zu verschmelzen.
    grouped: dict[str, list[Any]] = {}
    for row in endpoint_rows:
        key = row["identity_hint"]
        if key:
            grouped.setdefault(key, []).append(row)

    multihomed_groups = [
        rows
        for rows in grouped.values()
        if len({r["mac"] for r in rows if r["mac"]}) > 1
        and (
            len({r["network_cidr"] for r in rows if r["network_cidr"]}) > 1
            or len({r["ip"] for r in rows if r["ip"]}) > 1
        )
    ]
    if multihomed_groups:
        print()
        print("Host-/Interface-Sicht (nur Hinweis, keine Fusion):")
        for rows in multihomed_groups:
            display_name = next((r["hostname"] for r in rows if r["hostname"]), rows[0]["identity_hint"])
            print(f"  {display_name}")
            for row in rows:
                print(
                    f"    -> {(row['ip'] or '-'):<15} "
                    f"{(row['mac'] or '-'):<17} "
                    f"{(row['network_cidr'] or '-'):<18} "
                    f"via {(row['attachment_interface'] or '-')}"
                )

    print()
    print("Firewall-/NAT-Regeln:")
    policy_rows = connection.execute(
        """
        SELECT
            policy_type,
            rule_order,
            chain_name,
            action,
            src_cidr,
            dst_cidr,
            out_interface,
            comment
        FROM topology_policies
        WHERE snapshot_id = ? AND router_ip = ?
        ORDER BY policy_type, rule_order
        """,
        (snapshot_id, router_ip),
    ).fetchall()

    if not policy_rows:
        print("  keine")
    else:
        for row in policy_rows:
            comment = row["comment"] or "-"
            src = row["src_cidr"] or "*"
            dst = row["dst_cidr"] or "*"
            out_if = row["out_interface"] or "*"
            print(
                f"  {row['policy_type']:<6} #{row['rule_order']:<2} "
                f"{row['action'] or '-':<10} "
                f"{src} -> {dst} out={out_if} | {comment}"
            )

    print()
    print("Multi-Homing-/Identitaets-Kandidaten:")
    identity_rows = connection.execute(
        """
        SELECT
            hostname, candidate_type,
            device_id_a, ip_a, mac_a,
            device_id_b, ip_b, mac_b, confidence
        FROM topology_identity_candidates
        WHERE snapshot_id = ?
        ORDER BY hostname, ip_a, ip_b
        """,
        (snapshot_id,),
    ).fetchall()

    if not identity_rows:
        print("  keine")
    else:
        for row in identity_rows:
            candidate_type = row["candidate_type"] or "candidate"
            type_label = {
                "same_hostname_different_mac": "MULTI-HOMING?",
                "same_ip_different_mac": "IP/MAC-WIDERSPRUCH",
                "infrastructure_multiple_macs": "INFRA-MEHRERE-MACS?",
            }.get(candidate_type, candidate_type)

            print(
                f"  [{type_label}] {row['hostname']}: "
                f"{row['ip_a'] or '?'} / {row['mac_a'] or '?'} "
                f"<-> {row['ip_b'] or '?'} / {row['mac_b'] or '?'} "
                f"[{row['confidence']} %, noch NICHT zusammengefuehrt]"
            )


def _segment_cidrs_by_bridge(connection, snapshot_id: int, router_ip: str) -> dict[str, list[str]]:
    rows = connection.execute(
        """
        SELECT bridge_name, cidr
        FROM topology_segments
        WHERE snapshot_id = ? AND router_ip = ?
          AND segment_type = 'ip_network'
          AND bridge_name IS NOT NULL
          AND cidr IS NOT NULL
        ORDER BY cidr
        """,
        (snapshot_id, router_ip),
    ).fetchall()
    result: dict[str, list[str]] = {}
    for row in rows:
        result.setdefault(row["bridge_name"], []).append(row["cidr"])
    return result


def _physical_neighbors_by_port(connection, snapshot_id: int, router_ip: str) -> dict[str, list[Any]]:
    rows = connection.execute(
        """
        SELECT source_interface, target_device_id, target_ip, target_mac,
               target_interface, evidence_source, confidence
        FROM topology_links
        WHERE snapshot_id = ? AND source_ip = ? AND relation = 'physical_neighbor'
        ORDER BY source_interface, confidence DESC
        """,
        (snapshot_id, router_ip),
    ).fetchall()
    result: dict[str, list[Any]] = {}
    for row in rows:
        result.setdefault(row["source_interface"] or "?", []).append(row)
    return result


def _endpoints_by_port(connection, snapshot_id: int, router_ip: str) -> dict[str, list[Any]]:
    rows = connection.execute(
        """
        SELECT device_id, hostname, identity_hint, ip, mac, network_cidr,
               bridge_name, attachment_interface, source, confidence
        FROM topology_endpoint_interfaces
        WHERE snapshot_id = ? AND attachment_ip = ?
          AND attachment_interface IS NOT NULL
        ORDER BY attachment_interface, COALESCE(hostname, ip, mac)
        """,
        (snapshot_id, router_ip),
    ).fetchall()
    result: dict[str, list[Any]] = {}
    for row in rows:
        result.setdefault(row["attachment_interface"], []).append(row)
    return result


def print_topology_map(connection, snapshot_id: int, router_ip: str) -> None:
    """Zeigt eine konservative, menschenlesbare Topologie-Karte.

    Ein Bridge-Host-Eintrag wird nicht als direkter Kabel-Link verkauft. Existiert
    auf einem Port ein LLDP/MNDP/CDP-Nachbar, werden weitere MACs als "dahinter"
    zusammengefasst. So bleibt die Darstellung ehrlich und trotzdem nuetzlich.
    """
    print_header("Topologie-Karte (evidenzbasiert)")
    router_device_id = find_device_id_by_ip(connection, router_ip)
    print(f"Router/Switch: {router_ip} | {get_device_display(connection, router_device_id)}")
    print("Legende.....: <-> bestaetigter Discovery-Nachbar | -> beobachtet/erreichbar ueber Port")

    bridges = connection.execute(
        """
        SELECT DISTINCT bridge_name
        FROM topology_interfaces
        WHERE snapshot_id = ? AND owner_ip = ? AND bridge_name IS NOT NULL
        ORDER BY bridge_name
        """,
        (snapshot_id, router_ip),
    ).fetchall()
    cidrs_by_bridge = _segment_cidrs_by_bridge(connection, snapshot_id, router_ip)
    physical = _physical_neighbors_by_port(connection, snapshot_id, router_ip)
    endpoints = _endpoints_by_port(connection, snapshot_id, router_ip)

    for bridge_row in bridges:
        bridge = bridge_row["bridge_name"]
        cidrs = cidrs_by_bridge.get(bridge, [])
        cidr_text = ", ".join(cidrs) if cidrs else "nur Layer 2 / kein IP-Netz belegt"
        print()
        print(f"  {bridge}  [{cidr_text}]")

        ports = connection.execute(
            """
            SELECT interface_name, state
            FROM topology_interfaces
            WHERE snapshot_id = ? AND owner_ip = ? AND bridge_name = ?
            ORDER BY CASE WHEN state = 'active' THEN 0 ELSE 1 END, interface_name
            """,
            (snapshot_id, router_ip, bridge),
        ).fetchall()

        for port in ports:
            name = port["interface_name"]
            state = port["state"] or "?"
            marker = "*" if state == "active" else "-"
            print(f"    {marker} {name:<8} ({state})")

            p_neighbors = physical.get(name, [])
            if p_neighbors:
                for n in p_neighbors:
                    target = n["target_ip"] or n["target_mac"] or "?"
                    remote = n["target_interface"] or "?"
                    display = get_device_display(connection, n["target_device_id"])
                    print(
                        f"        <-> {target} | Remote-Port {remote} | {display} "
                        f"[{n['evidence_source']}, {n['confidence']} %]"
                    )

            p_endpoints = endpoints.get(name, [])
            # Wenn ein echter Discovery-Nachbar existiert, sind die uebrigen
            # MACs auf diesem Port typischerweise hinter diesem Nachbarn.
            if p_neighbors:
                visible = [
                    e for e in p_endpoints
                    if not any(
                        (e["ip"] and e["ip"] == n["target_ip"])
                        or (e["mac"] and normalize_mac(e["mac"]) == normalize_mac(n["target_mac"]))
                        for n in p_neighbors
                    )
                ]
                if visible:
                    print(f"        -> {len(visible)} weitere Endpunkt(e) hinter diesem Port/Nachbarn")
                    preview = visible[:5]
                    for e in preview:
                        label = e["hostname"] or e["ip"] or e["mac"] or "?"
                        print(f"           - {label} | {e['ip'] or '-'} | {e['mac'] or '-'}")
                    if len(visible) > len(preview):
                        print(f"           ... +{len(visible) - len(preview)} weitere")
            else:
                # Ohne Discovery-Nachbar zeigen wir einzelne aktuelle/gelernte
                # Endpunkte, aber nennen es bewusst nicht 'direkt verkabelt'.
                unique: dict[tuple[str | None, str | None], Any] = {}
                for e in p_endpoints:
                    unique[(e["ip"], e["mac"])] = e
                for e in list(unique.values())[:6]:
                    label = e["hostname"] or e["ip"] or e["mac"] or "?"
                    print(
                        f"        -> {label} | {e['ip'] or '-'} | {e['mac'] or '-'} "
                        f"[{e['source']}, {e['confidence']} %]"
                    )
                if len(unique) > 6:
                    print(f"        ... +{len(unique) - 6} weitere beobachtete Endpunkte")


def print_segmentation_summary(connection, snapshot_id: int, router_ip: str) -> None:
    print_header("Segmentierung / Kommunikationsregeln")
    rows = connection.execute(
        """
        SELECT policy_type, action, src_cidr, dst_cidr, out_interface, comment, confidence
        FROM topology_policies
        WHERE snapshot_id = ? AND router_ip = ?
        ORDER BY policy_type, rule_order
        """,
        (snapshot_id, router_ip),
    ).fetchall()

    meaningful = []
    for row in rows:
        src = row["src_cidr"]
        dst = row["dst_cidr"]
        action = (row["action"] or "").lower()
        comment = row["comment"] or ""
        if src or dst or "internet" in comment.lower():
            meaningful.append(row)

    if not meaningful:
        print("Keine expliziten Segmentierungsregeln erkannt.")
        return

    for row in meaningful:
        src = row["src_cidr"] or "*"
        dst = row["dst_cidr"] or ("Internet/Upstream" if row["out_interface"] else "*")
        action = (row["action"] or "-").upper()
        symbol = "X" if action in {"DROP", "REJECT"} else ">"
        print(
            f"  {src:<18} {symbol} {dst:<18} {action:<10} "
            f"| {row['comment'] or '-'} [{row['confidence']} %]"
        )


def build_topology_report(connection, snapshot_id: int) -> dict[str, Any]:
    snapshot = connection.execute(
        """
        SELECT ts.*, n.cidr AS local_cidr
        FROM topology_snapshots ts
        JOIN networks n ON n.id = ts.network_id
        WHERE ts.id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if not snapshot:
        raise RuntimeError(f"Snapshot {snapshot_id} nicht gefunden.")

    def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in connection.execute(query, params).fetchall()]

    report = {
        "schema": "netchecker.topology.v1",
        "snapshot": dict(snapshot),
        "routes": rows(
            "SELECT * FROM topology_routes WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "neighbors": rows(
            "SELECT * FROM topology_neighbors WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "segments": rows(
            "SELECT * FROM topology_segments WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "interfaces": rows(
            "SELECT * FROM topology_interfaces WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "links": rows(
            "SELECT * FROM topology_links WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "endpoint_interfaces": rows(
            "SELECT * FROM topology_endpoint_interfaces WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "policies": rows(
            "SELECT * FROM topology_policies WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "identity_candidates": rows(
            "SELECT * FROM topology_identity_candidates WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,),
        ),
        "device_hints": rows(
            """
            SELECT h.*
            FROM topology_device_hints h
            JOIN topology_snapshots s ON s.network_id = h.network_id
            WHERE s.id = ?
            ORDER BY h.device_id, h.confidence DESC, h.last_seen DESC
            """,
            (snapshot_id,),
        ),
    }
    return report


def export_topology_json(connection, snapshot_id: int, path: str | Path) -> Path:
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = Path(__file__).resolve().parent / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_topology_report(connection, snapshot_id), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target


def print_topology_counts(connection, snapshot_id: int) -> None:
    print_header("Gespeicherte Topologie-Evidenz")

    tables = [
        ("topology_routes", "Lokale Routen"),
        ("topology_neighbors", "Lokale Neighbor"),
        ("topology_routeros_records", "RouterOS-Rohdatensaetze"),
        ("topology_segments", "Segmente"),
        ("topology_interfaces", "Interfaces/Ports"),
        ("topology_links", "Beziehungen/Evidenz"),
        ("topology_endpoint_interfaces", "Beobachtete Interfaces"),
        ("topology_policies", "Firewall/NAT-Regeln"),
        ("topology_identity_candidates", "Identitaets-Kandidaten"),
    ]

    for table, label in tables:
        count = connection.execute(
            f"SELECT COUNT(*) AS c FROM {table} WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()["c"]
        print(f"{label:<28}: {count}")

    hint_count = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM topology_device_hints h
        JOIN topology_snapshots s ON s.network_id = h.network_id
        WHERE s.id = ?
        """,
        (snapshot_id,),
    ).fetchone()["c"]
    print(f"{'Persistente Geraete-Hints':<28}: {hint_count}")


# -----------------------------------------------------------------------------
# Hauptlauf
# -----------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetChecker Phase 3 - evidenzbasierte Netzwerktopologie"
    )
    parser.add_argument(
        "--routeros",
        metavar="IP",
        help="RouterOS-Geraet zusaetzlich lesend per SSH auslesen, z.B. 192.168.10.153",
    )
    parser.add_argument(
        "--routeros-user",
        default="admin",
        help="RouterOS-SSH-Benutzer (Standard: admin)",
    )
    parser.add_argument(
        "--json-out",
        nargs="?",
        const=str(DEFAULT_JSON_EXPORT),
        metavar="DATEI",
        help=(
            "Snapshot als JSON fuer FastAPI/Weiterverarbeitung exportieren. "
            "Ohne DATEI: data/topology_latest.json"
        ),
    )
    parser.add_argument(
        "--reconcile-only",
        action="store_true",
        help=(
            "Nur bereits gespeicherte Topologie-/LLDP-Evidenz auf die "
            "Geraeteklassifikation anwenden; keine Netzwerkabfrage."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connection = None
    snapshot_id: int | None = None
    router_error: str | None = None
    source_summary: dict[str, Any] = {
        "local_routes": False,
        "local_neighbors": False,
        "routeros": False,
        "production_safe_read_only": True,
    }

    try:
        connection = get_connection()
        init_database(connection)
        init_topology_database(connection)

        if args.reconcile_only:
            print_header("Topologie-Klassifikation aus gespeicherter Evidenz")
            print("Netzwerkabfrage.: NEIN")
            print("Datenquelle......: ausschliesslich lokale SQLite-Historie")

            before = topology_reconcile_diagnostics(connection)
            print()
            print("Historische Quellen vor Auswertung:")
            print(f"  RouterOS Neighbor-Rohdaten....: {before['raw_neighbors']}")
            print(f"  physische Neighbor-Links......: {before['physical_neighbors']}")
            print(f"  Interface-Evidenz.............: {before['endpoint_evidence']}")
            print(f"  vorhandene Device-Hints.......: {before['device_hints']}")

            neighbor_analysis = analyze_routeros_neighbor_history(connection)
            print()
            print("RouterOS-Neighbor-Analyse:")
            print(f"  Rohdatensaetze.................: {neighbor_analysis['total']}")
            print(f"  JSON parsebar..................: {neighbor_analysis['parseable']}")
            print(f"  mit IPv4-Ziel..................: {neighbor_analysis['with_ip']}")
            print(f"  bekanntem Device zugeordnet...: {neighbor_analysis['mapped_device']}")
            print(f"  direkte Infrastruktur-Evidenz.: {neighbor_analysis['direct_infrastructure']}")
            print(f"  lokal bestaetigte Infrastruktur: {neighbor_analysis['corroborated_infrastructure']}")

            backfilled = backfill_topology_device_hints_from_history(connection)
            result = reconcile_topology_classification_hints(connection, verbose=True)
            after = topology_reconcile_diagnostics(connection)

            print()
            print("Ergebnis:")
            print(f"  verwertete Neighbor-Evidenzen.: {backfilled}")
            print(f"  starke Hints aktiv............: {result['hints']}")
            print(f"  Klassifikationen korrigiert...: {result['applied']}")
            print(f"  Device-Hints insgesamt........: {after['device_hints']}")

            if (
                before["raw_neighbors"] == 0
                and before["physical_neighbors"] == 0
                and before["endpoint_evidence"] == 0
            ):
                print()
                print("Hinweis: In dieser Datenbank ist keine historische RouterOS-/LLDP-Neighbor-Evidenz gespeichert.")
                print("         Es wurde deshalb bewusst nichts geraten oder veraendert.")
            elif backfilled == 0 and after["strong_hints"] == 0:
                print()
                print("Hinweis: Historische Topologie-Evidenz ist vorhanden, aber daraus konnte kein")
                print("         starker Infrastruktur-Hinweis sicher einem bekannten Geraet zugeordnet werden.")
                if neighbor_analysis["samples"]:
                    print()
                    print("Diagnose-Beispiele aus der gespeicherten Neighbor-Historie:")
                    for sample in neighbor_analysis["samples"]:
                        print(
                            "  "
                            f"IP={sample['ip'] or '-'} | MAC={sample['mac'] or '-'} | "
                            f"Device-ID={sample['device_id'] or '-'} | "
                            f"Identity={sample['identity'] or '-'} | Platform={sample['platform'] or '-'} | "
                            f"Caps={sample['caps_enabled'] or '-'}"
                        )
                        if sample["description"]:
                            print(f"    Beschreibung: {sample['description']}")
                        print(
                            f"    direkt={sample['direct_infrastructure']} | "
                            f"Korrelation={sample['corroboration'] or '-'} | "
                            f"Keys={','.join(sample['keys'])}"
                        )
            elif result["applied"] == 0:
                print()
                print("Hinweis: Starke Hints sind vorhanden, aber die aktuelle Klassifikation war bereits")
                print("         gleichwertig oder staerker. Es musste nichts geaendert werden.")

            return 0

        routes = collect_local_routes()
        default_route = get_default_route(routes)

        interface = default_route.get("dev")
        gateway = default_route.get("gateway")
        if not interface:
            raise RuntimeError("Default-Route hat kein Interface.")

        local_cidr, local_ip = get_local_ipv4_network(interface)
        network_id = resolve_network_id(connection, local_cidr, interface, gateway)
        snapshot_id = create_snapshot(connection, network_id, interface, gateway)

        save_local_routes(connection, snapshot_id, routes, local_cidr)
        source_summary["local_routes"] = True

        neighbors = collect_local_neighbors(interface)
        save_local_neighbors(connection, snapshot_id, neighbors)
        source_summary["local_neighbors"] = True

        print_header("NetChecker Topologie")
        print("Betriebsmodus.: PRODUKTION / READ-ONLY")
        print("Schreibzugriff.: nur lokale NetChecker-SQLite-Datenbank")
        print("Netzgeraete....: keine Konfigurationsaenderungen")
        print(f"Snapshot-ID....: {snapshot_id}")
        print(f"Netz...........: {local_cidr}")
        print(f"NetChecker-IP..: {local_ip}")
        print(f"Interface......: {interface}")
        print(f"Gateway........: {gateway or '-'}")

        print_infrastructure(connection, network_id, gateway)
        print_routes(connection, snapshot_id)
        print_local_neighbors(connection, snapshot_id)

        if args.routeros:
            router_ip = args.routeros
            router_device_id = find_device_id_by_ip(connection, router_ip)

            try:
                datasets = collect_routeros_via_ssh(router_ip, args.routeros_user)
                save_routeros_raw_records(
                    connection,
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    datasets,
                )
                derive_routeros_topology(
                    connection,
                    snapshot_id,
                    router_device_id,
                    router_ip,
                    datasets,
                )
                hint_count = derive_topology_device_hints(
                    connection,
                    network_id,
                    router_device_id,
                    router_ip,
                    datasets,
                )
                source_summary["routeros"] = True
                source_summary["classification_hints"] = hint_count
                source_summary["routeros_ip"] = router_ip
                source_summary["routeros_records"] = sum(len(v) for v in datasets.values())

                print_routeros_summary(connection, snapshot_id, router_ip, datasets)
                print_topology_map(connection, snapshot_id, router_ip)
                print_segmentation_summary(connection, snapshot_id, router_ip)
            except Exception as exc:
                router_error = str(exc)
                print()
                print(f"WARNUNG: RouterOS-Evidenz konnte nicht vollstaendig gelesen werden: {router_error}")
                print("Der Snapshot bleibt als PARTIAL erhalten; lokale Evidenz wurde nicht verworfen.")

        # Bereits gespeicherte RouterOS-/LLDP-Evidenz bleibt auch dann wirksam,
        # wenn dieser konkrete Lauf nur lokal/passiv war.
        backfill_topology_device_hints_from_history(connection)
        classification_overlay = reconcile_topology_classification_hints(
            connection,
            network_id,
            verbose=True,
        )
        source_summary["classification_hints_active"] = classification_overlay["hints"]
        source_summary["classification_hints_applied"] = classification_overlay["applied"]

        status = "partial" if router_error else "complete"
        update_snapshot_status(
            connection,
            snapshot_id,
            status,
            router_error,
            source_summary,
        )

        print_topology_counts(connection, snapshot_id)

        export_path = None
        if args.json_out:
            export_path = export_topology_json(connection, snapshot_id, args.json_out)

        print_header("Topologie-Snapshot gespeichert")
        print(f"Status.......: {status.upper()}")
        if export_path:
            print(f"JSON.........: {export_path}")
        if not args.routeros:
            print(
                "Hinweis......: Dieser Lauf enthaelt nur lokale Evidenz. "
                "RouterOS kann mit --routeros IP lesend ergaenzt werden."
            )
        elif not router_error:
            print("Ergebnis.....: lokale Sicht + RouterOS-Konfiguration erfolgreich zusammengefuehrt.")

        return 2 if router_error else 0

    except KeyboardInterrupt:
        if connection is not None and snapshot_id is not None:
            update_snapshot_status(
                connection,
                snapshot_id,
                "partial",
                "Benutzerabbruch",
                source_summary,
            )
        print("\nAbgebrochen.")
        return 130
    except Exception as exc:
        if connection is not None and snapshot_id is not None:
            try:
                update_snapshot_status(
                    connection,
                    snapshot_id,
                    "failed",
                    str(exc),
                    source_summary,
                )
            except Exception:
                pass
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())


import ipaddress

from fastapi import APIRouter, HTTPException, Query

from web.database import get_connection


router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"]
)


# ==========================================================
# Hilfsfunktionen
# ==========================================================

def ip_sort_key(device):
    """
    Sortiert IP-Adressen numerisch statt alphabetisch.

    Beispiel:
        192.168.10.2
        192.168.10.10
        192.168.10.100

    Unbekannte/ungültige IP-Adressen stehen am Ende.
    """

    ip = device.get("ip")

    try:
        address = ipaddress.ip_address(ip)

        return (
            0,
            address.version,
            int(address),
            device["id"]
        )

    except (ValueError, TypeError):
        return (
            1,
            0,
            0,
            device["id"]
        )


# ==========================================================
# Geräteübersicht
# ==========================================================

@router.get("")
def get_devices(
    network_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0)
):
    """
    Liefert Geräte mit Netzwerkadresse, Klassifikation,
    Anwesenheitsstatus und Betriebssystem.

    Standardmäßig numerisch nach IP-Adresse sortiert.

    Die Paginierung erfolgt erst nach der Sortierung.
    """

    sql = """
        SELECT
            d.id,
            d.mac,
            d.vendor,
            d.hostname,
            d.identity_status,
            d.first_seen,
            d.last_seen,

            a.ip,
            a.network_id,
            n.cidr AS network,

            dc.category,
            dc.subtype,
            dc.confidence,

            dp.state AS presence,

            (
                SELECT oi.name
                FROM os_information oi
                WHERE oi.device_id = d.id
                ORDER BY
                    oi.observed_at DESC,
                    oi.id DESC
                LIMIT 1
            ) AS operating_system

        FROM devices d

        JOIN addresses a
            ON a.device_id = d.id

        JOIN networks n
            ON n.id = a.network_id

        LEFT JOIN device_classifications dc
            ON dc.device_id = d.id
            AND dc.network_id = a.network_id

        LEFT JOIN device_presence dp
            ON dp.device_id = d.id
            AND dp.network_id = a.network_id

        WHERE (? IS NULL OR a.network_id = ?)
    """

    with get_connection() as db:
        rows = db.execute(
            sql,
            (network_id, network_id)
        ).fetchall()

    devices = [dict(row) for row in rows]

    # Zuerst alle Ergebnisse numerisch sortieren.
    devices.sort(key=ip_sort_key)

    total = len(devices)

    # Erst danach die angeforderte Seite auswählen.
    page = devices[offset:offset + limit]

    return {
        "total": total,
        "count": len(page),
        "limit": limit,
        "offset": offset,
        "sort": "ip_asc",
        "devices": page
    }


# ==========================================================
# Einzelnes Gerät
# ==========================================================

@router.get("/{device_id}")
def get_device(
    device_id: int,
    network_id: int = Query(..., ge=1)
):
    """
    Liefert die Detailinformationen eines Geräts
    im ausgewählten Netzwerk.

    Alle Abfragen sind ausschließlich lesend.
    """

    with get_connection() as db:

        # --------------------------------------------------
        # Geräteidentität im ausgewählten Netzwerk prüfen
        # --------------------------------------------------

        device = db.execute("""
            SELECT d.*
            FROM devices d
            WHERE d.id = ?
              AND EXISTS (
                  SELECT 1
                  FROM addresses a
                  WHERE a.device_id = d.id
                    AND a.network_id = ?
              )
        """, (device_id, network_id)).fetchone()

        if device is None:
            raise HTTPException(
                status_code=404,
                detail="Gerät in diesem Netzwerk nicht gefunden"
            )

        # --------------------------------------------------
        # Netzwerkadressen
        # --------------------------------------------------

        addresses = db.execute("""
            SELECT
                a.*,
                n.cidr AS network
            FROM addresses a
            JOIN networks n
                ON n.id = a.network_id
            WHERE a.device_id = ?
              AND a.network_id = ?
            ORDER BY a.ip
        """, (device_id, network_id)).fetchall()

        # --------------------------------------------------
        # Aktuelle Klassifikation
        # --------------------------------------------------

        classification = db.execute("""
            SELECT *
            FROM device_classifications
            WHERE device_id = ?
              AND network_id = ?
        """, (device_id, network_id)).fetchone()

        # --------------------------------------------------
        # Anwesenheitsstatus
        # --------------------------------------------------

        presence = db.execute("""
            SELECT *
            FROM device_presence
            WHERE device_id = ?
              AND network_id = ?
        """, (device_id, network_id)).fetchone()

        # --------------------------------------------------
        # Ports und Dienste
        # --------------------------------------------------

        ports = db.execute("""
            SELECT *
            FROM ports
            WHERE device_id = ?
            ORDER BY protocol, port
        """, (device_id,)).fetchall()

        # --------------------------------------------------
        # Betriebssysteminformationen
        # --------------------------------------------------

        os_info = db.execute("""
            SELECT *
            FROM os_information
            WHERE device_id = ?
            ORDER BY observed_at DESC, id DESC
            LIMIT 20
        """, (device_id,)).fetchall()

        # --------------------------------------------------
        # Klassifikationshistorie
        # --------------------------------------------------

        history = db.execute("""
            SELECT
                category,
                subtype,
                confidence,
                source,
                classified_at
            FROM classification_history
            WHERE device_id = ?
              AND network_id = ?
            ORDER BY classified_at DESC, id DESC
            LIMIT 20
        """, (device_id, network_id)).fetchall()

        # --------------------------------------------------
        # Erkannte Veränderungen
        # --------------------------------------------------

        changes = db.execute("""
            SELECT
                change_type,
                old_value_json,
                new_value_json,
                detected_at
            FROM changes
            WHERE device_id = ?
              AND network_id = ?
            ORDER BY detected_at DESC, id DESC
            LIMIT 20
        """, (device_id, network_id)).fetchall()

        # --------------------------------------------------
        # Topologiehinweise
        # --------------------------------------------------

        topology = db.execute("""
            SELECT
                category,
                subtype,
                manufacturer,
                model,
                confidence,
                source,
                last_seen
            FROM topology_device_hints
            WHERE device_id = ?
              AND network_id = ?
            ORDER BY last_seen DESC, id DESC
            LIMIT 20
        """, (device_id, network_id)).fetchall()

    return {
        "device": dict(device),
        "network_id": network_id,
        "addresses": [dict(row) for row in addresses],
        "classification": (
            dict(classification) if classification else None
        ),
        "presence": (
            dict(presence) if presence else None
        ),
        "ports": [dict(row) for row in ports],
        "os_information": [dict(row) for row in os_info],
        "classification_history": [
            dict(row) for row in history
        ],
        "changes": [dict(row) for row in changes],
        "topology_hints": [
            dict(row) for row in topology
        ]
    }

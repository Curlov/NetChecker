
import ipaddress

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from web.database import get_connection, get_write_connection
from database import get_port_inventory, get_os_history, get_os_claims, get_os_claims_for_devices
from os_analysis import summarize_claims
from mac_analysis import analyze_mac
from web.access import allowed_scopes, require_network


router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"]
)


class DeviceNameUpdate(BaseModel):
    display_name: str | None


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

def sqlite_ip_order(value):
    """Fixed-width keys retain IPv4/IPv6 numeric order inside SQLite pagination."""
    try:
        address = ipaddress.ip_address(value)
        return f'0{address.version}{int(address):032x}'
    except (ValueError,TypeError):
        return '1'

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
            d.display_name,
            d.identity_status,
            d.first_seen,
            d.last_seen,

            a.ip,
            a.network_id,
            n.cidr AS network,
            n.scope_id AS network_scope,

            dc.category,
            dc.subtype,
            dc.confidence,

            dp.state AS presence,

            EXISTS (
                SELECT 1 FROM topology_layouts layout
                WHERE layout.network_id=a.network_id AND layout.is_default=1
                  AND (
                    EXISTS (
                        SELECT 1 FROM topology_layout_positions position
                        WHERE position.layout_id=layout.id AND position.device_id=d.id
                    )
                    OR EXISTS (
                        SELECT 1 FROM topology_manual_nodes manual
                        WHERE manual.layout_id=layout.id AND manual.linked_device_id=d.id
                    )
                  )
            ) AS topology_placed,

            (
                SELECT json_extract(oi.data_json, '$.os.name')
                FROM observations oi
                WHERE oi.device_id = d.id AND oi.network_id=a.network_id
                  AND oi.observation_type='os_detection' AND json_valid(oi.data_json)
                ORDER BY
                    (CAST(json_extract(oi.data_json, '$.os.accuracy') AS INTEGER)>=70) DESC,
                    oi.observed_at DESC,
                    oi.id DESC
                LIMIT 1
            ) AS operating_system,

            (
                SELECT group_concat(
                    'port ' || CAST(pi.port AS TEXT) || ' ' || pi.protocol || '/' ||
                    CAST(pi.port AS TEXT) || ' ' || CAST(pi.port AS TEXT) || '/' || pi.protocol || ' ' ||
                    COALESCE(pi.service,'') || ' ' || COALESCE(pi.product,'') || ' ' ||
                    COALESCE(pi.version,'') || ' ' || COALESCE(pi.state,''),
                    ' '
                )
                FROM port_inventory pi
                WHERE pi.device_id=d.id AND pi.network_id=a.network_id
                  AND (pi.ever_open=1 OR pi.state='open')
            ) AS port_search,

            (
                SELECT group_concat(DISTINCT CAST(pi.port AS TEXT))
                FROM port_inventory pi
                WHERE pi.device_id=d.id AND pi.network_id=a.network_id
                  AND (pi.ever_open=1 OR pi.state='open')
            ) AS port_numbers

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
          AND a.id = (SELECT latest.id FROM addresses latest
                      WHERE latest.device_id=d.id AND latest.network_id=a.network_id
                      ORDER BY latest.last_seen DESC,latest.id DESC LIMIT 1)
    """

    with get_connection() as db:
        if network_id is not None:
            require_network(db, network_id)
        scopes = sorted(allowed_scopes(db))
        sql += ' AND n.scope_id IN (' + ','.join('?' for _ in scopes) + ')'
        parameters = (network_id,network_id,*scopes)
        db.create_function('netchecker_ip_order',1,sqlite_ip_order,deterministic=True)
        total = db.execute('SELECT COUNT(*) FROM (' + sql + ')',parameters).fetchone()[0]
        rows = db.execute(
            sql + ' ORDER BY netchecker_ip_order(a.ip),d.id,n.id LIMIT ? OFFSET ?',
            (*parameters,limit,offset)
        ).fetchall()

        page = [dict(row) for row in rows]
        claims = get_os_claims_for_devices(db, [(device['network_id'],device['id']) for device in page])
        for device in page:
            device['mac_analysis'] = analyze_mac(device['mac'])
            device['os_summary'] = summarize_claims(claims.get((device['network_id'],device['id']), []))


    return {
        "total": total,
        "count": len(page),
        "limit": limit,
        "offset": offset,
        "sort": "ip_asc",
        "devices": page
    }


@router.put('/{device_id}/name')
def update_device_name(device_id: int, payload: DeviceNameUpdate,
                       network_id: int = Query(..., ge=1)):
    name = payload.display_name.strip() if payload.display_name is not None else None
    if name and (len(name) > 120 or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise HTTPException(422, 'Gerätename darf höchstens 120 Zeichen und keine Steuerzeichen enthalten')
    with get_write_connection() as db:
        require_network(db, network_id)
        device = db.execute('''SELECT d.id FROM devices d WHERE d.id=? AND EXISTS
            (SELECT 1 FROM addresses a WHERE a.device_id=d.id AND a.network_id=?)''',
            (device_id, network_id)).fetchone()
        if device is None:
            raise HTTPException(404, 'Gerät in diesem Netzwerk nicht gefunden')
        db.execute('UPDATE devices SET display_name=? WHERE id=?', (name or None, device_id))
    return {'device_id': device_id, 'display_name': name or None}


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
        require_network(db, network_id)

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

        ports = [port for port in get_port_inventory(db, network_id, device_id)
                 if port['ever_open'] or port['state'] == 'open']

        # --------------------------------------------------
        # Betriebssysteminformationen
        # --------------------------------------------------

        os_info = get_os_history(db, network_id, device_id)[:20]
        os_claims = get_os_claims(db, network_id, device_id)
        port_history = db.execute("""SELECT source,observed_at,scan_run_id,data_json
            FROM observations WHERE network_id=? AND device_id=?
            AND observation_type IN ('tcp_port_scan','known_tcp_port_scan','service_scan')
            ORDER BY observed_at DESC,id DESC LIMIT 100""",
            (network_id,device_id)).fetchall()
        identity_candidates = db.execute("""SELECT * FROM identity_candidates
            WHERE network_id=? AND (device_id=? OR candidate_device_id=?) ORDER BY id DESC LIMIT 50""",
            (network_id,device_id,device_id)).fetchall()
        interfaces = db.execute('SELECT * FROM device_interfaces WHERE device_id=? AND scope_id=? ORDER BY last_seen DESC,id DESC',
                                (device_id,device['scope_id'])).fetchall()
        last_identity = db.execute("""SELECT data_json,observed_at FROM observations WHERE network_id=? AND device_id=?
            AND observation_type='host_discovery' ORDER BY id DESC LIMIT 1""", (network_id,device_id)).fetchone()

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
        "mac_analysis": analyze_mac(device['mac']),
        "os_summary": summarize_claims(os_claims),
        "os_claims": os_claims,
        "port_history": [dict(row) for row in port_history],
        "identity_candidates": [dict(row) for row in identity_candidates],
        "interfaces": [dict(row) for row in interfaces],
        "last_identity_observation": dict(last_identity) if last_identity else None,
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

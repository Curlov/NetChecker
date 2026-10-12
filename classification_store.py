from transactions import atomic
import json

from classifier import classify_device

from database import get_inventory


# ==========================================================
# Tabellen
# ==========================================================

def init_classification_tables(connection):
    """Compatibility entry point for the central schema coordinator."""
    from schema import initialize_database
    initialize_database(connection)


# ==========================================================
# Geräte des aktuellen Netzwerkes
# ==========================================================

def get_network_device_ids(
    connection,
    network_id
):
    """
    Liefert alle Geräte, die irgendwann in diesem
    Netzwerk beobachtet wurden.

    Das ist wichtig, weil die Datenbank später auch
    andere Kundennetze enthalten kann.
    """

    rows = connection.execute(
        """
        SELECT DISTINCT device_id

        FROM addresses

        WHERE network_id = ?
        """,
        (network_id,)
    ).fetchall()


    return {
        row["device_id"]
        for row in rows
    }


# ==========================================================
# Evidence serialisieren
# ==========================================================

def serialize_evidence(
    evidence
):
    """
    Speichert die Klassifikationsbegründungen
    reproduzierbar als JSON.
    """

    return json.dumps(
        evidence or [],
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":"
        )
    )


# ==========================================================
# Einzelne Klassifikation speichern
# ==========================================================


def save_classification(connection, network_id, device_id, result):
    """Store a complete classification and append history atomically on change."""
    source = result.get('source', 'classifier')
    values = (result['category'], result['subtype'], int(result['confidence']),
              int(result['score']), serialize_evidence(result.get('evidence')), source)
    existing = connection.execute("""SELECT category,subtype,confidence,score,evidence_json,source
        FROM device_classifications WHERE network_id=? AND device_id=?""",
        (network_id,device_id)).fetchone()
    changed = existing is None or tuple(existing) != values
    with atomic(connection):
        connection.execute("""INSERT INTO device_classifications(network_id,device_id,
            category,subtype,confidence,score,evidence_json,source)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(network_id,device_id) DO UPDATE SET
                category=excluded.category,subtype=excluded.subtype,confidence=excluded.confidence,
                score=excluded.score,evidence_json=excluded.evidence_json,source=excluded.source,
                last_classified_at=CURRENT_TIMESTAMP,
                last_changed_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_changed_at END
        """, (network_id,device_id,*values,changed))
        if changed:
            connection.execute("""INSERT INTO classification_history(network_id,device_id,
                category,subtype,confidence,score,evidence_json,source) VALUES(?,?,?,?,?,?,?,?)""",
                (network_id,device_id,*values))
    return changed


# ==========================================================
# Gesamtes Netzwerk klassifizieren
# ==========================================================

def classify_and_store_inventory(
    connection,
    network_id
):
    """
    Klassifiziert alle bekannten Geräte des aktuellen
    Netzwerkes anhand des aktuellen DB-Inventars.

    Das ist günstig:
    kein Nmap,
    kein Netzwerkverkehr,
    nur SQLite + Python-Regeln.
    """

    inventory = get_inventory(
        connection, network_id=network_id
    )


    network_device_ids = (
        get_network_device_ids(
            connection,
            network_id
        )
    )


    evaluated = 0
    changed = 0


    for device in inventory:

        device_id = device.get(
            "id"
        )


        if (
            device_id
            not in network_device_ids
        ):

            continue


        result = classify_device(
            device
        )


        from classification_evidence import apply_topology_hint
        result = apply_topology_hint(connection, network_id, device_id, result)
        evaluated += 1


        if save_classification(
            connection,
            network_id,
            device_id,
            result
        ):

            changed += 1


    return {
        "evaluated":
            evaluated,

        "changed":
            changed,

        "unchanged":
            evaluated - changed,
    }

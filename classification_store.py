import json

from classifier import classify_device

from database import get_inventory


# ==========================================================
# Tabellen
# ==========================================================

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


    connection.commit()


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

def save_classification(
    connection,
    network_id,
    device_id,
    result
):
    """
    Speichert den aktuellen Klassifikationsstand.

    Nur wenn sich Kategorie, Untertyp, Confidence,
    Score oder Evidence geändert haben, wird zusätzlich
    ein Historieneintrag erzeugt.

    Rückgabe:
        True  = Klassifikation verändert
        False = unverändert
    """

    category = result[
        "category"
    ]

    subtype = result[
        "subtype"
    ]

    confidence = int(
        result[
            "confidence"
        ]
    )

    score = int(
        result[
            "score"
        ]
    )


    evidence_json = serialize_evidence(
        result.get(
            "evidence"
        )
    )


    existing = connection.execute(
        """
        SELECT
            category,
            subtype,
            confidence,
            score,
            evidence_json

        FROM device_classifications

        WHERE network_id = ?
          AND device_id = ?
        """,
        (
            network_id,
            device_id,
        )
    ).fetchone()


    changed = False


    if existing is None:

        changed = True

    else:

        changed = (
            existing["category"]
            != category

            or (
                existing["subtype"]
                or ""
            )
            != (
                subtype
                or ""
            )

            or int(
                existing["confidence"]
            )
            != confidence

            or int(
                existing["score"]
            )
            != score

            or existing[
                "evidence_json"
            ]
            != evidence_json
        )


    # ======================================================
    # Aktuellen Stand speichern
    # ======================================================

    connection.execute(
        """
        INSERT INTO device_classifications (
            network_id,
            device_id,
            category,
            subtype,
            confidence,
            score,
            evidence_json,
            source,
            first_classified_at,
            last_classified_at,
            last_changed_at
        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?,
            'classifier',
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )

        ON CONFLICT (
            network_id,
            device_id
        )

        DO UPDATE SET

            category =
                excluded.category,

            subtype =
                excluded.subtype,

            confidence =
                excluded.confidence,

            score =
                excluded.score,

            evidence_json =
                excluded.evidence_json,

            source =
                excluded.source,

            last_classified_at =
                CURRENT_TIMESTAMP,

            last_changed_at =
                CASE
                    WHEN
                        device_classifications.category
                            != excluded.category

                        OR COALESCE(
                            device_classifications.subtype,
                            ''
                        )
                            != COALESCE(
                                excluded.subtype,
                                ''
                            )

                        OR device_classifications.confidence
                            != excluded.confidence

                        OR device_classifications.score
                            != excluded.score

                        OR device_classifications.evidence_json
                            != excluded.evidence_json

                    THEN CURRENT_TIMESTAMP

                    ELSE
                        device_classifications.last_changed_at
                END
        """,
        (
            network_id,
            device_id,
            category,
            subtype,
            confidence,
            score,
            evidence_json,
        )
    )


    # ======================================================
    # Nur echte Änderungen in Historie schreiben
    # ======================================================

    if changed:

        connection.execute(
            """
            INSERT INTO classification_history (
                network_id,
                device_id,
                category,
                subtype,
                confidence,
                score,
                evidence_json,
                source
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                'classifier'
            )
            """,
            (
                network_id,
                device_id,
                category,
                subtype,
                confidence,
                score,
                evidence_json,
            )
        )


    connection.commit()


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
        connection
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
from database import get_inventory


# ==========================================================
# Hilfsfunktionen
# ==========================================================

def display_value(value):
    """
    Gibt für leere Werte ein '-' zurück.
    """

    if value is None:
        return "-"

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return "-"

    return value


# ==========================================================
# Gespeicherte Klassifikation laden
# ==========================================================

def get_saved_classification(
    connection,
    device_id
):
    """
    Liest die zuletzt gespeicherte Klassifikation
    eines Gerätes aus device_classifications.

    Ein Gerät kann theoretisch in mehreren Netzwerken
    vorkommen. Für die Konsolenausgabe genügt hier der
    zuletzt aktualisierte Klassifikationsstand.
    """

    try:

        row = connection.execute(
            """
            SELECT
                category,
                subtype,
                confidence,
                score,
                last_classified_at,
                last_changed_at

            FROM device_classifications

            WHERE device_id = ?

            ORDER BY
                last_classified_at DESC

            LIMIT 1
            """,
            (device_id,)
        ).fetchone()

    except Exception:

        # output.py soll auch dann weiter funktionieren,
        # wenn die Klassifikationstabellen beispielsweise
        # bei einem sehr frühen Programmstart noch nicht
        # existieren.
        return None


    if row is None:

        return None


    return dict(
        row
    )


# ==========================================================
# Kategorie in lesbare Form übersetzen
# ==========================================================

def get_category_label(category):
    """
    Übersetzt interne Kategorienamen in die
    deutschsprachige Anzeige.
    """

    labels = {
        "firewall_router":
            "Router / Firewall",

        "network_device":
            "Netzwerkgerät",

        "virtualization":
            "Virtualisierung",

        "server":
            "Server",

        "workstation":
            "PC / Workstation",

        "apple_device":
            "Apple-Gerät",

        "voip_phone":
            "VoIP-Telefon",

        "printer":
            "Drucker",

        "camera":
            "IP-Kamera",

        "power_device":
            "USV / Stromversorgung",

        "single_board_computer":
            "Single-Board-Computer",

        "unknown":
            "Unbekannt",
    }


    return labels.get(
        category,
        category or "Unbekannt"
    )


# ==========================================================
# Ports ausgeben
# ==========================================================

def print_ports(ports):
    """
    Zeigt die offenen Ports eines Gerätes.

    Die erste Zeile bekommt das normale Feldlabel.
    Weitere Ports werden darunter eingerückt.
    """

    if not ports:

        print(
            "Ports.......: -"
        )

        return


    for index, port in enumerate(
        ports
    ):

        port_number = display_value(
            port.get(
                "port"
            )
        )


        protocol = display_value(
            port.get(
                "protocol"
            )
        )


        service = display_value(
            port.get(
                "service"
            )
        )


        port_text = (
            f"{port_number}/{protocol}"
        )


        if index == 0:

            print(
                f"Ports.......: "
                f"{port_text:<8}  "
                f"{service}"
            )

        else:

            print(
                f"              "
                f"{port_text:<8}  "
                f"{service}"
            )


# ==========================================================
# Einzelnes Gerät ausgeben
# ==========================================================

def print_device(
    connection,
    device_id
):
    """
    Gibt den aktuellen bekannten Zustand eines Gerätes aus.

    Neben den Rohdaten werden jetzt auch die dauerhaft
    gespeicherten Klassifikationsergebnisse angezeigt.
    """

    devices = get_inventory(
        connection,
        device_id
    )


    if not devices:

        print(
            f"Gerät {device_id} "
            f"wurde nicht gefunden."
        )

        return


    device = devices[0]


    classification = get_saved_classification(
        connection,
        device_id
    )


    os_info = (
        device.get(
            "os"
        )
        or {}
    )


    print("-" * 80)


    # ======================================================
    # Identität
    # ======================================================

    print(
        f"Geräte-ID...: "
        f"{display_value(device.get('id'))}"
    )


    print(
        f"IP..........: "
        f"{display_value(device.get('ip'))}"
    )


    print(
        f"MAC.........: "
        f"{display_value(device.get('mac'))}"
    )


    print(
        f"Hersteller..: "
        f"{display_value(device.get('vendor'))}"
    )


    print(
        f"Hostname....: "
        f"{display_value(device.get('hostname'))}"
    )


    print(
        f"Identität...: "
        f"{display_value(device.get('identity_status'))}"
    )


    # ======================================================
    # Klassifikation
    # ======================================================

    if classification:

        print(
            f"Kategorie...: "
            f"{get_category_label(classification.get('category'))}"
        )


        print(
            f"Untertyp....: "
            f"{display_value(classification.get('subtype'))}"
        )


        confidence = classification.get(
            "confidence"
        )


        if (
            confidence is None
            or confidence == 0
        ):

            print(
                "Confidence..: -"
            )

        else:

            print(
                f"Confidence..: "
                f"{confidence} %"
            )


    else:

        print(
            "Kategorie...: -"
        )

        print(
            "Untertyp....: -"
        )

        print(
            "Confidence..: -"
        )


    # ======================================================
    # Betriebssystem
    # ======================================================

    print(
        f"OS..........: "
        f"{display_value(os_info.get('name'))}"
    )


    accuracy = os_info.get(
        "accuracy"
    )


    if accuracy is None:

        print(
            "Genauigkeit.: -"
        )

    else:

        print(
            f"Genauigkeit.: "
            f"{accuracy} %"
        )


    # ======================================================
    # Ports
    # ======================================================

    print_ports(
        device.get(
            "ports"
        )
        or []
    )


    # ======================================================
    # Zeitinformationen
    # ======================================================

    print(
        f"Erstmals....: "
        f"{display_value(device.get('first_seen'))}"
    )


    print(
        f"Zuletzt.....: "
        f"{display_value(device.get('last_seen'))}"
    )


    print(
        f"Portscan....: "
        f"{display_value(device.get('port_scan_at'))}"
    )


    print(
        f"OS-Scan.....: "
        f"{display_value(device.get('os_scan_at'))}"
    )


    print("-" * 80)
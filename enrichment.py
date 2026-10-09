import argparse
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from classifier import classify_device

from database import (
    abort_scan_run,
    fail_scan_run,
    finish_scan_run,
    get_connection,
    get_inventory,
    init_database,
    save_network,
    save_os_information,
    start_scan_run,
)

from network import (
    get_default_route,
    get_interface_info,
)


# ==========================================================
# Einstellungen
# ==========================================================

CLASSIFICATION_CONFIDENCE_THRESHOLD = 70

MIN_OS_ACCURACY = 70


# Python wartet etwas länger als Nmaps eigener Host-Timeout.
# Damit können wir unterscheiden zwischen:
#
# - Nmap beendet den Host selbst
# - der komplette Nmap-Prozess hängt
LIGHT_PROCESS_TIMEOUT_SECONDS = 35
DEEP_PROCESS_TIMEOUT_SECONDS = 135
REACHABILITY_TIMEOUT_SECONDS = 15


# ==========================================================
# LIGHT-Portliste
# ==========================================================

LIGHT_PORTS = {
    21,
    22,
    23,
    25,
    53,
    80,
    88,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    464,
    515,
    631,
    636,
    993,
    995,
    2049,
    3128,
    3268,
    3269,
    3306,
    3389,
    5432,
    5985,
    5986,
    6379,
    8006,
    8080,
    8443,
    9100,
}


# ==========================================================
# DEEP-Zusatzports
# ==========================================================

DEEP_ADDITIONAL_PORTS = {
    2049,
    3128,
    3268,
    3269,
    3306,
    3389,
    5432,
    5985,
    5986,
    6379,
    8006,
    8080,
    8443,
    9100,
    10000,
    10002,
    49152,
}


# ==========================================================
# Enrichment-Status-Tabelle
# ==========================================================

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

    connection.commit()


def get_enrichment_status(
    connection,
    network_id,
    device_id
):
    """
    Liest den gespeicherten Enrichment-Status.
    """

    return connection.execute(
        """
        SELECT
            network_id,
            device_id,
            status,
            light_attempted,
            deep_attempted,
            last_stage,
            last_result,
            last_os_name,
            last_os_accuracy,
            last_attempted_at,
            updated_at

        FROM enrichment_status

        WHERE network_id = ?
          AND device_id = ?
        """,
        (
            network_id,
            device_id,
        )
    ).fetchone()


def save_enrichment_status(
    connection,
    network_id,
    device_id,
    status,
    light_attempted=False,
    deep_attempted=False,
    last_stage=None,
    last_result=None,
    os_result=None
):
    """
    Erstellt bzw. aktualisiert den Enrichment-Status.
    """

    os_name = None
    os_accuracy = None

    if os_result:

        os_name = os_result.get(
            "name"
        )

        os_accuracy = os_result.get(
            "accuracy"
        )


    connection.execute(
        """
        INSERT INTO enrichment_status (
            network_id,
            device_id,
            status,
            light_attempted,
            deep_attempted,
            last_stage,
            last_result,
            last_os_name,
            last_os_accuracy,
            last_attempted_at,
            updated_at
        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )

        ON CONFLICT (
            network_id,
            device_id
        )

        DO UPDATE SET

            status = excluded.status,

            light_attempted = MAX(
                enrichment_status.light_attempted,
                excluded.light_attempted
            ),

            deep_attempted = MAX(
                enrichment_status.deep_attempted,
                excluded.deep_attempted
            ),

            last_stage = excluded.last_stage,

            last_result = excluded.last_result,

            last_os_name = excluded.last_os_name,

            last_os_accuracy =
                excluded.last_os_accuracy,

            last_attempted_at =
                CURRENT_TIMESTAMP,

            updated_at =
                CURRENT_TIMESTAMP
        """,
        (
            network_id,
            device_id,
            status,
            1 if light_attempted else 0,
            1 if deep_attempted else 0,
            last_stage,
            last_result,
            os_name,
            os_accuracy,
        )
    )

    connection.commit()


# ==========================================================
# Geräteinformationen
# ==========================================================

def get_device_os(device):
    """
    Liefert gespeicherte OS-Informationen.
    """

    return (
        device.get("os")
        or {}
    )


def has_saved_os(device):
    """
    Ein bereits gespeichertes OS wird nicht
    automatisch erneut ermittelt.
    """

    os_info = get_device_os(
        device
    )

    return bool(
        os_info.get("name")
    )


def get_known_ports(device):
    """
    Liefert bereits bekannte TCP-Ports.
    """

    ports = set()

    for port in (
        device.get("ports", [])
        or []
    ):

        if (
            port.get("protocol") == "tcp"
            and port.get("port") is not None
        ):

            ports.add(
                int(
                    port["port"]
                )
            )

    return ports


# ==========================================================
# Portlisten
# ==========================================================

def build_light_ports(device):
    """
    Kleine Portliste für den schnellen Versuch.
    """

    ports = set(
        LIGHT_PORTS
    )

    ports.update(
        get_known_ports(
            device
        )
    )

    return sorted(
        ports
    )


def build_deep_ports(device):
    """
    DEEP:

    TCP 1-1024
    + interessante hohe Ports
    + bereits bekannte Ports
    """

    ports = set(
        range(
            1,
            1025
        )
    )

    ports.update(
        DEEP_ADDITIONAL_PORTS
    )

    ports.update(
        get_known_ports(
            device
        )
    )

    return sorted(
        ports
    )


# ==========================================================
# Fehlertext aufräumen
# ==========================================================

def summarize_error_text(text):
    """
    Wir wollen nicht Nmaps komplette Ausgabe auf die
    Konsole kippen.

    Deshalb wird nur die letzte sinnvolle Zeile
    übernommen.
    """

    if not text:

        return None


    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]


    if not lines:

        return None


    result = lines[-1]


    if len(result) > 200:

        result = (
            result[:197]
            + "..."
        )


    return result


# ==========================================================
# Schnelle Erreichbarkeitsprüfung
# ==========================================================

def parse_reachability_xml(xml_path):
    """
    Prüft im XML, ob Nmap den Host aktuell als UP sieht.
    """

    try:

        tree = ET.parse(
            xml_path
        )

    except (
        FileNotFoundError,
        ET.ParseError
    ):

        return None


    root = tree.getroot()


    for host_element in root.findall(
        "host"
    ):

        status_element = host_element.find(
            "status"
        )


        if (
            status_element is not None
            and status_element.get("state")
            == "up"
        ):

            return True


    # Falls kein Host-Element vorhanden ist,
    # kann runstats trotzdem eindeutig zeigen,
    # dass kein Host erreichbar war.
    runstats_element = root.find(
        "runstats"
    )


    if runstats_element is not None:

        hosts_element = runstats_element.find(
            "hosts"
        )


        if hosts_element is not None:

            try:

                up_count = int(
                    hosts_element.get(
                        "up",
                        "0"
                    )
                )

                return (
                    up_count > 0
                )

            except ValueError:

                pass


    return False


def check_reachability(ip_address):
    """
    Sehr schneller Nmap-Hostcheck.

    Auf demselben Ethernet-Netz verwendet Nmap dabei
    normalerweise ARP-Erkennung. Das funktioniert auch,
    wenn ein Windows-PC ICMP/Ping blockiert.

    Rückgabezustände:

    reachable
    offline
    timeout
    nmap_error
    parse_error
    """

    with tempfile.TemporaryDirectory(
        prefix="netchecker_presence_"
    ) as temporary_directory:

        xml_path = (
            f"{temporary_directory}/scan.xml"
        )


        command = [
            "sudo",
            "nmap",

            "-sn",

            # Keine DNS-Abfragen.
            # Das macht den kurzen Check schneller.
            "-n",

            "-oX",
            xml_path,

            ip_address,
        ]


        try:

            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=
                    REACHABILITY_TIMEOUT_SECONDS,
            )

        except subprocess.TimeoutExpired:

            return {
                "status": "timeout",
                "message":
                    "Erreichbarkeitsprüfung "
                    "lief in einen Timeout.",
            }


        if process.returncode != 0:

            return {
                "status": "nmap_error",

                "message":
                    summarize_error_text(
                        process.stderr
                    )
                    or (
                        "Nmap beendete die "
                        "Erreichbarkeitsprüfung "
                        "mit einem Fehler."
                    ),

                "returncode":
                    process.returncode,
            }


        reachable = parse_reachability_xml(
            xml_path
        )


        if reachable is None:

            return {
                "status": "parse_error",
                "message":
                    "Nmap-XML der "
                    "Erreichbarkeitsprüfung "
                    "konnte nicht gelesen werden.",
            }


        if reachable:

            return {
                "status": "reachable",
                "message":
                    "Gerät antwortet aktuell.",
            }


        return {
            "status": "offline",
            "message":
                "Gerät antwortet aktuell "
                "nicht auf die Host-Erkennung.",
        }


# ==========================================================
# Serviceinformationen
# ==========================================================

def combine_service_text(
    service_element
):
    """
    Fasst Nmap-Serviceinformationen zusammen.
    """

    if service_element is None:

        return ""


    parts = [
        service_element.get("name"),
        service_element.get("product"),
        service_element.get("version"),
        service_element.get("extrainfo"),
        service_element.get("ostype"),
        service_element.get("devicetype"),
    ]


    for cpe_element in service_element.findall(
        "cpe"
    ):

        if cpe_element.text:

            parts.append(
                cpe_element.text
            )


    return " ".join(
        str(value)
        for value in parts
        if value
    )


# ==========================================================
# OS-Fallback über Services
# ==========================================================

def detect_os_from_services(
    host_element
):
    """
    Falls Nmap -O keinen Treffer bekommt, verwenden wir
    vorhandene Serviceinformationen als schwächere
    zweite Quelle.
    """

    detected_texts = []


    ports_element = host_element.find(
        "ports"
    )


    if ports_element is not None:

        for port_element in ports_element.findall(
            "port"
        ):

            state_element = port_element.find(
                "state"
            )


            if (
                state_element is None
                or state_element.get("state")
                != "open"
            ):

                continue


            service_element = port_element.find(
                "service"
            )


            service_text = combine_service_text(
                service_element
            )


            if service_text:

                detected_texts.append(
                    service_text.lower()
                )


            for script_element in port_element.findall(
                "script"
            ):

                output = script_element.get(
                    "output"
                )


                if output:

                    detected_texts.append(
                        output.lower()
                    )


    hostscript_element = host_element.find(
        "hostscript"
    )


    if hostscript_element is not None:

        for script_element in hostscript_element.findall(
            "script"
        ):

            output = script_element.get(
                "output"
            )


            if output:

                detected_texts.append(
                    output.lower()
                )


    combined = " ".join(
        detected_texts
    )


    if "windows 11" in combined:

        return {
            "name":
                "Microsoft Windows 11 "
                "(Service-Erkennung)",

            "accuracy":
                75,

            "source":
                "nmap_service",
        }


    if "windows 10" in combined:

        return {
            "name":
                "Microsoft Windows 10 "
                "(Service-Erkennung)",

            "accuracy":
                70,

            "source":
                "nmap_service",
        }


    if (
        "microsoft windows" in combined
        or "windows rpc" in combined
        or "windows server" in combined
    ):

        return {
            "name":
                "Microsoft Windows "
                "(Service-Erkennung)",

            "accuracy":
                60,

            "source":
                "nmap_service",
        }


    if "linux" in combined:

        return {
            "name":
                "Linux "
                "(Service-Erkennung)",

            "accuracy":
                50,

            "source":
                "nmap_service",
        }


    return None


# ==========================================================
# Nmap XML auswerten
# ==========================================================

def parse_scan_xml(xml_path):
    """
    Liest das OS-Ergebnis eines LIGHT-/DEEP-Scans.
    """

    try:

        tree = ET.parse(
            xml_path
        )

    except FileNotFoundError:

        return {
            "status": "parse_error",
            "os": None,
            "message":
                "Nmap hat keine XML-Datei erzeugt.",
        }


    except ET.ParseError:

        return {
            "status": "parse_error",
            "os": None,
            "message":
                "Nmap-XML ist unvollständig "
                "oder beschädigt.",
        }


    root = tree.getroot()


    host_element = root.find(
        "host"
    )


    if host_element is None:

        return {
            "status": "no_host_result",
            "os": None,
            "message":
                "Im Nmap-Ergebnis befinden "
                "sich keine Hostdaten.",
        }


    result = {
        "status": "success",
        "os": None,
        "message": None,
    }


    # ======================================================
    # Echtes Nmap OS-Fingerprinting
    # ======================================================

    os_element = host_element.find(
        "os"
    )


    if os_element is not None:

        os_matches = os_element.findall(
            "osmatch"
        )


        if os_matches:

            best_match = max(
                os_matches,
                key=lambda match: int(
                    match.get(
                        "accuracy",
                        "0"
                    )
                )
            )


            result["os"] = {
                "name":
                    best_match.get(
                        "name"
                    ),

                "accuracy":
                    int(
                        best_match.get(
                            "accuracy",
                            "0"
                        )
                    ),

                "source":
                    "nmap_os",
            }


    # ======================================================
    # Service-Fallback
    # ======================================================

    if result["os"] is None:

        result["os"] = (
            detect_os_from_services(
                host_element
            )
        )


    return result


# ==========================================================
# Gemeinsame Nmap-Ausführung
# ==========================================================

def execute_nmap(
    command,
    xml_path,
    process_timeout
):
    """
    Führt einen LIGHT-/DEEP-Scan aus.

    Wir unterscheiden jetzt:

    success
    timeout
    nmap_error
    parse_error
    no_host_result
    """

    try:

        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=process_timeout,
        )


    except subprocess.TimeoutExpired:

        return {
            "status": "timeout",
            "os": None,
            "message":
                "Der Nmap-Prozess hat das "
                "Zeitlimit überschritten.",
        }


    if process.returncode != 0:

        return {
            "status": "nmap_error",

            "os": None,

            "returncode":
                process.returncode,

            "message":
                summarize_error_text(
                    process.stderr
                )
                or (
                    "Nmap wurde mit einem "
                    "Fehlercode beendet."
                ),
        }


    parsed_result = parse_scan_xml(
        xml_path
    )


    return parsed_result


# ==========================================================
# LIGHT
# ==========================================================

def scan_light(device):
    """
    Schneller OS-Versuch.
    """

    ip_address = device.get(
        "ip"
    )


    if not ip_address:

        return {
            "status": "nmap_error",
            "os": None,
            "message":
                "Das Gerät besitzt keine IP-Adresse.",
        }


    ports = build_light_ports(
        device
    )


    port_specification = ",".join(
        str(port)
        for port in ports
    )


    with tempfile.TemporaryDirectory(
        prefix="netchecker_light_"
    ) as temporary_directory:

        xml_path = (
            f"{temporary_directory}/scan.xml"
        )


        command = [
            "sudo",
            "nmap",

            "-Pn",
            "-n",

            "-sS",

            "-O",
            "--osscan-guess",
            "--max-os-tries",
            "1",

            "-sV",
            "--version-light",

            "-T4",

            "--max-retries",
            "1",

            "--host-timeout",
            "25s",

            "-p",
            port_specification,

            "-oX",
            xml_path,

            ip_address,
        ]


        return execute_nmap(
            command,
            xml_path,
            LIGHT_PROCESS_TIMEOUT_SECONDS,
        )


# ==========================================================
# DEEP
# ==========================================================

def scan_deep(device):
    """
    Gründlicher zweiter Versuch.
    """

    ip_address = device.get(
        "ip"
    )


    if not ip_address:

        return {
            "status": "nmap_error",
            "os": None,
            "message":
                "Das Gerät besitzt keine IP-Adresse.",
        }


    ports = build_deep_ports(
        device
    )


    port_specification = ",".join(
        str(port)
        for port in ports
    )


    with tempfile.TemporaryDirectory(
        prefix="netchecker_deep_"
    ) as temporary_directory:

        xml_path = (
            f"{temporary_directory}/scan.xml"
        )


        command = [
            "sudo",
            "nmap",

            "-Pn",
            "-n",

            "-sS",

            "-O",
            "--osscan-guess",
            "--max-os-tries",
            "2",

            "-sV",
            "--version-all",

            "--script",
            "smb-os-discovery",

            "-T4",

            "--max-retries",
            "2",

            "--host-timeout",
            "120s",

            "-p",
            port_specification,

            "-oX",
            xml_path,

            ip_address,
        ]


        return execute_nmap(
            command,
            xml_path,
            DEEP_PROCESS_TIMEOUT_SECONDS,
        )


# ==========================================================
# OS-Ergebnis bewerten
# ==========================================================

def is_usable_os_result(os_result):
    """
    Nur ausreichend belastbare Ergebnisse werden
    dauerhaft gespeichert.
    """

    if not os_result:

        return False


    if not os_result.get(
        "name"
    ):

        return False


    accuracy = int(
        os_result.get(
            "accuracy",
            0
        )
    )


    return (
        accuracy
        >= MIN_OS_ACCURACY
    )


# ==========================================================
# OS speichern
# ==========================================================

def save_detected_os(
    connection,
    network_id,
    scan_run_id,
    device,
    os_result
):
    """
    Speichert das erkannte OS.

    get_inventory() liefert "id".
    save_os_information() erwartet "device_id".
    """

    enriched_host = dict(
        device
    )


    enriched_host[
        "device_id"
    ] = device[
        "id"
    ]


    enriched_host[
        "os"
    ] = os_result


    save_os_information(
        connection,
        network_id,
        scan_run_id,
        enriched_host
    )


# ==========================================================
# Präsenz laut Datenbank
# ==========================================================

def get_present_device_ids(
    connection,
    network_id
):
    """
    Liefert Geräte, die laut letzter Discovery
    momentan als vorhanden gelten.

    Der zusätzliche Live-Check vor Enrichment bleibt
    trotzdem nötig, weil dieser Zustand inzwischen
    veraltet sein kann.
    """

    rows = connection.execute(
        """
        SELECT device_id

        FROM device_presence

        WHERE network_id = ?
          AND state = 'present'
        """,
        (network_id,)
    ).fetchall()


    return {
        row["device_id"]
        for row in rows
    }


# ==========================================================
# Kandidaten auswählen
# ==========================================================

def get_enrichment_targets(
    connection,
    network_id,
    ip_filter=None,
    force=False
):
    """
    Überspringt normalerweise:

    - bekannte Betriebssysteme
    - sichere Klassifikationen
    - bereits erfolglos vollständig untersuchte Geräte

    --force ignoriert diese gespeicherten Entscheidungen
    für genau eine angegebene IP.
    """

    inventory = get_inventory(
        connection
    )


    present_ids = get_present_device_ids(
        connection,
        network_id
    )


    targets = []


    stats = {
        "total": 0,
        "not_present": 0,
        "os_known": 0,
        "classified": 0,
        "no_os_detected": 0,
        "targets": 0,
    }


    for device in inventory:

        if (
            ip_filter is not None
            and device.get("ip")
            != ip_filter
        ):

            continue


        stats["total"] += 1


        if (
            present_ids
            and device["id"]
            not in present_ids
        ):

            stats[
                "not_present"
            ] += 1

            continue


        status = get_enrichment_status(
            connection,
            network_id,
            device["id"]
        )


        if not force:

            if has_saved_os(
                device
            ):

                stats[
                    "os_known"
                ] += 1

                continue


            if (
                status is not None
                and status["status"]
                == "no_os_detected"
            ):

                stats[
                    "no_os_detected"
                ] += 1

                continue


        classification = classify_device(
            device
        )


        if (
            not force
            and classification[
                "confidence"
            ]
            >= CLASSIFICATION_CONFIDENCE_THRESHOLD
        ):

            stats[
                "classified"
            ] += 1

            continue


        targets.append(
            (
                device,
                classification
            )
        )


        stats[
            "targets"
        ] += 1


    return (
        targets,
        stats
    )


# ==========================================================
# Ausgabe
# ==========================================================

def print_selection_stats(stats):
    """
    Zeigt die Kandidatenauswahl.
    """

    print()
    print("=" * 80)
    print("Enrichment-Auswahl")
    print("=" * 80)

    print(
        f"Geprüfte Geräte..........: "
        f"{stats['total']}"
    )

    print(
        f"Nicht aktuell vorhanden..: "
        f"{stats['not_present']}"
    )

    print(
        f"OS bereits bekannt.......: "
        f"{stats['os_known']}"
    )

    print(
        f"Schon sicher klassifiziert: "
        f"{stats['classified']}"
    )

    print(
        f"OS bereits erfolglos gesucht: "
        f"{stats['no_os_detected']}"
    )

    print(
        f"Neue Kandidaten..........: "
        f"{stats['targets']}"
    )

    print("=" * 80)


def print_classification_summary(
    title,
    device,
    classification
):
    """
    Kompakte Geräteausgabe.
    """

    print()
    print(title)


    print(
        f"  Geräte-ID...: "
        f"{device.get('id') or '-'}"
    )


    print(
        f"  IP..........: "
        f"{device.get('ip') or '-'}"
    )


    os_info = get_device_os(
        device
    )


    print(
        f"  OS..........: "
        f"{os_info.get('name') or '-'}"
    )


    if os_info:

        print(
            f"  OS-Quelle...: "
            f"{os_info.get('source') or '-'}"
        )

        print(
            f"  OS-Genauigk.: "
            f"{os_info.get('accuracy', '-')} %"
        )


    print(
        f"  Kategorie...: "
        f"{classification['category_label']}"
    )


    print(
        f"  Untertyp....: "
        f"{classification['subtype']}"
    )


    if classification["confidence"]:

        print(
            f"  Confidence..: "
            f"{classification['confidence']} %"
        )

    else:

        print(
            "  Confidence..: -"
        )


def print_scan_result(
    scan_type,
    result
):
    """
    Zeigt einen verständlichen LIGHT-/DEEP-Status.
    """

    status = result.get(
        "status"
    )


    print()


    if status == "timeout":

        print(
            f"  {scan_type}: TIMEOUT"
        )

        print(
            f"    {result.get('message')}"
        )

        return


    if status == "nmap_error":

        print(
            f"  {scan_type}: NMAP-FEHLER"
        )

        print(
            f"    {result.get('message')}"
        )


        if result.get(
            "returncode"
        ) is not None:

            print(
                f"    Returncode.: "
                f"{result.get('returncode')}"
            )

        return


    if status == "parse_error":

        print(
            f"  {scan_type}: XML-FEHLER"
        )

        print(
            f"    {result.get('message')}"
        )

        return


    if status == "no_host_result":

        print(
            f"  {scan_type}: KEINE HOSTDATEN"
        )

        print(
            f"    {result.get('message')}"
        )

        return


    os_result = result.get(
        "os"
    )


    if os_result is None:

        print(
            f"  {scan_type}: Scan erfolgreich, "
            f"aber kein OS erkannt"
        )

        return


    print(
        f"  {scan_type}:"
    )

    print(
        f"    Name.......: "
        f"{os_result.get('name') or '-'}"
    )

    print(
        f"    Quelle.....: "
        f"{os_result.get('source') or '-'}"
    )

    print(
        f"    Genauigkeit: "
        f"{os_result.get('accuracy', '-')} %"
    )


# ==========================================================
# Einzelnes Gerät anreichern
# ==========================================================

def enrich_device(
    connection,
    network_id,
    scan_run_id,
    device,
    force=False
):
    """
    Ablauf:

    1. aktuelle Erreichbarkeit prüfen

    2. LIGHT

    3. falls notwendig DEEP

    Offline/Timeout/technische Fehler werden NICHT als
    dauerhaft "OS nicht ermittelbar" gespeichert.
    """

    device_id = device[
        "id"
    ]

    ip_address = device.get(
        "ip"
    )


    # ======================================================
    # 0. LIVE-ERREICHBARKEIT
    # ======================================================

    print()
    print(
        "  Vorprüfung: aktuelle Erreichbarkeit"
    )


    reachability = check_reachability(
        ip_address
    )


    reachability_status = (
        reachability.get(
            "status"
        )
    )


    if (
        reachability_status
        == "reachable"
    ):

        print(
            "  Ergebnis....: ERREICHBAR"
        )


    elif (
        reachability_status
        == "offline"
    ):

        print(
            "  Ergebnis....: OFFLINE / "
            "NICHT ERREICHBAR"
        )

        print(
            f"  Hinweis.....: "
            f"{reachability.get('message')}"
        )


        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="temporarily_unreachable",
            light_attempted=False,
            deep_attempted=False,
            last_stage="reachability",
            last_result="offline",
        )


        return {
            "success": False,
            "technical_error": False,
            "temporary_unreachable": True,
            "timeout": False,
            "stage": "reachability",
            "os": None,
        }


    elif (
        reachability_status
        == "timeout"
    ):

        print(
            "  Ergebnis....: TIMEOUT"
        )

        print(
            f"  Hinweis.....: "
            f"{reachability.get('message')}"
        )


        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="technical_error",
            light_attempted=False,
            deep_attempted=False,
            last_stage="reachability",
            last_result="timeout",
        )


        return {
            "success": False,
            "technical_error": True,
            "temporary_unreachable": False,
            "timeout": True,
            "stage": "reachability",
            "os": None,
        }


    else:

        print(
            "  Ergebnis....: TECHNISCHER FEHLER"
        )

        print(
            f"  Hinweis.....: "
            f"{reachability.get('message')}"
        )


        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="technical_error",
            light_attempted=False,
            deep_attempted=False,
            last_stage="reachability",
            last_result=reachability_status,
        )


        return {
            "success": False,
            "technical_error": True,
            "temporary_unreachable": False,
            "timeout": False,
            "stage": "reachability",
            "os": None,
        }


    # ======================================================
    # Bisheriger Status
    # ======================================================

    saved_status = get_enrichment_status(
        connection,
        network_id,
        device_id
    )


    # ======================================================
    # 1. LIGHT
    # ======================================================

    light_already_done = (
        saved_status is not None
        and saved_status[
            "light_attempted"
        ] == 1
    )


    if (
        light_already_done
        and not force
    ):

        print()
        print(
            "  LIGHT wurde früher bereits "
            "erfolgreich durchgeführt."
        )

        print(
            "  Weiter mit DEEP."
        )


    else:

        print()
        print(
            "  Stufe 1: LIGHT-Enrichment"
        )


        light_result = scan_light(
            device
        )


        print_scan_result(
            "LIGHT-Ergebnis",
            light_result
        )


        if (
            light_result["status"]
            != "success"
        ):

            save_enrichment_status(
                connection,
                network_id,
                device_id,
                status="technical_error",
                light_attempted=False,
                deep_attempted=False,
                last_stage="light",
                last_result=
                    light_result[
                        "status"
                    ],
            )


            return {
                "success": False,
                "technical_error": True,
                "temporary_unreachable": False,
                "timeout":
                    light_result["status"]
                    == "timeout",
                "stage": "light",
                "os": None,
            }


        light_os = light_result.get(
            "os"
        )


        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="in_progress",
            light_attempted=True,
            deep_attempted=False,
            last_stage="light",
            last_result=(
                "usable_os"
                if is_usable_os_result(
                    light_os
                )
                else "no_usable_os"
            ),
            os_result=light_os,
        )


        if is_usable_os_result(
            light_os
        ):

            print()
            print(
                "  LIGHT-Ergebnis ist ausreichend."
            )

            print(
                "  OS wird gespeichert."
            )

            print(
                "  DEEP ist nicht notwendig."
            )


            save_detected_os(
                connection,
                network_id,
                scan_run_id,
                device,
                light_os
            )


            save_enrichment_status(
                connection,
                network_id,
                device_id,
                status="os_found",
                light_attempted=True,
                deep_attempted=False,
                last_stage="light",
                last_result="os_found",
                os_result=light_os,
            )


            return {
                "success": True,
                "technical_error": False,
                "temporary_unreachable": False,
                "timeout": False,
                "stage": "light",
                "os": light_os,
            }


    # ======================================================
    # 2. DEEP
    # ======================================================

    print()
    print(
        "  LIGHT brachte kein "
        "ausreichendes OS."
    )

    print(
        "  Stufe 2: DEEP-Enrichment"
    )


    deep_result = scan_deep(
        device
    )


    print_scan_result(
        "DEEP-Ergebnis",
        deep_result
    )


    if (
        deep_result["status"]
        != "success"
    ):

        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="technical_error",
            light_attempted=True,
            deep_attempted=False,
            last_stage="deep",
            last_result=
                deep_result[
                    "status"
                ],
        )


        return {
            "success": False,
            "technical_error": True,
            "temporary_unreachable": False,
            "timeout":
                deep_result["status"]
                == "timeout",
            "stage": "deep",
            "os": None,
        }


    deep_os = deep_result.get(
        "os"
    )


    if is_usable_os_result(
        deep_os
    ):

        print()
        print(
            "  DEEP-Ergebnis ist ausreichend."
        )

        print(
            "  OS wird gespeichert."
        )


        save_detected_os(
            connection,
            network_id,
            scan_run_id,
            device,
            deep_os
        )


        save_enrichment_status(
            connection,
            network_id,
            device_id,
            status="os_found",
            light_attempted=True,
            deep_attempted=True,
            last_stage="deep",
            last_result="os_found",
            os_result=deep_os,
        )


        return {
            "success": True,
            "technical_error": False,
            "temporary_unreachable": False,
            "timeout": False,
            "stage": "deep",
            "os": deep_os,
        }


    # ======================================================
    # LIGHT + DEEP sauber durchgeführt
    # aber kein brauchbares OS
    # ======================================================

    print()
    print(
        "  LIGHT und DEEP wurden technisch "
        "erfolgreich durchgeführt."
    )

    print(
        "  Es konnte trotzdem kein ausreichend "
        "zuverlässiges OS ermittelt werden."
    )

    print(
        "  Dieses Gerät wird künftig nicht "
        "automatisch erneut OS-gescannt."
    )


    save_enrichment_status(
        connection,
        network_id,
        device_id,
        status="no_os_detected",
        light_attempted=True,
        deep_attempted=True,
        last_stage="deep",
        last_result="no_usable_os",
        os_result=deep_os,
    )


    return {
        "success": False,
        "technical_error": False,
        "temporary_unreachable": False,
        "timeout": False,
        "stage": "deep",
        "os": None,
    }


# ==========================================================
# Gesamtlauf
# ==========================================================

def run_enrichment(
    connection,
    network_id,
    targets,
    force=False
):
    """
    Führt alle Enrichment-Kandidaten nacheinander aus.
    """

    if not targets:

        print()
        print(
            "Keine Geräte benötigen momentan "
            "einen OS-Enrichment-Scan."
        )

        return


    scan_run_id = start_scan_run(
        connection,
        network_id,
        "enrichment"
    )


    total = len(
        targets
    )


    processed = 0
    failed = 0

    light_success = 0
    deep_success = 0

    without_os = 0

    temporarily_unreachable = 0

    timeouts = 0

    technical_errors = 0


    try:

        print()
        print("=" * 80)
        print("NetChecker Enrichment")
        print("=" * 80)

        print(
            f"Kandidaten....: "
            f"{total}"
        )

        print(
            f"Scan-Run-ID...: "
            f"{scan_run_id}"
        )

        print()


        for index, (
            device,
            old_classification
        ) in enumerate(
            targets,
            start=1
        ):

            print("=" * 80)

            print(
                f"[{index:02d}/{total:02d}] "
                f"Enrichment für "
                f"{device.get('ip')}"
            )

            print("=" * 80)


            print_classification_summary(
                "Vorher:",
                device,
                old_classification
            )


            result = enrich_device(
                connection,
                network_id,
                scan_run_id,
                device,
                force=force
            )


            if result[
                "temporary_unreachable"
            ]:

                temporarily_unreachable += 1

                failed += 1


            elif result[
                "technical_error"
            ]:

                technical_errors += 1

                failed += 1


                if result[
                    "timeout"
                ]:

                    timeouts += 1


            else:

                processed += 1


                if result[
                    "success"
                ]:

                    if (
                        result["stage"]
                        == "light"
                    ):

                        light_success += 1

                    else:

                        deep_success += 1

                else:

                    without_os += 1


            # ==================================================
            # Aktuellen Zustand erneut aus SQLite lesen
            # ==================================================

            refreshed_devices = get_inventory(
                connection,
                device["id"]
            )


            if not refreshed_devices:

                continue


            refreshed_device = (
                refreshed_devices[0]
            )


            new_classification = (
                classify_device(
                    refreshed_device
                )
            )


            print_classification_summary(
                "Nachher:",
                refreshed_device,
                new_classification
            )


        finish_scan_run(
            connection,
            scan_run_id,
            hosts_found=total,
            hosts_processed=processed,
            hosts_failed=failed
        )


        print()
        print("=" * 80)
        print("Enrichment abgeschlossen")
        print("=" * 80)

        print(
            f"Kandidaten..........: "
            f"{total}"
        )

        print(
            f"Verarbeitet..........: "
            f"{processed}"
        )

        print(
            f"LIGHT erfolgreich....: "
            f"{light_success}"
        )

        print(
            f"DEEP erfolgreich.....: "
            f"{deep_success}"
        )

        print(
            f"OS nicht ermittelbar.: "
            f"{without_os}"
        )

        print(
            f"Momentan offline.....: "
            f"{temporarily_unreachable}"
        )

        print(
            f"Timeouts..............: "
            f"{timeouts}"
        )

        print(
            f"Technische Fehler.....: "
            f"{technical_errors}"
        )

        print("=" * 80)


    except KeyboardInterrupt:

        abort_scan_run(
            connection,
            scan_run_id
        )

        print()
        print(
            "Enrichment wurde abgebrochen."
        )

        raise


    except Exception as error:

        fail_scan_run(
            connection,
            scan_run_id,
            error
        )

        raise


# ==========================================================
# Argumente
# ==========================================================

def parse_arguments():
    """
    --force darf absichtlich nur zusammen mit
    genau einer IP verwendet werden.
    """

    parser = argparse.ArgumentParser(
        description=(
            "NetChecker automatisches "
            "OS-Enrichment"
        )
    )


    parser.add_argument(
        "--ip",
        help=(
            "Nur diese IP als "
            "Enrichment-Kandidaten betrachten."
        )
    )


    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Gespeicherten Enrichment-Status "
            "für diese IP ignorieren."
        )
    )


    arguments = parser.parse_args()


    if (
        arguments.force
        and not arguments.ip
    ):

        parser.error(
            "--force darf nur zusammen "
            "mit --ip verwendet werden."
        )


    return arguments


# ==========================================================
# Hauptprogramm
# ==========================================================

def main():

    arguments = parse_arguments()


    connection = get_connection()


    try:

        init_database(
            connection
        )


        init_enrichment_status_table(
            connection
        )


        # ==================================================
        # Aktuelles Netzwerk
        # ==================================================

        route = get_default_route()


        if not route:

            print(
                "Keine Default-Route gefunden."
            )

            return


        interface_name = route.get(
            "interface"
        )


        gateway = route.get(
            "gateway"
        )


        if not interface_name:

            print(
                "Keine Netzwerkschnittstelle gefunden."
            )

            return


        interface_info = get_interface_info(
            interface_name
        )


        if not interface_info:

            print(
                "Netzwerkinformationen konnten "
                "nicht ermittelt werden."
            )

            return


        network_id = save_network(
            connection,
            interface_info["network"],
            interface_info["interface"],
            gateway
        )


        # ==================================================
        # Kandidaten
        # ==================================================

        targets, stats = get_enrichment_targets(
            connection,
            network_id,
            ip_filter=arguments.ip,
            force=arguments.force
        )


        print_selection_stats(
            stats
        )


        if arguments.force:

            print()
            print(
                "FORCE-Modus: gespeicherter Status "
                "wird für dieses Gerät ignoriert."
            )


        run_enrichment(
            connection,
            network_id,
            targets,
            force=arguments.force
        )


    finally:

        connection.close()


if __name__ == "__main__":
    main()
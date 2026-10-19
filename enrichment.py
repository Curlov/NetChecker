from transactions import atomic
import argparse
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from classifier import classify_device
from scan_parser import parse_services, scan_metadata
from os_analysis import infer_os_claims, service_evidence_sufficient
from runtime_lock import exclusive_cycle
from datetime import datetime, timezone, timedelta
import os

from database import (
    abort_scan_run,
    fail_scan_run,
    finish_scan_run,
    get_connection,
    get_inventory,
    init_database,
    save_network,
    save_os_information,
    save_port_scan,
    save_os_claims,
    start_scan_run,
)

from network import (
    get_default_route,
    get_interface_info,
)
from netchecker_config import nmap_profile


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
    """Compatibility entry point for the central schema coordinator."""
    from schema import initialize_database
    initialize_database(connection)


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


        profile = nmap_profile("reachability")
        command = ["sudo", "nmap", *profile["arguments"], "-oX", xml_path, ip_address]


        try:

            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=profile["timeout_seconds"],
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
        "ports": parse_services(host_element),
        "scan_metadata": scan_metadata(root, host_element),
        "os_classes": [dict(element.attrib, cpe=[c.text for c in element.findall('cpe') if c.text])
                       for element in host_element.findall('os/osmatch/osclass')],
        "os_matches": [dict(element.attrib) for element in host_element.findall('os/osmatch')],
        "host_scripts": [ET.tostring(element, encoding='unicode') for element in host_element.findall('hostscript')],
    }
    if not result['scan_metadata']['complete']:
        result['status'] = 'incomplete'
        result['message'] = 'Unvollstaendiger Scan; keine dauerhafte Negativentscheidung'


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


        profile = nmap_profile("os_light")
        command = ["sudo", "nmap", *profile["arguments"], "-p", port_specification,
                   "-oX", xml_path, ip_address]


        return execute_nmap(
            command,
            xml_path,
            profile["timeout_seconds"],
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


        profile = nmap_profile("os_deep")
        command = ["sudo", "nmap", *profile["arguments"], "-p", port_specification,
                   "-oX", xml_path, ip_address]


        return execute_nmap(
            command,
            xml_path,
            profile["timeout_seconds"],
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

def persist_enrichment_result(connection, network_id, scan_run_id, device, result, stage):
    if result.get('status') not in {'success', 'incomplete'}:
        return
    host = dict(result, device_id=device['id'], ip=device.get('ip'))
    with atomic(connection):
        save_port_scan(connection, network_id, scan_run_id, host,
                       source='nmap_' + stage, observation_type='service_scan')
        save_os_claims(connection, network_id, scan_run_id, device['id'],
                       infer_os_claims(result.get('os'), os_classes=result.get('os_classes') or [],
                                       host_scripts=result.get('host_scripts') or []))
        connection.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
            observation_type,source,data_json) VALUES(?,?,?,'enrichment_result',?,?)""",
            (network_id,device['id'],scan_run_id,'nmap_' + stage,
             json.dumps(host, ensure_ascii=False)))


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


def build_service_ports(device):
    """Service probes stay within TCP ports already observed as open."""
    known = {int(port['port']) for port in device.get('ports') or ()
                   if port.get('protocol') == 'tcp' and port.get('state') == 'open'
                   and port.get('port') is not None and 1 <= int(port['port']) <= 65535}
    requested = device.get('_service_ports')
    return sorted(known if requested is None else known.intersection(requested))


def service_enrichment_due(connection, network_id, device):
    """Return due known ports and last attempt time; reuse recent complete probes."""
    ports = build_service_ports(device)
    if not ports or not device.get('ip'):
        return [], ''
    latest = connection.execute("""SELECT observation_type,data_json,observed_at FROM observations
        WHERE network_id=? AND device_id=?
          AND observation_type IN ('service_enrichment_attempt','service_scan')
        ORDER BY id DESC LIMIT 1""", (network_id,device['id'])).fetchone()
    if latest is None:
        return ports, ''
    try:
        payload = json.loads(latest['data_json'] or '{}')
        if not isinstance(payload,dict):
            payload = {}
    except (ValueError,TypeError):
        payload = {}
    complete = (payload.get('status') == 'success' if latest['observation_type']=='service_enrichment_attempt'
                else bool((payload.get('scan_metadata') or {}).get('complete')))
    now = datetime.now(timezone.utc)
    if not complete and latest['observed_at'] >= (now-timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'):
        return [], latest['observed_at']
    days = max(1,int(os.environ.get('NETCHECKER_SERVICE_RETRY_DAYS','7')))
    cutoff = (now-timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    recent = connection.execute("""SELECT observation_type,data_json FROM observations
        WHERE network_id=? AND device_id=? AND observed_at>=?
          AND observation_type IN ('service_enrichment_attempt','service_scan')""",
        (network_id,device['id'],cutoff))
    covered = set()
    from scan_parser import covered_port
    for row in recent:
        try:
            result = json.loads(row['data_json'] or '{}')
            if not isinstance(result,dict):
                continue
            if row['observation_type']=='service_enrichment_attempt' and result.get('status')=='success':
                covered.update(result.get('requested_ports') or ())
            elif row['observation_type']=='service_scan':
                covered.update(port for port in ports if covered_port(result.get('scan_metadata') or {},'tcp',port))
        except (ValueError,TypeError):
            continue
    return [port for port in ports if port not in covered], latest['observed_at']


def scan_services(device):
    ports = build_service_ports(device)
    if not ports or not device.get('ip'):
        return {'status':'no_ports','ports':[],'os':None}
    with tempfile.TemporaryDirectory(prefix='netchecker_services_') as directory:
        xml_path = f'{directory}/scan.xml'
        profile = nmap_profile("services")
        command = ['sudo','nmap',*profile['arguments'],
                   '-p',','.join(str(port) for port in ports),'-oX',xml_path,device['ip']]
        return execute_nmap(command,xml_path,profile["timeout_seconds"])


def enrich_services(connection, network_id, scan_run_id, device):
    """Independent LIGHT service stage; does not overwrite OS retry decisions."""
    requested = build_service_ports(device)
    try:
        result = scan_services(device)
    except (OSError,ValueError):
        result = {'status':'nmap_error','ports':[],'os':None}
    if result.get('status') == 'success' and not (result.get('scan_metadata') or {}).get('complete'):
        result = dict(result,status='incomplete')
    with atomic(connection):
        persist_enrichment_result(connection,network_id,scan_run_id,device,result,'service_light')
        connection.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
            observation_type,source,data_json) VALUES(?,?,?,'service_enrichment_attempt','nmap_service_light',?)""",
            (network_id,device['id'],scan_run_id,json.dumps({'status':result.get('status'),
                'requested_ports':requested,'scan_metadata':result.get('scan_metadata') or {}},ensure_ascii=False)))
    success = result.get('status') == 'success'
    return {'success':success,'technical_error':not success,'temporary_unreachable':False,
            'timeout':result.get('status')=='timeout','stage':'service_light','os':None}


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

    Service-Enrichment wird unabhängig ausgewählt, auf bekannte offene
    TCP-Ports beschränkt und separat budgetiert.
    """

    inventory = get_inventory(
        connection, network_id=network_id
    )


    present_ids = get_present_device_ids(
        connection,
        network_id
    )


    targets = []
    service_candidates = []


    stats = {
        "total": 0,
        "not_present": 0,
        "os_known": 0,
        "classified": 0,
        "no_os_detected": 0,
        "targets": 0,
        "service_targets": 0,
        "service_deferred": 0,
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
            device["id"]
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

        # Select service work before applying OS-specific exclusion rules.
        service_due, attempted_at = service_enrichment_due(connection,network_id,device)
        if service_due and not force:
            service_candidates.append((attempted_at,dict(device,_service_ports=service_due)))


        if not force:

            summary = device.get('os_summary') or {}
            if any(summary.get(kind) and not summary[kind].get('stale') for kind in ('family','distribution')):
                stats['os_known'] += 1
                continue

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

                # Automatic retries are opt-in; existing deployments keep their scan budget.
                retry_days = max(0, int(os.environ.get('NETCHECKER_ENRICHMENT_RETRY_DAYS', '0')))
                cutoff = (datetime.now(timezone.utc) - timedelta(days=retry_days)).strftime('%Y-%m-%d %H:%M:%S')
                if retry_days and status['last_attempted_at'] < cutoff:
                    classification = classify_device(device)
                    targets.append((device, classification))
                    stats['targets'] += 1
                    continue

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
        targets + select_service_targets(targets,service_candidates,stats),
        stats
    )


def select_service_targets(os_targets, candidates, stats):
    """Never service-probe a host twice in the same cycle; oldest attempts first."""
    os_ids = {device['id'] for device,_ in os_targets}
    eligible = sorted(((attempted,device) for attempted,device in candidates if device['id'] not in os_ids),
                      key=lambda item:(item[0],item[1]['id']))
    budget = max(0,int(os.environ.get('NETCHECKER_SERVICE_MAX_HOSTS','4')))
    selected = [(dict(device,_enrichment_goal='service'),classify_device(device))
                for _,device in eligible[:budget]]
    stats['service_targets'] = len(selected)
    stats['service_deferred'] = max(0,len(eligible)-len(selected))
    stats['targets'] += len(selected)
    return selected


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
    print(f"Service-Kandidaten.......: {stats['service_targets']}")
    print(f"Service wegen Budget später: {stats['service_deferred']}")

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
        persist_enrichment_result(connection, network_id, scan_run_id, device, light_result, 'light')


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

        if service_evidence_sufficient(light_result):
            save_enrichment_status(connection, network_id, device_id,
                status='service_evidence_found', light_attempted=True,
                last_stage='light', last_result='service_evidence')
            return {'success': True, 'technical_error': False,
                    'temporary_unreachable': False, 'timeout': False,
                    'stage': 'light', 'os': light_os}


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
    persist_enrichment_result(connection, network_id, scan_run_id, device, deep_result, 'deep')


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
            "einen Enrichment-Scan."
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
    service_success = 0

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


            if device.get('_enrichment_goal') == 'service':
                print('  Stufe: Service-LIGHT auf bekannten offenen TCP-Ports; keine OS-Erkennung')
                result = enrich_services(connection,network_id,scan_run_id,device)
            else:
                result = enrich_device(connection,network_id,scan_run_id,device,force=force)


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

                    if result['stage'] == 'service_light':
                        service_success += 1
                    elif (
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
                device["id"], network_id=network_id
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
        print(f"Service-LIGHT erfolgreich: {service_success}")

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

@exclusive_cycle
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

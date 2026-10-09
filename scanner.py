import subprocess
import tempfile
import sys
import time
import xml.etree.ElementTree as ET


def run_nmap(command):
    """
    Führt einen Nmap-Befehl aus.
    """

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except subprocess.CalledProcessError as error:
        print("Fehler beim Ausführen von Nmap.")
        print(error.stderr)
        sys.exit(1)

    except FileNotFoundError:
        print("Nmap wurde nicht gefunden.")
        sys.exit(1)


def get_vendor_from_mac(mac_address):
    """
    Ermittelt anhand der MAC-Adresse den Hersteller
    aus Nmaps MAC-Prefix-Datenbank.
    """

    if not mac_address:
        return None

    prefix = mac_address.replace(":", "").replace("-", "").upper()[:6]

    database = "/usr/share/nmap/nmap-mac-prefixes"

    try:
        with open(database, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                if line.startswith(prefix):

                    parts = line.strip().split(maxsplit=1)

                    if len(parts) == 2:
                        return parts[1]

    except FileNotFoundError:
        return None

    return None


def scan_network(network):
    """
    Sucht nach aktiven Hosts im Netzwerk.
    """

    output = run_nmap(
        ["sudo", "/usr/bin/nmap", "-sn", "-oX", "-", network]
    )

    root = ET.fromstring(output)

    hosts = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        ipv4_address = None
        mac_address = None
        hostname = None
        vendor = None

        for address in host.findall("address"):

            if address.get("addrtype") == "ipv4":
                ipv4_address = address.get("addr")

            elif address.get("addrtype") == "mac":
                mac_address = address.get("addr")
                vendor = address.get("vendor")

        hostname_element = host.find("hostnames/hostname")

        if hostname_element is not None:
            hostname = hostname_element.get("name")

        hosts.append({
            "ip": ipv4_address,
            "mac": mac_address,
            "vendor": vendor,
            "hostname": hostname
        })

    return hosts


def scan_details(hosts):
    """
    Führt einen vollständigen TCP-Scan aller gefundenen Hosts durch.

    Ermittelt:
    - offene TCP-Ports
    - Dienste
    - Versionen
    - Betriebssystem
    """

    ip_addresses = [
        host["ip"]
        for host in hosts
        if host.get("ip")
    ]

    if not ip_addresses:
        return hosts

    command = [
        "sudo",
        "nmap",
        "-sS",
        "-p-",
        "-sV",
        "-O",
        "--open",
        "-oX",
        "-"
    ]

    command.extend(ip_addresses)

    output = run_nmap(command)

    root = ET.fromstring(output)

    # Auswertung kommt als nächster Teil.

    return hosts


def scan_host_details(ip_address):
    """
    Untersucht einen Host ausführlich.

    Ermittelt:
    - alle offenen TCP-Ports
    - Dienste
    - Produktnamen
    - Versionen
    - Betriebssystem

    Während des Scans werden Nmap-Statistiken
    live auf der Konsole ausgegeben.

    Bei einem Fehler wird None zurückgegeben.
    """

    with tempfile.TemporaryDirectory(
        prefix="netchecker_"
    ) as temp_directory:

        xml_path = (
            f"{temp_directory}/scan.xml"
        )

        command = [
            "sudo",
            "nmap",

            "-Pn",
            "-sS",

            "--top-ports",
            "100",

            "-T4",
            "--max-retries",
            "1",

            "--host-timeout",
            "20s",

            "--open",

            "-oX",
            xml_path,

            ip_address
        ]

        """ command = [
            "sudo",
            "nmap",

            "-Pn",
            "-sS",

            "--top-ports",
            "200",

            "-sV",
            "--version-light",

            "-O",
            "--open",

            "--stats-every",
            "10s",

            "-oX",
            xml_path,

            ip_address
        ] """

        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )

        return_code = process.wait()

        if return_code != 0:

            print(
                f"         FEHLER: "
                f"Nmap-Scan von {ip_address} "
                f"fehlgeschlagen."
            )

            return None

        try:

            tree = ET.parse(xml_path)
            root = tree.getroot()

        except (
            FileNotFoundError,
            ET.ParseError
        ) as error:

            print(
                f"         FEHLER beim Lesen "
                f"der Nmap-XML-Datei: {error}"
            )

            return None

        result = {
            "ports": [],
            "os": None
        }

        host_element = root.find("host")

        if host_element is None:
            return result

        # -----------------------------------------
        # Offene TCP-Ports
        # -----------------------------------------

        for port_element in host_element.findall(
            "ports/port"
        ):

            state_element = port_element.find(
                "state"
            )

            if state_element is None:
                continue

            state = state_element.get("state")

            if state != "open":
                continue

            service_element = port_element.find(
                "service"
            )

            service = None
            product = None
            version = None

            if service_element is not None:

                service = service_element.get(
                    "name"
                )

                product = service_element.get(
                    "product"
                )

                version = service_element.get(
                    "version"
                )

            result["ports"].append(
                {
                    "port": int(
                        port_element.get(
                            "portid"
                        )
                    ),
                    "protocol": port_element.get(
                        "protocol"
                    ),
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version
                }
            )

        # -----------------------------------------
        # Betriebssystem
        # -----------------------------------------

        os_matches = host_element.findall(
            "os/osmatch"
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
                "name": best_match.get("name"),
                "accuracy": int(
                    best_match.get(
                        "accuracy",
                        "0"
                    )
                ),
                "source": "nmap"
            }

        return result
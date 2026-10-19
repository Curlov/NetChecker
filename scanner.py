import subprocess
import tempfile
import sys
import time
import xml.etree.ElementTree as ET
from scan_parser import covered_port, parse_services, scan_metadata
from netchecker_config import nmap_profile


def run_nmap(command, timeout_seconds=90):
    """
    Führt einen Nmap-Befehl aus.
    """

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout_seconds,
        )

        return result.stdout

    except subprocess.CalledProcessError as error:
        print("Fehler beim Ausführen von Nmap.")
        print(error.stderr)
        raise RuntimeError("Nmap discovery failed") from error

    except FileNotFoundError:
        print("Nmap wurde nicht gefunden.")
        raise RuntimeError("Nmap executable not found")


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

    profile = nmap_profile("discovery")
    output = run_nmap(
        ["sudo", "/usr/bin/nmap", *profile["arguments"], "-oX", "-", network],
        profile["timeout_seconds"],
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

    command = ["sudo", "nmap", "-sS", "-p-", "-sV", "-O", "--open", "-oX", "-"]

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

        profile = nmap_profile("detail")
        command = [
            "sudo", "nmap", *profile["arguments"],

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

        try:
            process = subprocess.run(command, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True,
                                     timeout=profile["timeout_seconds"])
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        return_code = process.returncode

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
            return None

        if host_element.get("timedout") == "true":
            return None
        result["ports"] = parse_services(host_element)
        result["scan_metadata"] = scan_metadata(root, host_element)
        if not result['scan_metadata']['complete']:
            return None
        return result


KNOWN_PORT_HOST_TIMEOUT = "15s"
KNOWN_PORT_PROCESS_TIMEOUT_SECONDS = 20


def _expand_port_list(value):
    ports = set()
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if "-" in item:
                start, end = (int(part) for part in item.split("-", 1))
                if start < 1 or end > 65535 or start > end:
                    continue
                ports.update(range(start, end + 1))
            else:
                port = int(item)
                if 1 <= port <= 65535:
                    ports.add(port)
        except ValueError:
            continue
    return ports


def scan_known_tcp_ports(ip_address, ports):
    """Check only TCP ports previously observed open; do no service probing."""
    requested = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if not ip_address or not requested:
        return None

    command = [
        "sudo", "/usr/bin/nmap", "-Pn", "-n", "-sS", "-T3",
        "--max-retries", "1", "--host-timeout", KNOWN_PORT_HOST_TIMEOUT,
        "--reason", "-p", ",".join(str(port) for port in requested),
        "-oX", "-", ip_address,
    ]
    xml_text = run_nmap(command, KNOWN_PORT_PROCESS_TIMEOUT_SECONDS)
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return None

    metadata = scan_metadata(root, host)
    found = {}
    for port in parse_services(host):
        if port.get("protocol") != "tcp" or port.get("port") not in requested:
            continue
        state = port.get("state") or "unknown"
        if state in {"open", "closed"}:
            found[port["port"]] = port
        elif state in {"filtered", "open|filtered", "closed|filtered"}:
            port["state"] = "filtered"
            found[port["port"]] = port

    # Nmap groups ports with the same state in <extraports>. Use its exact
    # extrareason port lists to recover per-port closed/filtered results.
    ports_element = host.find("ports")
    if ports_element is not None:
        for extra in ports_element.findall("extraports"):
            extra_state = extra.get("state") or "unknown"
            for reason in extra.findall("extrareasons"):
                listed = _expand_port_list(reason.get("ports"))
                for port_number in listed.intersection(requested):
                    if port_number in found:
                        continue
                    state = extra_state
                    if state not in {"open", "closed"}:
                        state = "filtered"
                    found[port_number] = {
                        "protocol": "tcp", "port": port_number,
                        "state": state, "service": None, "product": None,
                        "version": None,
                    }

    # A missing per-port result is ambiguous, even if Nmap says the host scan
    # completed. Do not let it close a port in inventory.
    if (len(found) != len(requested) or
            not all(covered_port(metadata,'tcp',port) for port in requested)):
        metadata = dict(metadata, complete=False)

    return {
        "ports": [found[port] for port in requested if port in found],
        "os": None,
        "scan_metadata": metadata,
    }

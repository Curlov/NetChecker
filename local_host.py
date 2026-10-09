
import json
import socket
import subprocess
from pathlib import Path


def get_local_host(interface):
    """
    Liest die IPv4-Adresse und MAC-Adresse
    einer lokalen Netzwerkschnittstelle.

    Keine Netzwerkpakete, nur lokale Abfragen.
    """

    interface_path = Path("/sys/class/net") / interface

    if not interface_path.is_dir():
        raise ValueError(
            f"Netzwerkschnittstelle {interface} nicht gefunden"
        )

    mac = (
        (interface_path / "address")
        .read_text(encoding="utf-8")
        .strip()
        .upper()
    )

    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True
    )

    interfaces = json.loads(result.stdout)

    ipv4 = []

    for item in interfaces:
        for address in item.get("addr_info", []):
            if (
                address.get("family") == "inet"
                and address.get("scope") == "global"
            ):
                ipv4.append(address["local"])

    if not ipv4:
        raise RuntimeError(
            f"Keine globale IPv4-Adresse auf {interface}"
        )

    return {
        "ip": ipv4[0],
        "mac": mac,
        "hostname": socket.gethostname(),
        "vendor": None
    }


def enrich_local_host(hosts, interface):
    """
    Ergänzt den eigenen Host in der Nmap-Hostliste.
    Es wird kein zusätzlicher Host erfunden.
    """

    local = get_local_host(interface)

    matches = [
        host for host in hosts
        if host.get("ip") == local["ip"]
    ]

    if len(matches) != 1:
        raise RuntimeError(
            "Lokaler Host in Discovery nicht eindeutig gefunden: "
            f"{local['ip']} ({len(matches)} Treffer)"
        )

    host = matches[0]

    if (
        host.get("mac")
        and host["mac"].upper() != local["mac"]
    ):
        raise RuntimeError(
            "MAC-Konflikt bei lokaler Host-Erkennung"
        )

    host["mac"] = local["mac"]
    host["hostname"] = (
        host.get("hostname") or local["hostname"]
    )

    return hosts

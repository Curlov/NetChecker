import ipaddress
import json
import subprocess
import sys


def run_command(command):
    """
    Führt einen Linux-Befehl aus und gibt dessen Ausgabe zurück.
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
        print(f"Fehler beim Ausführen von: {' '.join(command)}")
        print(error.stderr)
        sys.exit(1)

    except FileNotFoundError:
        print(f"Befehl nicht gefunden: {command[0]}")
        sys.exit(1)


def get_default_route():
    """
    Ermittelt das Interface und Gateway der Standardroute.
    """

    output = run_command(
        ["ip", "-j", "route", "show", "default"]
    )

    routes = json.loads(output)

    if not routes:
        return None

    route = routes[0]

    return {
        "interface": route.get("dev"),
        "gateway": route.get("gateway")
    }


def get_interface_info(interface_name):
    """
    Liest IP- und MAC-Informationen eines Netzwerkinterfaces aus.
    """

    output = run_command(
        ["ip", "-j", "address", "show", "dev", interface_name]
    )

    interfaces = json.loads(output)

    if not interfaces:
        return None

    interface = interfaces[0]

    mac_address = interface.get("address")

    ipv4_address = None
    prefix_length = None

    for address in interface.get("addr_info", []):
        if address.get("family") == "inet":
            ipv4_address = address.get("local")
            prefix_length = address.get("prefixlen")
            break

    if ipv4_address is None or prefix_length is None:
        return None

    network = ipaddress.ip_interface(
        f"{ipv4_address}/{prefix_length}"
    ).network

    return {
        "interface": interface_name,
        "mac": mac_address,
        "ip": ipv4_address,
        "prefix": prefix_length,
        "network": str(network)
    }
import ipaddress
from collections import defaultdict
from mac_analysis import analyze_mac
from fingerprints import match_device as match_fingerprints
from runtime_lock import exclusive_cycle

from database import (
    get_connection,
    get_inventory,
    init_database,
)


# ==========================================================
# Einstellungen
# ==========================================================

MIN_CLASSIFICATION_SCORE = 30


CATEGORY_LABELS = {
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

    "smart_tv":
        "Smart-TV",

    "unknown":
        "Unbekannt",
}


# ==========================================================
# Allgemeine Hilfsfunktionen
# ==========================================================

def normalize(value):
    """
    Wandelt Text in eine einheitliche Kleinschreibweise um.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def add_score(
    scores,
    evidence,
    category,
    points,
    reason
):
    """
    Gibt einer Kategorie Punkte und merkt sich
    gleichzeitig die Begründung.
    """

    scores[category] += points

    evidence[category].append(
        {
            "points": points,
            "reason": reason,
        }
    )


def get_ports(device):
    """
    Liefert die zuletzt bekannten offenen Ports.
    """

    return device.get(
        "ports",
        []
    ) or []


def has_port(
    device,
    port_number,
    protocol="tcp"
):
    """
    Prüft, ob ein bestimmter Port offen ist.
    """

    for port in get_ports(device):

        if (
            port.get("port") == port_number
            and normalize(port.get("state")) == "open"
            and normalize(
                port.get("protocol")
            ) == protocol
        ):

            return True

    return False


def get_open_tcp_port(device, port_number):
    """Return an open TCP port record, if present."""
    for port in get_ports(device):
        try:
            number = int(port.get("port"))
        except (TypeError, ValueError):
            continue

        if (
            number == port_number
            and normalize(port.get("protocol")) == "tcp"
            and normalize(port.get("state")) == "open"
        ):
            return port

    return None


def is_apple_sync_service(port):
    """Recognize the Apple sync/lockdown service on TCP 62078."""
    if not port:
        return False

    service_text = " ".join(
        normalize(port.get(field))
        for field in ("service", "product", "version", "extrainfo", "ostype", "devicetype")
    )
    return any(
        marker in service_text
        for marker in ("iphone-sync", "iphone sync", "apple mobile device", "lockdown")
    )


def count_ports(
    device,
    port_numbers
):
    """
    Zählt, wie viele Ports einer Gruppe vorhanden sind.
    """

    return sum(
        1
        for port_number in port_numbers
        if has_port(
            device,
            port_number
        )
    )


def contains_service_text(
    device,
    search_text
):
    """
    Sucht einen Text in Service, Produkt und Version.
    """

    search_text = normalize(
        search_text
    )

    for port in get_ports(device):

        combined = " ".join(
            [
                normalize(port.get("service")) if normalize(port.get('method')) != 'table' else '',

                normalize(
                    port.get("product")
                ),

                normalize(
                    port.get("version")
                ),
                normalize(port.get('extrainfo')),
                normalize(port.get('ostype')),
                normalize(port.get('devicetype')),
                normalize(' '.join(port.get('cpe') or [])),
            ]
        )

        if search_text in combined:
            return True

    return False


def is_locally_administered_mac(
    mac_address
):
    """
    Erkennt lokal vergebene / randomisierte MAC-Adressen.
    """

    return analyze_mac(mac_address).get("locally_administered", False)


# ==========================================================
# Apple-Hilfsfunktionen
# ==========================================================

def is_ambiguous_apple_os(os_name):
    """
    Erkennt Nmap-Treffer, die Mac UND mobiles Apple-Gerät
    gleichzeitig als Möglichkeit nennen.

    Beispiel:

    Apple macOS ... or iOS ...
    """

    os_name = normalize(
        os_name
    )

    has_macos = (
        "macos" in os_name
        or "mac os" in os_name
    )

    has_ios = (
        "ios" in os_name
    )

    return (
        has_macos
        and has_ios
    )


def is_ios_os(os_name):
    """
    Erkennt einen iOS-/iPadOS-Hinweis.
    """

    os_name = normalize(
        os_name
    )

    return (
        "ios" in os_name
        or "ipados" in os_name
    )


def is_macos_os(os_name):
    """
    Erkennt macOS, aber nur wenn der Treffer
    NICHT gleichzeitig iOS nennt.
    """

    os_name = normalize(
        os_name
    )

    if is_ambiguous_apple_os(
        os_name
    ):
        return False

    return (
        "macos" in os_name
        or "mac os" in os_name
        or (
            "darwin" in os_name
            and "ios" not in os_name
        )
    )


# ==========================================================
# Confidence
# ==========================================================

def calculate_confidence(
    best_score,
    second_score,
    evidence_count
):
    """
    Berechnet eine verständliche Confidence.

    Es handelt sich nicht um eine mathematische
    Wahrscheinlichkeit.
    """

    margin = max(
        0,
        best_score - second_score
    )


    if best_score >= 100:
        confidence = 92

    elif best_score >= 80:
        confidence = 82

    elif best_score >= 60:
        confidence = 70

    elif best_score >= 45:
        confidence = 58

    elif best_score >= 30:
        confidence = 40

    else:
        confidence = 20


    confidence += min(
        5,
        margin // 20
    )


    confidence += min(
        4,
        max(
            0,
            evidence_count - 1
        ) * 2
    )


    return min(
        99,
        confidence
    )


def confidence_label(
    confidence
):
    """
    Verbale Confidence-Stufe.
    """

    if confidence >= 85:
        return "hoch"

    if confidence >= 60:
        return "mittel"

    return "niedrig"


# ==========================================================
# Untertypen
# ==========================================================

def detect_subtype(
    device,
    category,
    fingerprints=(),
):
    """
    Bestimmt einen genaueren Untertyp.
    """

    vendor = normalize(
        device.get("vendor")
    )

    hostname = normalize(
        device.get("hostname")
    )


    os_info = (
        device.get("os")
        or {}
    )

    os_name = normalize(
        os_info.get("name")
    )

    if not os_name:
        family = (device.get('os_summary') or {}).get('family')
        if family and not family.get('stale'):
            os_name = normalize(family['value'])

    matching_subtypes = [item for item in fingerprints
                         if item['category'] == category and item.get('subtype')]
    if matching_subtypes:
        return max(matching_subtypes, key=lambda item: item['points'])['subtype']


    # ======================================================
    # Router / Firewall
    # ======================================================

    if category == "firewall_router":

        if "sophos" in vendor:
            return "Sophos Firewall / Gateway"

        return "Router / Gateway"


    # ======================================================
    # Netzwerkgerät
    # ======================================================

    if category == "network_device":

        if (
            "routerboard" in vendor
            or "mikrotik" in vendor
        ):

            return "MikroTik / RouterBOARD"


        if "ubiquiti" in vendor:
            return "Ubiquiti-Netzwerkgerät"


        return "Netzwerkinfrastruktur"


    # ======================================================
    # Virtualisierung
    # ======================================================

    if category == "virtualization":

        if (contains_service_text(device, "proxmox virtual environment")
                or contains_service_text(device, "proxmox datacenter")):

            return "Proxmox-Host"

        if has_port(device, 8006):
            return "Möglicher Proxmox-Host"


        if "proxmox" in vendor:

            return (
                "Virtualisiertes System "
                "(Proxmox-Netzwerkadapter)"
            )


        return "Virtualisiertes System"


    # ======================================================
    # Server
    # ======================================================

    if category == "server":

        if "windows server" in os_name:

            if (
                has_port(
                    device,
                    88
                )
                and has_port(
                    device,
                    389
                )
                and has_port(
                    device,
                    445
                )
            ):

                return "Windows Domain Controller"


            return "Windows Server"


        active_directory_ports = {
            53,
            88,
            135,
            389,
            445,
            464,
            636,
            3268,
            3269,
        }


        ad_count = count_ports(
            device,
            active_directory_ports
        )


        if (
            (
                "-dc" in hostname
                or hostname.startswith("dc")
            )
            and ad_count >= 3
        ):

            return "Domain Controller"


        if (
            has_port(
                device,
                88
            )
            and has_port(
                device,
                389
            )
            and has_port(
                device,
                445
            )
        ):

            return "Active-Directory-Server"


        if (
            "-fs" in hostname
            or hostname.startswith("fs")
        ):

            return "Fileserver"


        if (
            has_port(
                device,
                80
            )
            or has_port(
                device,
                443
            )
            or has_port(
                device,
                8443
            )
        ):

            return "Server mit Webdienst"


        return "Server"


    # ======================================================
    # Workstation
    # ======================================================

    if category == "workstation":

        if (
            (
                "windows 10" in os_name
                or "windows 11" in os_name
            )
            and "proxmox" in vendor
        ):

            return "Windows-PC / virtuelle Maschine"


        if "windows 11" in os_name:

            return "Windows-11-PC"


        if "windows 10" in os_name:

            return "Windows-10-PC"


        if "windows" in os_name:

            return "Windows-PC / Workstation"


        if is_macos_os(
            os_name
        ):

            return "Mac"


        return "PC / Workstation"


    # ======================================================
    # Apple
    # ======================================================

    if category == "apple_device":

        if is_ambiguous_apple_os(
            os_name
        ):

            return (
                "macOS / iOS nicht eindeutig"
            )


        if "ipados" in os_name:

            return "iPad / iPadOS-Gerät"


        if "ios" in os_name:

            return "iPhone / iPad / iOS-Gerät"


        if get_open_tcp_port(device, 62078):

            return "Mögliches iPhone / iPad"


        return "Apple-Gerät"


    # ======================================================
    # VoIP
    # ======================================================

    if category == "voip_phone":

        if "yealink" in vendor:
            return "Yealink VoIP-Telefon"

        return "VoIP-Endgerät"


    # ======================================================
    # Drucker
    # ======================================================

    if category == "printer":

        if "epson" in vendor:
            return "Epson Netzwerkdrucker"

        return "Netzwerkdrucker"


    # ======================================================
    # Kamera
    # ======================================================

    if category == "camera":

        if "reolink" in vendor:
            return "Reolink IP-Kamera"

        return "IP-Kamera"


    # ======================================================
    # Power
    # ======================================================

    if category == "power_device":

        if (
            "apc" in vendor
            or "schneider" in vendor
        ):

            return "APC USV / Power Device"

        return "USV / Power Device"


    # ======================================================
    # SBC
    # ======================================================

    if category == "single_board_computer":

        if "raspberry pi" in vendor:
            return "Raspberry Pi"

        return "Single-Board-Computer"

    if category == "smart_tv":
        identification = device.get('device_identification') or {}
        return ("Samsung Smart-TV" if identification.get('status') == 'confirmed'
                else "Möglicher Samsung Smart-TV")


    return "-"


# ==========================================================
# Klassifikation
# ==========================================================

def classify_device(device):
    """
    Klassifiziert ein Gerät anhand mehrerer Hinweise.
    """

    scores = defaultdict(int)
    evidence = defaultdict(list)


    vendor = normalize(
        device.get("vendor")
    )

    hostname = normalize(
        device.get("hostname")
    )


    os_info = (
        device.get("os")
        or {}
    )

    os_name = normalize(
        os_info.get("name")
    )
    if not os_name:
        family = (device.get('os_summary') or {}).get('family')
        if family and not family.get('stale'):
            os_name = normalize(family['value'])

    identification = device.get("device_identification") or {}
    samsung_confirmed = (identification.get("status") == "confirmed"
            and identification.get("source") == "samsung_smart_tv_api"
            and normalize(identification.get("manufacturer")) == "samsung"
            and normalize(identification.get("type")) == "samsung smart-tv")
    if samsung_confirmed:
        model = identification.get("model")
        detail = f" (Modell {model})" if model else ""
        add_score(scores, evidence, "smart_tv", 200,
                  f"Samsung-Geräte-API bestätigt Smart-TV{detail}")

    fingerprint_matches = match_fingerprints(device)
    for finding in fingerprint_matches:
        add_score(scores, evidence, finding['category'], finding['points'], finding['reason'])


    # ======================================================
    # Router / Firewall
    # ======================================================

    if "sophos" in vendor:

        add_score(
            scores,
            evidence,
            "firewall_router",
            55,
            "Hersteller ist Sophos"
        )


    if hostname == "_gateway":

        add_score(
            scores,
            evidence,
            "firewall_router",
            60,
            "Hostname kennzeichnet das Gateway"
        )


    # ======================================================
    # VoIP
    # ======================================================

    if "yealink" in vendor:

        add_score(
            scores,
            evidence,
            "voip_phone",
            45,
            "Hersteller ist Yealink"
        )


    # ======================================================
    # Kamera
    # ======================================================

    if "reolink" in vendor:

        add_score(
            scores,
            evidence,
            "camera",
            45,
            "Hersteller ist Reolink"
        )


    # ======================================================
    # USV
    # ======================================================

    if (
        "apc by schneider" in vendor
        or "schneider electric" in vendor
    ):

        add_score(
            scores,
            evidence,
            "power_device",
            55,
            "Hersteller ist APC / Schneider Electric"
        )


    # ======================================================
    # Drucker
    # ======================================================

    if "seiko epson" in vendor:

        add_score(
            scores,
            evidence,
            "printer",
            45,
            "Hersteller ist Epson"
        )


    if has_port(
        device,
        9100
    ):

        add_score(
            scores,
            evidence,
            "printer",
            60,
            "TCP-Port 9100 ist ein typischer Druckerport"
        )


    if has_port(
        device,
        631
    ):

        add_score(
            scores,
            evidence,
            "printer",
            35,
            "IPP-Port 631 ist offen"
        )


    if has_port(
        device,
        515
    ):

        add_score(
            scores,
            evidence,
            "printer",
            30,
            "LPD-Port 515 ist offen"
        )


    # ======================================================
    # Raspberry Pi
    # ======================================================

    if "raspberry pi" in vendor:

        add_score(
            scores,
            evidence,
            "single_board_computer",
            45,
            "Hersteller ist Raspberry Pi"
        )


    # ======================================================
    # Netzwerkgeräte
    # ======================================================

    if "ubiquiti" in vendor:

        add_score(
            scores,
            evidence,
            "network_device",
            45,
            "Hersteller ist Ubiquiti"
        )


    if (
        "routerboard" in vendor
        or "mikrotik" in vendor
    ):

        add_score(
            scores,
            evidence,
            "network_device",
            50,
            "Hersteller ist MikroTik / RouterBOARD"
        )


    # ======================================================
    # Proxmox / Virtualisierung
    # ======================================================

    if "proxmox" in vendor:

        add_score(
            scores,
            evidence,
            "virtualization",
            30,
            (
                "MAC-Hersteller weist auf "
                "Proxmox-Virtualisierung hin"
            )
        )


    if contains_service_text(
        device,
        "proxmox virtual environment"
    ):

        add_score(
            scores,
            evidence,
            "virtualization",
            100,
            "Dienst identifiziert Proxmox VE"
        )


    if contains_service_text(
        device,
        "proxmox datacenter"
    ):

        add_score(
            scores,
            evidence,
            "virtualization",
            100,
            "Dienst identifiziert Proxmox Datacenter"
        )


    if contains_service_text(
        device,
        "proxmox"
    ):

        add_score(
            scores,
            evidence,
            "virtualization",
            70,
            "Ein erkannter Dienst enthält Proxmox"
        )

    # osclass is already present in saved Nmap XML observations. Nmap may
    # report several competing classes; the regular score margin handles that.
    os_class_types = {normalize(item.get('type')) for item in device.get('os_classes') or ()
                      if isinstance(item, dict)}
    if 'wap' in os_class_types:
        add_score(scores, evidence, 'network_device', 55,
                  'Nmap-Betriebssystemfingerprint meldet Gerätetyp WAP')
    if 'printer' in os_class_types:
        add_score(scores, evidence, 'printer', 55,
                  'Nmap-Betriebssystemfingerprint meldet Drucker')
    if 'router' in os_class_types:
        add_score(scores, evidence, 'firewall_router', 55,
                  'Nmap-Betriebssystemfingerprint meldet Router')
    if any(normalize(port.get('devicetype')) == 'wap' for port in get_ports(device)
           if port.get('state') == 'open'):
        add_score(scores, evidence, 'network_device', 60,
                  'Nmap-Dienstfingerprint meldet Gerätetyp WAP')


    if has_port(
        device,
        8006
    ):

        add_score(
            scores,
            evidence,
            "virtualization",
            75,
            "TCP-Port 8006 ist typisch für Proxmox VE"
        )

    if has_port(device, 8007):
        add_score(scores, evidence, 'virtualization', 25,
                  'TCP-Port 8007 kann auf Proxmox Backup Server hinweisen')

    if 'samsung' in vendor and get_open_tcp_port(device, 8001):
        add_score(scores, evidence, 'smart_tv', 50,
                  'Samsung-MAC und offener TCP-Port 8001 weisen auf Smart-TV hin')
        if get_open_tcp_port(device, 8002):
            add_score(scores, evidence, 'smart_tv', 20,
                      'Auch Samsung-TV-Port 8002 ist offen')

    if 'yealink' in vendor and (has_port(device, 5060) or has_port(device, 5061)):
        add_score(scores, evidence, 'voip_phone', 20,
                  'Yealink-MAC und SIP-Port sind gemeinsam vorhanden')

    if 'reolink' in vendor and has_port(device, 9000):
        add_score(scores, evidence, 'camera', 20,
                  'Reolink-MAC und TCP-Port 9000 sind gemeinsam vorhanden')


    # ======================================================
    # WINDOWS SERVER
    # ======================================================

    if "windows server" in os_name:

        add_score(
            scores,
            evidence,
            "server",
            80,
            "Nmap erkennt Microsoft Windows Server"
        )


    # ======================================================
    # WINDOWS 10 / 11
    # ======================================================

    elif (
        "windows 11" in os_name
        or "windows 10" in os_name
        or "windows 10 or 11" in os_name
    ):

        add_score(
            scores,
            evidence,
            "workstation",
            75,
            "Nmap erkennt Windows 10/11"
        )


    # ======================================================
    # Sonstiges Windows
    # ======================================================

    elif "windows" in os_name:

        add_score(
            scores,
            evidence,
            "workstation",
            40,
            "Nmap erkennt Microsoft Windows"
        )


    # ======================================================
    # Apple:
    # macOS ODER iOS
    #
    # Genau der Fall von 192.168.10.229.
    # Wir dürfen daraus NICHT einfach einen Mac machen.
    # ======================================================

    if is_ambiguous_apple_os(
        os_name
    ):

        add_score(
            scores,
            evidence,
            "apple_device",
            70,
            (
                "Nmap erkennt einen Apple-Fingerprint, "
                "kann aber macOS und iOS nicht unterscheiden"
            )
        )


    # ======================================================
    # iOS / iPadOS eindeutig genug
    # ======================================================

    elif is_ios_os(
        os_name
    ):

        add_score(
            scores,
            evidence,
            "apple_device",
            75,
            "Nmap erkennt iOS / iPadOS"
        )


    # ======================================================
    # macOS ohne iOS-Alternative
    # ======================================================

    elif is_macos_os(
        os_name
    ):

        add_score(
            scores,
            evidence,
            "workstation",
            65,
            "Nmap erkennt macOS"
        )


    # ======================================================
    # Linux
    # ======================================================

    if "linux" in os_name:

        add_score(
            scores,
            evidence,
            "server",
            15,
            "Nmap erkennt Linux"
        )


    # ======================================================
    # Serverdienste
    # ======================================================

    if has_port(
        device,
        22
    ):

        add_score(
            scores,
            evidence,
            "server",
            15,
            "SSH-Port 22 ist offen"
        )


    web_ports = {
        80,
        443,
        8080,
        8443,
    }


    web_count = count_ports(
        device,
        web_ports
    )


    if (
        has_port(
            device,
            22
        )
        and web_count >= 1
    ):

        add_score(
            scores,
            evidence,
            "server",
            20,
            "SSH und Webdienst sind gemeinsam vorhanden"
        )


    server_service_ports = {
        21,
        22,
        25,
        53,
        88,
        110,
        143,
        389,
        636,
        993,
        995,
        2049,
        3306,
        5432,
        6379,
    }


    server_port_count = count_ports(
        device,
        server_service_ports
    )


    if server_port_count >= 2:

        add_score(
            scores,
            evidence,
            "server",
            25,
            "Mehrere typische Serverdienste sind offen"
        )


    if (
        "-dc" in hostname
        or hostname.startswith("dc")
    ):

        add_score(
            scores,
            evidence,
            "server",
            25,
            "Hostname deutet auf Domain Controller hin"
        )


    if (
        "-fs" in hostname
        or hostname.startswith("fs")
    ):

        add_score(
            scores,
            evidence,
            "server",
            25,
            "Hostname deutet auf Fileserver hin"
        )


    ad_ports = {
        53,
        88,
        389,
        445,
        464,
        636,
        3268,
        3269,
    }


    if count_ports(
        device,
        ad_ports
    ) >= 3:

        add_score(
            scores,
            evidence,
            "server",
            50,
            (
                "Mehrere typische "
                "Active-Directory-Dienste sind offen"
            )
        )


    # ======================================================
    # Workstation-Dienste
    # ======================================================

    if has_port(
        device,
        3389
    ):

        add_score(
            scores,
            evidence,
            "workstation",
            40,
            "RDP-Port 3389 ist offen"
        )


    if has_port(
        device,
        445
    ):

        add_score(
            scores,
            evidence,
            "workstation",
            15,
            "SMB-Port 445 ist offen"
        )


    if (
        has_port(
            device,
            3389
        )
        and has_port(
            device,
            445
        )
    ):

        add_score(
            scores,
            evidence,
            "workstation",
            25,
            "RDP und SMB sind gemeinsam vorhanden"
        )


    # ======================================================
    # Apple-Mobilgeräte: iphone-sync auf TCP 62078
    # ======================================================

    sync_port = get_open_tcp_port(device, 62078)

    if sync_port:
        apple_signals = []

        if is_apple_sync_service(sync_port):
            apple_signals.append((
                25,
                "TCP-Port 62078 meldet den Apple-Dienst iphone-sync"
            ))

        if "apple" in vendor:
            apple_signals.append((
                10,
                "MAC-Hersteller weist zusätzlich auf Apple hin"
            ))

        apple_signals.append((
            60,
            "TCP-Port 62078 ist offen; Apple-Mobilgerät möglich"
        ))

        apple_base_score = scores.get("apple_device", 0)
        baseline_scores = sorted(
            scores.items(),
            key=lambda item: item[1],
            reverse=True
        )

        # A newly seen port must not displace a category that existing
        # evidence already classifies. Apple evidence can still strengthen
        # an Apple result that was already leading.
        allowed_points = sum(points for points, _ in apple_signals)
        if (
            baseline_scores
            and baseline_scores[0][0] != "apple_device"
            and baseline_scores[0][1] >= MIN_CLASSIFICATION_SCORE
        ):
            allowed_points = max(
                0,
                baseline_scores[0][1] - apple_base_score - 1
            )

        for points, reason in apple_signals:
            applied_points = min(points, allowed_points)
            if applied_points:
                add_score(
                    scores,
                    evidence,
                    "apple_device",
                    applied_points,
                    reason
                )
                allowed_points -= applied_points


    local_mac = is_locally_administered_mac(
        device.get("mac")
    )


    # ======================================================
    # Ergebnis
    # ======================================================

    if not scores:

        return {
            "category": "unknown",

            "category_label":
                CATEGORY_LABELS[
                    "unknown"
                ],

            "subtype": "-",

            "confidence": 0,

            "confidence_label":
                "keine",

            "score": 0,

            "evidence": [],

            "local_mac":
                local_mac,
        }


    sorted_scores = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True
    )


    best_category = (
        sorted_scores[0][0]
    )

    best_score = (
        sorted_scores[0][1]
    )


    second_score = (
        sorted_scores[1][1]
        if len(sorted_scores) > 1
        else 0
    )


    if (
        best_score
        < MIN_CLASSIFICATION_SCORE
    ):

        return {
            "category": "unknown",

            "category_label":
                CATEGORY_LABELS[
                    "unknown"
                ],

            "subtype": "-",

            "confidence": 0,

            "confidence_label":
                "keine",

            "score":
                best_score,

            "evidence": [],

            "local_mac":
                local_mac,
        }


    best_evidence = evidence[
        best_category
    ]


    confidence = calculate_confidence(
        best_score,
        second_score,
        len(
            best_evidence
        )
    )


    subtype = detect_subtype(
        device,
        best_category,
        fingerprint_matches,
    )


    return {
        "category":
            best_category,

        "category_label":
            CATEGORY_LABELS[
                best_category
            ],

        "subtype":
            subtype,

        "confidence":
            confidence,

        "confidence_label":
            confidence_label(
                confidence
            ),

        "score":
            best_score,

        "evidence":
            best_evidence,

        **({"source": "samsung_smart_tv_api"} if best_category == "smart_tv" and samsung_confirmed else {}),

        "local_mac":
            local_mac,
    }


# ==========================================================
# Sortierung
# ==========================================================

def sort_inventory(
    inventory
):
    """
    Sortiert Geräte numerisch nach IP.
    """

    def sort_key(device):

        ip_address = device.get(
            "ip"
        )


        if not ip_address:

            return (
                1,
                0
            )


        try:

            return (
                0,
                int(
                    ipaddress.ip_address(
                        ip_address
                    )
                )
            )


        except ValueError:

            return (
                1,
                0
            )


    return sorted(
        inventory,
        key=sort_key
    )


# ==========================================================
# Ausgabe
# ==========================================================

def print_classification(
    device,
    result
):
    """
    Zeigt das Klassifikationsergebnis.
    """

    print("-" * 80)


    print(
        f"Geräte-ID....: "
        f"{device.get('id')}"
    )


    print(
        f"IP...........: "
        f"{device.get('ip') or '-'}"
    )


    print(
        f"MAC..........: "
        f"{device.get('mac') or '-'}"
    )


    print(
        f"Hersteller...: "
        f"{device.get('vendor') or '-'}"
    )


    print(
        f"Hostname.....: "
        f"{device.get('hostname') or '-'}"
    )


    os_info = (
        device.get("os")
        or {}
    )


    print(
        f"OS...........: "
        f"{os_info.get('name') or '-'}"
    )


    print(
        f"Kategorie....: "
        f"{result['category_label']}"
    )


    print(
        f"Untertyp.....: "
        f"{result['subtype']}"
    )


    if result[
        "confidence"
    ] > 0:

        print(
            f"Confidence...: "
            f"{result['confidence']} % "
            f"({result['confidence_label']})"
        )

    else:

        print(
            "Confidence...: -"
        )


    if result[
        "local_mac"
    ]:

        print(
            "MAC-Typ......: lokal vergeben / "
            "randomisiert / virtuell möglich"
        )


    if result[
        "evidence"
    ]:

        print(
            "Hinweise......:"
        )


        for item in result[
            "evidence"
        ]:

            print(
                f"  +{item['points']:3d}  "
                f"{item['reason']}"
            )

    else:

        print(
            "Hinweise......: "
            "keine ausreichenden Hinweise"
        )


    print("-" * 80)


# ==========================================================
# Zusammenfassung
# ==========================================================

def print_summary(
    classifications
):
    """
    Zeigt eine Statistik der Kategorien.
    """

    counts = defaultdict(
        int
    )


    for result in classifications:

        counts[
            result[
                "category_label"
            ]
        ] += 1


    print()
    print("=" * 80)
    print("Zusammenfassung")
    print("=" * 80)


    for category, count in sorted(
        counts.items(),
        key=lambda item: (
            -item[1],
            item[0]
        )
    ):

        print(
            f"{category:25s} "
            f"{count:3d}"
        )


    print("=" * 80)


# ==========================================================
# Hauptprogramm
# ==========================================================

@exclusive_cycle
def main():

    connection = get_connection()


    try:

        init_database(
            connection
        )


        inventory = get_inventory(
            connection
        )


        inventory = sort_inventory(
            inventory
        )


        print()
        print("=" * 80)
        print(
            "NetChecker Geräteklassifikation"
        )
        print("=" * 80)


        print(
            f"Bekannte Geräte: "
            f"{len(inventory)}"
        )

        print()


        classifications = []


        for device in inventory:

            result = classify_device(
                device
            )


            classifications.append(
                result
            )


            print_classification(
                device,
                result
            )


        print_summary(
            classifications
        )


    finally:

        connection.close()


if __name__ == "__main__":
    main()

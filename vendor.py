import csv
from functools import lru_cache
from pathlib import Path


IEEE_DATA_DIR = Path("/var/lib/ieee-data")

IEEE_FILES = [
    "oui.csv",
    "mam.csv",
    "oui36.csv",
    "iab.csv"
]


def normalize_mac(mac_address):
    """
    Entfernt Doppelpunkte und Bindestriche aus einer MAC-Adresse
    und wandelt sie in Großbuchstaben um.
    """

    if not mac_address:
        return None

    normalized = (
        mac_address
        .replace(":", "")
        .replace("-", "")
        .upper()
    )

    if len(normalized) != 12:
        return None

    return normalized


@lru_cache(maxsize=1)
def load_vendor_database():
    """
    Lädt die IEEE-Herstellerdaten aus den CSV-Dateien.

    Das Ergebnis wird gecacht, damit die Dateien während eines
    Programmlaufs nur einmal eingelesen werden müssen.
    """

    database = {}

    for filename in IEEE_FILES:

        file_path = IEEE_DATA_DIR / filename

        if not file_path.exists():
            continue

        with file_path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                assignment = row.get("Assignment")
                organization = row.get("Organization Name")

                if not assignment or not organization:
                    continue

                assignment = assignment.strip().upper()
                organization = organization.strip()

                if organization == "Private":
                    continue

                database[assignment] = organization

    return database


def get_vendor_from_mac(mac_address):
    """
    Ermittelt den Hersteller einer MAC-Adresse anhand
    der lokalen IEEE-Datenbank.
    """

    normalized_mac = normalize_mac(mac_address)

    if normalized_mac is None:
        return None

    database = load_vendor_database()

    # Längste Präfixe zuerst prüfen.
    #
    # 9 Hex-Zeichen = 36 Bit → MA-S / IAB
    # 7 Hex-Zeichen = 28 Bit → MA-M
    # 6 Hex-Zeichen = 24 Bit → MA-L
    for prefix_length in (9, 7, 6):

        prefix = normalized_mac[:prefix_length]

        vendor = database.get(prefix)

        if vendor:
            return vendor

    return None
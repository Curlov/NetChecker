"""Offline MAC facts. The local bit does not prove randomization."""
import re


def normalize_mac(value):
    if not isinstance(value, str):
        return None
    compact = re.sub(r"[:.\-]", "", value.strip())
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return None
    return ":".join(compact[i:i + 2].upper() for i in range(0, 12, 2))


def analyze_mac(value):
    mac = normalize_mac(value)
    if mac is None:
        return {"valid": False, "mac": None, "hypotheses": []}
    first = int(mac[:2], 16)
    local = bool(first & 2)
    multicast = bool(first & 1)
    hypotheses = []
    if local and not multicast:
        hypotheses.append("Randomisierung oder virtuelle Schnittstelle möglich; nicht nachgewiesen")
    return {
        "valid": True, "mac": mac, "multicast": multicast,
        "unicast": not multicast, "locally_administered": local,
        "universally_administered": not local,
        "broadcast": mac == "FF:FF:FF:FF:FF:FF", "hypotheses": hypotheses,
    }

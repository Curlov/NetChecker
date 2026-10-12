"""Source-aware OS claims from saved fingerprints and service metadata."""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

DISTROS = {
    "Ubuntu": r"\bubuntu\b", "Debian": r"\bdebian\b",
    "SUSE": r"\b(?:opensuse|suse|sles)\b", "Fedora": r"\bfedora\b",
    "Rocky Linux": r"\brocky(?:[ _-]linux)?\b",
    "AlmaLinux": r"\balma(?:[ _-]?linux)\b",
    "Red Hat Enterprise Linux": r"\b(?:red[ _-]hat|rhel)\b",
    "CentOS": r"\bcentos\b",
}


def infer_os_claims(os_result=None, ports=(), os_classes=(), host_scripts=()):
    claims = []

    def inspect(text, source, evidence, confidence):
        if not text:
            return
        text = str(text)
        found_distros = [name for name, pattern in DISTROS.items()
                        if re.search(pattern, text, re.I)]
        family = "Linux" if found_distros or re.search(r"\blinux\b|linux_kernel", text, re.I) else None
        if re.search(r"\bwindows\b", text, re.I):
            family = "Windows"
        if re.search(r"\b(?:darwin|macos|mac os)\b", text, re.I):
            family = "macOS"
        values = [("family", family)] if family else []
        values.extend(("distribution", name) for name in found_distros)
        # Kernel numbers only come from explicit Linux fingerprints/CPEs.
        # Service versions such as OpenSSH 9.0 are never kernel versions.
        if source == "nmap_os":
            match = re.search(r"\bLinux\s+([0-9][0-9.xX+\-]*(?:\s*-\s*[0-9][0-9.xX+\-]*)?)", text)
            if match:
                values.append(("kernel", match.group(1).strip()))
        for match in re.finditer(r'cpe:(?:/o:|2\.3:o:)linux:linux_kernel:([^:\s]+)', text, re.I):
            if match.group(1) not in {'*', '-'}:
                values.append(('kernel', match.group(1)))
        for distro in found_distros:
            pattern = DISTROS[distro]
            version = re.search('(?:' + pattern + r')[ _:-]+(?:Linux[ _:-]+)?([0-9]+(?:\.[0-9]+)*)', text, re.I)
            if version:
                values.append(('distribution_version', distro + ' ' + version.group(1)))
        for kind, value in values:
            claims.append({"kind": kind, "value": value, "source": source,
                           "status": "suspected", "confidence": confidence,
                           "evidence": evidence})

    if os_result:
        inspect(os_result.get("name"), os_result.get("source") or "nmap_os",
                dict(os_result), min(99, int(os_result.get("accuracy") or 0)))
    for os_class in os_classes:
        inspect(" ".join(str(v) for v in os_class.values()), "nmap_osclass",
                os_class, 70)
    for port in ports:
        if port.get("state") != "open":
            continue
        for key in ("product", "version", "extrainfo", "ostype", "cpe"):
            value = port.get(key)
            text = " ".join(value) if isinstance(value, list) else value
            inspect(text, "nmap_service", {"port": port["port"],
                    "protocol": port.get("protocol"), "field": key, "value": value}, 65)
        for script in port.get('scripts') or ():
            inspect(script.get('output'), 'nmap_script',
                    {'port': port['port'], 'protocol': port.get('protocol'), 'script': script}, 60)
    for script in host_scripts:
        try:
            element = ET.fromstring(script) if isinstance(script, str) else None
            text = ' '.join(s.get('output') or '' for s in element.iter('script')) if element is not None else ''
            inspect(text, 'nmap_hostscript', {'xml': script}, 70)
        except (ET.ParseError, TypeError):
            continue
    return claims


def summarize_claims(claims, now=None, max_age_days=90):
    result = {}
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)).strftime('%Y-%m-%d %H:%M:%S')
    for kind in ("family", "kernel", "distribution", "distribution_version"):
        candidates = [c for c in claims if c["kind"] == kind and c.get("value")]
        if not candidates:
            result[kind] = None
            continue
        candidates.sort(key=lambda c: (not c.get('observed_at') or c['observed_at'] >= cutoff,
                                       c["status"] == "confirmed", c["confidence"],
                                       c.get("observed_at", ""), c.get("id", 0)), reverse=True)
        best = dict(candidates[0])
        best['stale'] = bool(best.get('observed_at') and best['observed_at'] < cutoff)
        best["alternatives"] = sorted({c["value"] for c in candidates if c["value"] != best["value"]})
        best["conflicting"] = bool(best["alternatives"])
        result[kind] = best
    return result


def select_os(history):
    """A new high-quality observation may replace an older OS installation."""
    usable = [item for item in history if item.get('name')]
    if not usable:
        return None
    reliable = [item for item in usable if int(item.get('accuracy') or 0) >= 70]
    return max(reliable or usable, key=lambda item: (item.get('observed_at', ''), item.get('id', 0)))


def service_evidence_sufficient(result):
    claims = infer_os_claims(result.get('os'), result.get('ports') or (),
                             result.get('os_classes') or (), result.get('host_scripts') or ())
    return any(item['kind'] in {'family', 'distribution'} and item['confidence'] >= 65 for item in claims)

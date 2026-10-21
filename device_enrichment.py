"""Read-only, manufacturer-specific device identification probes.

Handlers are deliberately small and run from the regular enrichment cycle.
Adding a future manufacturer should only require another handler in
``DEVICE_ENRICHERS``.
"""

import ipaddress
import json
from urllib.request import Request, HTTPRedirectHandler, ProxyHandler, build_opener


API_TIMEOUT_SECONDS = 3
MAX_RESPONSE_BYTES = 256 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def urlopen(request, timeout):
    """Connect directly to the validated IP; never follow redirects or proxies."""
    return build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=timeout)


class SamsungSmartTVEnricher:
    source = "samsung_smart_tv_api"

    def matches(self, device):
        vendor = str(device.get("vendor") or "").strip().lower()
        if "samsung" not in vendor:
            return False

        for port in device.get("ports") or ():
            try:
                number = int(port.get("port"))
            except (TypeError, ValueError, AttributeError):
                continue
            if (number == 8001
                    and str(port.get("protocol") or "").lower() == "tcp"
                    and str(port.get("state") or "").lower() == "open"):
                return True
        return False

    def probe(self, device):
        """Fetch and validate the Samsung device info endpoint with GET only."""
        try:
            ip = str(ipaddress.ip_address(device.get("ip")))
        except (ValueError, TypeError):
            return {"status": "error", "reason": "invalid_ip"}

        request = Request(
            f"http://{ip}:8001/api/v2/",
            headers={"Accept": "application/json", "User-Agent": "NetChecker"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except Exception:
            return {"status": "error", "reason": "connection_error"}
        if len(raw) > MAX_RESPONSE_BYTES:
            return {"status": "error", "reason": "response_too_large"}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return {"status": "error", "reason": "invalid_json"}

        if not isinstance(payload, dict):
            return {"status": "error", "reason": "invalid_response"}
        payload = payload.get("device", payload)
        if not isinstance(payload, dict):
            return {"status": "error", "reason": "invalid_response"}

        device_type = payload.get("type")
        normalized_type = " ".join(str(device_type or "").lower().split())
        if "samsung" not in normalized_type or "smarttv" not in normalized_type.replace(" ", ""):
            return {"status": "error", "reason": "not_samsung_smart_tv"}

        return {
            "status": "confirmed",
            "manufacturer": "Samsung",
            "type": "Samsung Smart-TV",
            "category": "smart_tv",
            "subtype": "Samsung Smart-TV",
            "confidence": 99,
            "evidence": ["Samsung-Geräte-API /api/v2/ meldet Samsung SmartTV"],
            "name": _clean_text(payload.get("name")),
            "model": _clean_text(payload.get("modelName")),
            "operating_system": _clean_text(payload.get("OS")),
            "network_type": _clean_text(payload.get("networkType")),
            "source": self.source,
        }


def _clean_text(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:200] or None


DEVICE_ENRICHERS = (SamsungSmartTVEnricher(),)


def matching_enrichers(device):
    """Return manufacturer handlers whose existing clues match this device."""
    return [handler for handler in DEVICE_ENRICHERS if handler.matches(device)]


def get_enricher(source):
    return next((handler for handler in DEVICE_ENRICHERS if handler.source == source), None)

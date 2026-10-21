"""Small, versioned rules over saved Nmap service evidence.

The rules never infer a product from a port assignment. They score through
the existing classifier and do not perform network activity.
"""

import json
from functools import lru_cache
from pathlib import Path


RULES_PATH = Path(__file__).resolve().parent / 'fingerprints' / 'rules-v1.json'
LOCAL_RULES_PATH = RULES_PATH.parent / 'local-rules.json'
FIELDS = {'product', 'version', 'extrainfo', 'ostype', 'devicetype', 'cpe', 'script'}
ALLOWED_CATEGORIES = {'firewall_router', 'network_device', 'virtualization', 'server',
                      'workstation', 'apple_device', 'voip_phone', 'printer', 'camera',
                      'power_device', 'single_board_computer', 'smart_tv'}


@lru_cache(maxsize=1)
def load_rules():
    """Read reviewed built-in and optional local rules once per process."""
    seen = set()
    result = []
    for path in (RULES_PATH, LOCAL_RULES_PATH):
        for rule in load_rule_file(path):
            if rule['id'] not in seen:
                result.append(rule)
                seen.add(rule['id'])
    return tuple(result)


def load_rule_file(path):
    """Accept a small local JSON subset, never an entire external database."""
    try:
        path = Path(path)
        if path.stat().st_size > 256 * 1024:
            return ()
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return ()
    if not isinstance(document, dict) or document.get('schema') != 1:
        return ()
    if not isinstance(document.get('rules'), list):
        return ()
    revision = str(document.get('revision') or 'unknown')
    source = str(document.get('source') or 'local')
    result = []
    for rule in document['rules'][:128]:
        if not isinstance(rule, dict) or not isinstance(rule.get('id'), str):
            continue
        if rule.get('category') not in ALLOWED_CATEGORIES or not isinstance(rule.get('any'), list):
            continue
        if not isinstance(rule.get('points'), int) or not 1 <= rule['points'] <= 150:
            continue
        conditions = rule['any']
        if not conditions or len(conditions) > 8 or any(
                                 not isinstance(c, dict) or c.get('field') not in FIELDS
                                 or not isinstance(c.get('contains'), str)
                                 or not 1 <= len(c['contains']) <= 100
                                 for c in conditions):
            continue
        result.append(dict(rule, revision=revision, rule_source=source))
    return tuple(result)


def _values(port, field):
    if field == 'cpe':
        return [str(value) for value in port.get('cpe') or () if isinstance(value, str)]
    if field == 'script':
        return [str(item.get('output')) for item in port.get('scripts') or ()
                if isinstance(item, dict) and item.get('output')]
    value = port.get(field)
    return [value] if isinstance(value, str) and value else []


def match_device(device, rules=None):
    """Return at most one traceable finding per rule for currently open ports."""
    findings = []
    for rule in load_rules() if rules is None else rules:
        found = None
        for port in device.get('ports') or ():
            if not isinstance(port, dict) or str(port.get('state')).lower() != 'open':
                continue
            for condition in rule['any']:
                for value in _values(port, condition['field']):
                    if condition['contains'].casefold() in value[:2048].casefold():
                        found = (port, condition['field'], value)
                        break
                if found:
                    break
            if found:
                break
        if not found:
            continue
        port, field, value = found
        findings.append({
            'rule_id': rule['id'], 'revision': rule['revision'],
            'rule_source': rule.get('rule_source', 'local'),
            'category': rule['category'], 'subtype': rule.get('subtype'),
            'manufacturer': rule.get('manufacturer'),
            'model': rule.get('model'), 'points': rule['points'],
            'source': 'nmap_service_fingerprint',
            'observed_at': port.get('service_observed_at') or port.get('last_seen'),
            'matched_field': field, 'matched_value': value[:200],
            'service_version': port.get('version'),
            'reason': (f"Nmap-Fingerprint {rule['id']}@{rule['revision']} "
                       f"[{rule.get('rule_source', 'local')}]: "
                       f"{field}={value[:100]} ({port.get('port')}/{port.get('protocol')})"),
        })
    return findings

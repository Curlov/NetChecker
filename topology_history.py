"""Compare topology evidence without turning absence into a physical outage."""
import json


def link_key(row):
    return tuple(row.get(key) for key in ('source_device_id', 'source_ip', 'source_interface',
        'target_device_id', 'target_ip', 'target_mac', 'target_interface', 'relation', 'evidence_source'))


def compare_links(before, after):
    old = {link_key(row): row for row in before}
    new = {link_key(row): row for row in after}
    ordering = lambda key: json.dumps(key, ensure_ascii=False)
    return {
        'added': [new[key] for key in sorted(new.keys() - old.keys(), key=ordering)],
        'removed': [old[key] for key in sorted(old.keys() - new.keys(), key=ordering)],
        'changed': [{'before':old[key], 'after':new[key]} for key in sorted(old.keys() & new.keys(), key=ordering)
                    if (old[key].get('confidence'), old[key].get('evidence_json')) !=
                       (new[key].get('confidence'), new[key].get('evidence_json'))],
        'interpretation': 'Unterschiede der gespeicherten Evidenz; fehlende Beobachtung beweist keinen Verbindungsausfall',
    }

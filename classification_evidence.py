"""Classification overlays from fresh, locally saved evidence only."""
import json

HINT_MAX_AGE_DAYS = 90


def apply_topology_hint(connection, network_id, device_id, result):
    hint = connection.execute("""SELECT * FROM topology_device_hints
        WHERE network_id=? AND device_id=? AND confidence>=90
          AND last_seen >= datetime('now', ?)
        ORDER BY confidence DESC,last_seen DESC,id DESC LIMIT 1""",
        (network_id,device_id,f'-{HINT_MAX_AGE_DAYS} days')).fetchone()
    if not hint:
        return result
    accepted = result['category'] == 'unknown'
    accepted |= hint['category'] == result['category'] and hint['confidence'] >= result['confidence']
    accepted |= (hint['category'] == 'network_device' and hint['confidence'] >= 95
                 and result['category'] not in {'firewall_router','network_device'})
    if not accepted:
        return result
    return dict(result, category=hint['category'], subtype=hint['subtype'],
                confidence=hint['confidence'], score=0, source=hint['source'],
                evidence=[{'source':hint['source'], 'hint_id':hint['id'],
                           'reason':'Gespeicherte Topologie-Evidenz',
                           'data':json.loads(hint['evidence_json'] or '{}')}])

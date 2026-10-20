"""Read-only daily view of existing scan evidence; no schema migration."""
import json
import ipaddress
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from fastapi import APIRouter, Query, HTTPException
from web.database import get_connection
from web.access import require_network

router = APIRouter(prefix='/api/timeline', tags=['Timeline'])


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


@router.get('')
def daily(network_id: int = Query(..., ge=1), day: date | None = None,
          tz: str = 'Europe/Berlin'):
    try:
        zone = ZoneInfo(tz)
    except ZoneInfoNotFoundError:
        raise HTTPException(422, 'Unbekannte Zeitzone')
    now = datetime.now(timezone.utc)
    with get_connection() as db:
        require_network(db, network_id)
        observations = db.execute("""SELECT device_id,scan_run_id,observation_type,source,observed_at,data_json,id
            FROM observations WHERE network_id=? AND device_id IS NOT NULL
            AND observation_type IN ('host_discovery','tcp_port_scan','service_scan','known_tcp_port_scan')
            ORDER BY observed_at,id""", (network_id,)).fetchall()
        missing = db.execute("""SELECT device_id,detected_at FROM changes
            WHERE network_id=? AND upper(change_type)='DEVICE_MISSING' ORDER BY detected_at,id""",
            (network_id,)).fetchall()
        port_changes = db.execute("""SELECT device_id,scan_run_id,change_type,old_value_json,
            new_value_json,detected_at,id FROM changes WHERE network_id=?
            AND upper(change_type) IN ('PORT_OPENED','PORT_CLOSED','PORT_NOT_OPEN','PORT_ADDED','PORT_REMOVED')
            ORDER BY detected_at,id""", (network_id,)).fetchall()
        inventory_ports = {}
        for row in db.execute("""SELECT device_id,protocol,port,state,ever_open,service,product,version
            FROM port_inventory WHERE network_id=? AND (ever_open=1 OR state='open')
            ORDER BY device_id,protocol,port""", (network_id,)):
            inventory_ports.setdefault(row['device_id'], []).append(dict(row))
        identities = {r['id']: dict(r) for r in db.execute("""SELECT d.id,d.hostname,d.display_name,d.mac,
            dc.category,
            EXISTS (
                SELECT 1 FROM topology_layouts layout
                WHERE layout.network_id=? AND layout.is_default=1
                  AND (
                    EXISTS (
                        SELECT 1 FROM topology_layout_positions position
                        WHERE position.layout_id=layout.id AND position.device_id=d.id
                    )
                    OR EXISTS (
                        SELECT 1 FROM topology_manual_nodes manual
                        WHERE manual.layout_id=layout.id AND manual.linked_device_id=d.id
                    )
                  )
            ) AS topology_placed,
            (SELECT ip FROM addresses WHERE device_id=d.id AND network_id=?
             ORDER BY last_seen DESC,id DESC LIMIT 1) AS ip FROM devices d
            LEFT JOIN device_classifications dc ON dc.device_id=d.id AND dc.network_id=?
            WHERE EXISTS(SELECT 1 FROM addresses WHERE device_id=d.id AND network_id=?)""",
            (network_id, network_id, network_id, network_id))}
    days = sorted({timestamp(r['observed_at']).astimezone(zone).date().isoformat() for r in observations}
                  | {timestamp(r['detected_at']).astimezone(zone).date().isoformat() for r in missing}
                  | {timestamp(r['detected_at']).astimezone(zone).date().isoformat() for r in port_changes})
    selected = day or (date.fromisoformat(days[-1]) if days else now.astimezone(zone).date())
    start = datetime.combine(selected, time.min, zone)
    end = datetime.combine(selected + timedelta(days=1), time.min, zone)
    cutoff = min(end, now)
    events = {}
    for r in observations:
        events.setdefault(r['device_id'], []).append((timestamp(r['observed_at']), 1, r))
    for r in missing:
        events.setdefault(r['device_id'], []).append((timestamp(r['detected_at']), 2, None))
    for r in port_changes:
        events.setdefault(r['device_id'], []).append((timestamp(r['detected_at']), 3, r))

    def segment(a, b):
        a, b = max(a, start), min(b, cutoff)
        if a >= b:
            return None
        def minute(t):
            if t == end:
                return 1440
            local = t.astimezone(zone)
            return local.hour * 60 + local.minute + local.second / 60
        return {'start': minute(a), 'end': minute(b), 'from': a.isoformat(), 'to': b.isoformat()}

    result = []
    has_day_observations = any(
        start <= timestamp(row['observed_at']) < end for row in observations
    ) or any(
        start <= timestamp(row['detected_at']) < end for row in missing
    ) or any(
        start <= timestamp(row['detected_at']) < end for row in port_changes
    )

    # Keep every known network device visible, including devices without an
    # online interval or new observation on the selected day.
    device_ids = dict.fromkeys((*identities.keys(), *events.keys()))
    for device_id in device_ids:
        sequence = events.get(device_id, [])
        online = []
        ports = {}
        for inventory_port in inventory_ports.get(device_id, []):
            protocol = str(inventory_port['protocol'] or 'tcp').lower()
            port_number = str(inventory_port['port'])
            key = f'{protocol}/{port_number}'
            ports[key] = {
                'key': key, 'protocol': protocol, 'port': port_number,
                'opened': None, 'intervals': [], 'observations': [],
                'last_state': None, 'inventory_state': inventory_port['state'],
                'ever_open': bool(inventory_port['ever_open'] or inventory_port['state'] == 'open'),
                'service': inventory_port['service'], 'product': inventory_port['product'],
                'version': inventory_port['version'],
            }
        opened = None
        device_active = None

        def close_open_ports(at):
            for port in ports.values():
                if port['opened'] is None:
                    continue
                bar = segment(port['opened'], at)
                if bar:
                    port['intervals'].append(bar)
                port['opened'] = None

        for at, kind, row in sorted(sequence, key=lambda e: (e[0], {2:0, 1:1, 3:2}[e[1]])):
            if at > cutoff:
                break
            if kind == 2:
                if opened is not None:
                    bar = segment(opened, at)
                    if bar: online.append(bar)
                    opened = None
                device_active = False
                close_open_ports(at)
                continue
            if kind == 3:
                try:
                    old_value = json.loads(row['old_value_json'] or 'null')
                    new_value = json.loads(row['new_value_json'] or 'null')
                except (ValueError, TypeError):
                    continue
                endpoint = None
                for value in (new_value, old_value):
                    if not isinstance(value, dict):
                        continue
                    candidate = value.get('port') if isinstance(value.get('port'), dict) else value
                    if candidate.get('port') is not None:
                        endpoint = candidate
                        break
                if endpoint is None:
                    continue
                change_type = str(row['change_type']).upper()
                state = 'open' if change_type in {'PORT_OPENED', 'PORT_ADDED'} else (
                    'closed' if change_type == 'PORT_CLOSED' else 'not_open')
                protocol = str(endpoint.get('protocol') or 'tcp').lower()
                port_number = str(endpoint['port'])
                key = f'{protocol}/{port_number}'
                port = ports.setdefault(key, {
                    'key': key, 'protocol': protocol, 'port': port_number,
                    'opened': None, 'intervals': [], 'observations': [],
                    'last_state': None, 'inventory_state': None, 'ever_open': True,
                    'service': None, 'product': None, 'version': None,
                })
                port['ever_open'] = True
                port_data = {**endpoint, 'protocol': protocol, 'port': port_number, 'state': state}
                port['service'] = port_data.get('service') or port['service']
                port['product'] = port_data.get('product') or port['product']
                port['version'] = port_data.get('version') or port['version']
                port['observations'].append({
                    'id': f"change:{row['id']}", 'observed_at': at.isoformat(),
                    'source': 'Änderungshistorie', 'observation_type': change_type.lower(),
                    'scan_run_id': row['scan_run_id'], 'port_data': port_data,
                })
                port['last_state'] = state
                if state == 'open':
                    if port['opened'] is None:
                        port['opened'] = at
                elif port['opened'] is not None:
                    bar = segment(port['opened'], at)
                    if bar: port['intervals'].append(bar)
                    port['opened'] = None
                continue
            device_active = True
            if opened is None: opened = at
            if row['observation_type'] == 'host_discovery': continue
            try: data = json.loads(row['data_json'])
            except (ValueError, TypeError): continue
            if not isinstance(data, dict): continue
            for index, port_data in enumerate(data.get('ports', [])):
                if not isinstance(port_data, dict) or port_data.get('port') is None:
                    continue
                protocol = str(port_data.get('protocol') or 'tcp').lower()
                port_number = str(port_data['port'])
                key = f'{protocol}/{port_number}'
                port = ports.setdefault(key, {
                    'key': key, 'protocol': protocol, 'port': port_number,
                    'opened': None, 'intervals': [], 'observations': [],
                    'last_state': None, 'inventory_state': None, 'ever_open': False,
                    'service': None, 'product': None, 'version': None,
                })
                port['observations'].append({
                    'id': f"{row['id']}:{index}",
                    'observed_at': at.isoformat(),
                    'source': row['source'],
                    'observation_type': row['observation_type'],
                    'scan_run_id': row['scan_run_id'],
                    'port_data': port_data,
                })
                state = str(port_data.get('state') or '').lower().replace('-', '_')
                port['last_state'] = state
                port['service'] = port_data.get('service') or port['service']
                port['product'] = port_data.get('product') or port['product']
                port['version'] = port_data.get('version') or port['version']
                if state == 'open':
                    port['ever_open'] = True
                    if port['opened'] is None:
                        port['opened'] = at
                elif state in {'closed', 'not_open', 'filtered', 'unfiltered'}:
                    if port['opened'] is not None:
                        bar = segment(port['opened'], at)
                        if bar: port['intervals'].append(bar)
                        port['opened'] = None
        if opened is not None:
            bar = segment(opened, cutoff)
            if bar: online.append(bar)
        close_open_ports(cutoff)

        day_ports = []
        for port in ports.values():
            if port['inventory_state'] is not None and selected == now.astimezone(zone).date():
                port['last_state'] = port['inventory_state']
            day_observations = [item for item in port['observations']
                                if start <= timestamp(item['observed_at']) < end]
            prior = [item for item in port['observations'] if timestamp(item['observed_at']) < start]
            displayed_observations = day_observations
            if not displayed_observations and prior:
                displayed_observations = [prior[-1]]
            # The timeline is a durable view of ports that were actually seen
            # open. A one-off closed/filtered result from enrichment is not a
            # discovered service and must not create a port row by itself.
            if port['ever_open']:
                latest_data = displayed_observations[-1]['port_data'] if displayed_observations else {}
                label = ' · '.join(value for value in (
                    port['key'], latest_data.get('service') or port['service'],
                    latest_data.get('product') or port['product'],
                    latest_data.get('version') or port['version']
                ) if value)
                day_ports.append({
                    'key': port['key'], 'protocol': port['protocol'], 'port': port['port'],
                    'label': label, 'intervals': port['intervals'],
                    'status': port['last_state'],
                    'closed': port['last_state'] in {'closed', 'not_open'},
                    'observations': displayed_observations,
                })
        result.append({**identities.get(device_id, {'id': device_id}), 'intervals': online,
                       'active': device_active,
                       'ports': day_ports, 'services': day_ports})
    def device_ip_order(device):
        try:
            address = ipaddress.ip_address(device.get('ip'))
            return (0, address.version, int(address), device['id'])
        except (ValueError, TypeError):
            return (1, 0, 0, device['id'])

    result.sort(key=device_ip_order)
    return {'day': selected.isoformat(), 'days': days, 'timezone': tz,
            'has_day_observations': has_day_observations, 'devices': result}

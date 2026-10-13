"""Read-only daily view of existing scan evidence; no schema migration."""
import json
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
            AND observation_type IN ('host_discovery','tcp_port_scan','service_scan')
            ORDER BY observed_at,id""", (network_id,)).fetchall()
        missing = db.execute("""SELECT device_id,detected_at FROM changes
            WHERE network_id=? AND upper(change_type)='DEVICE_MISSING' ORDER BY detected_at,id""",
            (network_id,)).fetchall()
        identities = {r['id']: dict(r) for r in db.execute("""SELECT d.id,d.hostname,d.mac,
            (SELECT ip FROM addresses WHERE device_id=d.id AND network_id=?
             ORDER BY last_seen DESC,id DESC LIMIT 1) AS ip FROM devices d
            WHERE EXISTS(SELECT 1 FROM addresses WHERE device_id=d.id AND network_id=?)""",
            (network_id, network_id))}
    days = sorted({timestamp(r['observed_at']).astimezone(zone).date().isoformat() for r in observations}
                  | {timestamp(r['detected_at']).astimezone(zone).date().isoformat() for r in missing})
    selected = day or (date.fromisoformat(days[-1]) if days else now.astimezone(zone).date())
    start = datetime.combine(selected, time.min, zone)
    end = datetime.combine(selected + timedelta(days=1), time.min, zone)
    cutoff = min(end, now)
    events = {}
    for r in observations:
        events.setdefault(r['device_id'], []).append((timestamp(r['observed_at']), 1, r))
    for r in missing:
        events.setdefault(r['device_id'], []).append((timestamp(r['detected_at']), 2, None))

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
    for device_id, sequence in events.items():
        online = []
        ports = {}
        opened = None

        def close_open_ports(at):
            for port in ports.values():
                if port['opened'] is None:
                    continue
                bar = segment(port['opened'], at)
                if bar:
                    port['intervals'].append(bar)
                port['opened'] = None

        for at, kind, row in sorted(sequence, key=lambda e: (e[0], e[1])):
            if at > cutoff:
                break
            if kind == 2:
                if opened is not None:
                    bar = segment(opened, at)
                    if bar: online.append(bar)
                    opened = None
                close_open_ports(at)
                continue
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
                if state == 'open':
                    if port['opened'] is None:
                        port['opened'] = at
                elif state in {'closed', 'filtered', 'not_open', 'unfiltered'} and port['opened'] is not None:
                    bar = segment(port['opened'], at)
                    if bar:
                        port['intervals'].append(bar)
                    port['opened'] = None
        if opened is not None:
            bar = segment(opened, cutoff)
            if bar: online.append(bar)
        close_open_ports(cutoff)

        day_ports = []
        for port in ports.values():
            day_observations = [item for item in port['observations']
                                if start <= timestamp(item['observed_at']) < end]
            prior = [item for item in port['observations'] if timestamp(item['observed_at']) < start]
            displayed_observations = day_observations
            if not displayed_observations and prior:
                displayed_observations = [prior[-1]]
            if port['intervals'] or day_observations:
                latest_data = displayed_observations[-1]['port_data'] if displayed_observations else {}
                label = ' · '.join(value for value in (
                    port['key'], latest_data.get('service'), latest_data.get('product'), latest_data.get('version')
                ) if value)
                day_ports.append({
                    'key': port['key'], 'protocol': port['protocol'], 'port': port['port'],
                    'label': label, 'intervals': port['intervals'], 'observations': displayed_observations,
                })
        if online or day_ports:
            result.append({**identities.get(device_id, {'id': device_id}), 'intervals': online,
                           'ports': day_ports, 'services': day_ports})
    return {'day': selected.isoformat(), 'days': days, 'timezone': tz, 'devices': result}

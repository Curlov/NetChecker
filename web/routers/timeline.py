"""Daily timeline summaries and paginated evidence loaded on demand."""
import ipaddress
import json
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, HTTPException, Query

from web.access import require_network
from web.database import get_connection

router = APIRouter(prefix='/api/timeline', tags=['Timeline'])


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def zone_for(tz):
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(422, 'Unbekannte Zeitzone')


def day_bounds(day, zone):
    # Construct both midnights locally so DST days can contain 23 or 25 hours.
    return (datetime.combine(day, time.min, zone),
            datetime.combine(day + timedelta(days=1), time.min, zone))


def event_id(row):
    return (f"change:{row['source_id']}" if row['source_kind'] == 'change'
            else f"{row['source_id']}:{row['port_index']}")


@router.get('')
def daily(network_id: int = Query(..., ge=1), day: date | None = None,
          tz: str = 'Europe/Berlin'):
    zone = zone_for(tz)
    now = datetime.now(timezone.utc)
    with get_connection() as db:
        require_network(db, network_id)
        # A covering index supplies navigation metadata without reading scan
        # documents. Repeated scan timestamps are deduplicated in SQLite.
        days = sorted({
            datetime.fromtimestamp(round((row[0] - 2440587.5) * 86400, 3), timezone.utc)
            .astimezone(zone).date().isoformat()
            for row in db.execute('SELECT DISTINCT at FROM timeline_events WHERE network_id=?',
                                  (network_id,))
        })
        selected = day or (date.fromisoformat(days[-1]) if days else now.astimezone(zone).date())
        start, end = day_bounds(selected, zone)
        cutoff = min(end, now)
        bounds = (network_id, start.isoformat(), end.isoformat(), cutoff.isoformat())
        # Repeated "still online/open" samples belong in the details, not in
        # interval reconstruction. Keep transitions, metadata updates and the
        # last sample; a missing device resets even an unchanged open port.
        device_events = db.execute("""WITH ranked AS (
            SELECT e.rowid AS event_rowid,e.kind,lag(kind) OVER (
                PARTITION BY device_id ORDER BY at,CASE kind WHEN 2 THEN 0 ELSE 1 END,source_id
            ) AS previous_kind
            FROM timeline_events e WHERE network_id=? AND at>=julianday(?)
                AND at<julianday(?) AND at<=julianday(?) AND kind IN (1,2)
        ) SELECT e.* FROM ranked r JOIN timeline_events e ON e.rowid=r.event_rowid
            WHERE r.kind=2 OR r.previous_kind IS NULL OR r.kind!=r.previous_kind""", bounds).fetchall()
        port_events = db.execute("""WITH ranked AS (
            SELECT e.rowid AS event_rowid,e.network_id,e.device_id,e.at,e.state,
                lag(state) OVER w AS previous_state,lag(at) OVER w AS previous_at
            FROM timeline_events e WHERE network_id=? AND at>=julianday(?)
                AND at<julianday(?) AND at<=julianday(?) AND kind IN (3,4)
            WINDOW w AS (
                PARTITION BY device_id,protocol,port ORDER BY at,kind,source_id,port_index)
        ) SELECT e.* FROM ranked r JOIN timeline_events e ON e.rowid=r.event_rowid
            WHERE r.previous_at IS NULL OR r.state IS NOT r.previous_state
            OR (r.state='open' AND EXISTS (SELECT 1 FROM timeline_events m
                WHERE m.network_id=r.network_id AND m.device_id=r.device_id AND m.kind=2
                  AND m.at>r.previous_at AND m.at<=r.at))""", bounds).fetchall()
        # Counts/search include every sample, while only the latest sample and
        # actual transitions are returned to Python for interval reconstruction.
        metadata = ','.join(f"""(SELECT v.{field} FROM timeline_events v
            WHERE v.network_id=e.network_id AND v.device_id=e.device_id
              AND v.protocol=e.protocol AND v.port=e.port AND v.kind IN (3,4)
              AND v.at>=julianday(?) AND v.at<julianday(?) AND v.at<=julianday(?)
              AND nullif(v.{field},'') IS NOT NULL
            ORDER BY v.at DESC,v.kind DESC,v.source_id DESC,v.port_index DESC LIMIT 1
            ) AS summary_{field}""" for field in ('service', 'product', 'version'))
        port_counts = {
            (r['device_id'], r['protocol'], r['port']): r
            for r in db.execute(f"""SELECT e.*,k.observation_count,k.ever_open,k.combined_search,{metadata}
                FROM (SELECT device_id,protocol,port,count(*) AS observation_count,
                max(kind=4 OR state='open') AS ever_open,group_concat(DISTINCT search_text) AS combined_search
                FROM timeline_events WHERE network_id=? AND at>=julianday(?)
                    AND at<julianday(?) AND at<=julianday(?) AND kind IN (3,4)
                GROUP BY device_id,protocol,port) k
                JOIN timeline_events e ON e.rowid=(
                    SELECT v.rowid FROM timeline_events v WHERE v.network_id=?
                        AND v.device_id=k.device_id AND v.protocol=k.protocol AND v.port=k.port
                        AND v.kind IN (3,4) AND v.at>=julianday(?)
                        AND v.at<julianday(?) AND v.at<=julianday(?)
                    ORDER BY v.at DESC,v.kind DESC,v.source_id DESC,v.port_index DESC LIMIT 1)""",
                ((start.isoformat(), end.isoformat(), cutoff.isoformat()) * 3 + bounds + bounds))
        }
        has_day_observations = db.execute("""SELECT 1 FROM timeline_events WHERE network_id=?
            AND at>=julianday(?) AND at<julianday(?) LIMIT 1""", bounds[:3]).fetchone() is not None
        # Indexed point lookups seed the last device state AND each individual
        # port. A last scan alone can omit ports scanned earlier.
        prior_devices = db.execute("""SELECT * FROM timeline_events WHERE rowid IN (
            SELECT (SELECT rowid FROM timeline_events e WHERE e.network_id=?
                AND e.device_id=k.device_id AND e.kind=k.kind AND e.at<julianday(?)
                ORDER BY e.at DESC,e.source_id DESC LIMIT 1)
            FROM (SELECT DISTINCT device_id,kind FROM timeline_events
                WHERE network_id=? AND kind IN (1,2)) k)""",
            (network_id, start.isoformat(), network_id)).fetchall()
        prior_ports = db.execute("""SELECT e.*,EXISTS (
            SELECT 1 FROM timeline_events opened WHERE opened.network_id=e.network_id
                AND opened.device_id=e.device_id AND opened.protocol=e.protocol AND opened.port=e.port
                AND opened.kind IN (3,4) AND (opened.state='open' OR opened.kind=4)
                AND opened.at<julianday(?)
            ) AS historically_open FROM timeline_events e WHERE rowid IN (
            SELECT (SELECT rowid FROM timeline_events e WHERE e.network_id=?
                AND e.device_id=k.device_id AND e.protocol=k.protocol AND e.port=k.port
                AND e.kind IN (3,4) AND e.at<julianday(?)
                ORDER BY e.at DESC,e.kind DESC,e.source_id DESC,e.port_index DESC LIMIT 1)
            FROM (SELECT DISTINCT device_id,protocol,port FROM timeline_events
                WHERE network_id=? AND kind IN (3,4)) k)""",
            (start.isoformat(), network_id, start.isoformat(), network_id)).fetchall()
        inventory_ports = {}
        for row in db.execute("""SELECT device_id,protocol,port,state,ever_open,service,product,version
            FROM port_inventory WHERE network_id=? AND (ever_open=1 OR state='open')
            ORDER BY device_id,protocol,port""", (network_id,)):
            inventory_ports.setdefault(row['device_id'], []).append(dict(row))
        current_presence = {row['device_id']: row['state'] == 'present'
                            for row in db.execute("""SELECT device_id,state FROM device_presence
                                WHERE network_id=?""", (network_id,))}
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

    events = {}
    historically_open = {(r['device_id'], r['protocol'], r['port'])
                         for r in prior_ports if r['historically_open']}
    # A latest row can also be a transition. Deduplicate its evidence identity.
    unique = {}
    for row in (*prior_devices, *prior_ports, *device_events, *port_events, *port_counts.values()):
        unique[(row['source_kind'], row['source_id'], row['port_index'])] = row
    for row in unique.values():
        events.setdefault(row['device_id'], []).append(row)

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

    def new_port(protocol, number):
        return {'key': f'{protocol}/{number}', 'protocol': protocol, 'port': number,
                'opened': None, 'intervals': [], 'last_state': None, 'inventory_state': None,
                'ever_open': False, 'service': None, 'product': None, 'version': None,
                'count': 0, 'latest': None, 'search': set()}

    result = []
    # Missing closes ports even if a subsequent host discovery has already
    # brought the device online again. Replay that seed before the day's events.
    priority = {2: 0, 1: 1, 3: 2, 4: 3}
    for device_id in dict.fromkeys((*identities, *events)):
        online, ports = [], {}
        for row in inventory_ports.get(device_id, []):
            port = new_port(str(row['protocol'] or 'tcp').lower(), str(row['port']))
            port.update(inventory_state=row['state'], ever_open=True, service=row['service'],
                        product=row['product'], version=row['version'])
            ports[port['key']] = port
        opened, device_active = None, None

        def close_port(port, at):
            if port['opened'] is not None:
                bar = segment(port['opened'], at)
                if bar:
                    port['intervals'].append(bar)
                port['opened'] = None

        for row in sorted(events.get(device_id, []),
                          key=lambda e: (e['at'], priority[e['kind']], e['source_id'], e['port_index'])):
            at = timestamp(row['observed_at'])
            if at > cutoff:
                break
            kind = row['kind']
            if kind == 2:
                if opened is not None:
                    bar = segment(opened, at)
                    if bar:
                        online.append(bar)
                    opened = None
                device_active = False
                for port in ports.values():
                    close_port(port, at)
            elif kind == 1:
                device_active = True
                if opened is None:
                    opened = at
            else:
                key = f"{row['protocol']}/{row['port']}"
                if key not in ports:
                    ports[key] = new_port(row['protocol'], row['port'])
                port = ports[key]
                if (device_id, row['protocol'], row['port']) in historically_open:
                    port['ever_open'] = True
                port['latest'] = row
                port['last_state'] = row['state']
                for field in ('service', 'product', 'version'):
                    port[field] = row[field] or port[field]
                if kind == 4 or row['state'] == 'open':
                    port['ever_open'] = True
                if row['state'] == 'open':
                    if port['opened'] is None:
                        port['opened'] = at
                elif row['state'] in {'closed', 'not_open', 'filtered', 'unfiltered'}:
                    close_port(port, at)
        if opened is not None:
            bar = segment(opened, cutoff)
            if bar:
                online.append(bar)
        day_ports = []
        for port in ports.values():
            close_port(port, cutoff)
            counts = port_counts.get((device_id, port['protocol'], port['port']))
            if counts is not None:
                port['count'] = counts['observation_count']
                port['ever_open'] = port['ever_open'] or counts['ever_open']
                if counts['combined_search']:
                    port['search'].add(counts['combined_search'])
                for field in ('service', 'product', 'version'):
                    port[field] = counts[f'summary_{field}'] or port[field]
            if not port['ever_open']:
                continue
            if port['inventory_state'] is not None and selected == now.astimezone(zone).date():
                port['last_state'] = port['inventory_state']
            latest = port['latest']
            count = port['count'] or (1 if latest is not None else 0)
            if not port['count'] and latest is not None and latest['search_text']:
                port['search'].add(latest['search_text'])
            day_ports.append({
                'key': port['key'], 'protocol': port['protocol'], 'port': port['port'],
                'label': ' · '.join(str(value) for value in
                                   (port['key'], port['service'], port['product'], port['version']) if value),
                'service': port['service'], 'product': port['product'], 'version': port['version'],
                'intervals': port['intervals'], 'status': port['last_state'],
                'current_status': port['inventory_state'],
                'closed': port['last_state'] in {'closed', 'not_open'}, 'observations': [],
                'observation_count': count,
                'observation_revision': f'{count}:{event_id(latest)}' if latest is not None else '0',
                'search_text': ' '.join(sorted(port['search'])),
            })
        result.append({**identities.get(device_id, {'id': device_id}), 'intervals': online,
                       'active': device_active, 'current_active': current_presence.get(device_id),
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


@router.get('/{device_id}/ports/{protocol}/{port}')
def port_observations(device_id: int, protocol: str, port: str,
                      network_id: int = Query(..., ge=1), day: date = Query(...),
                      tz: str = 'Europe/Berlin', offset: int = Query(0, ge=0),
                      limit: int = Query(100, ge=1, le=100)):
    zone = zone_for(tz)
    start, end = day_bounds(day, zone)
    cutoff = min(end, datetime.now(timezone.utc))
    with get_connection() as db:
        require_network(db, network_id)
        params = (network_id, device_id, protocol.lower(), port)
        columns = """e.*,o.observation_type,o.source,o.scan_run_id,
            json_extract(o.data_json,'$.ports[' || e.port_index || ']') AS port_json,
            c.change_type,c.old_value_json,c.new_value_json,c.scan_run_id AS change_scan_run_id"""
        source = """FROM timeline_events e
            LEFT JOIN observations o ON e.source_kind='observation' AND o.id=e.source_id
            LEFT JOIN changes c ON e.source_kind='change' AND c.id=e.source_id
            WHERE e.network_id=? AND e.device_id=? AND e.protocol=? AND e.port=?
              AND e.kind IN (3,4)"""
        window = ' AND e.at>=julianday(?) AND e.at<julianday(?) AND e.at<=julianday(?)'
        bounds = (start.isoformat(), end.isoformat(), cutoff.isoformat())
        rows = db.execute(f"""SELECT {columns} {source} {window}
            ORDER BY e.at,e.kind,e.source_id,e.port_index LIMIT ? OFFSET ?""",
            (*params, *bounds, limit + 1, offset)).fetchall()
        if not rows and offset == 0:
            # Match the overview's fallback evidence for a quiet day.
            rows = db.execute(f"""SELECT {columns} {source} AND e.at<julianday(?)
                ORDER BY e.at DESC,e.kind DESC,e.source_id DESC,e.port_index DESC LIMIT 1""",
                (*params, start.isoformat())).fetchall()

    observations = []
    for row in rows[:limit]:
        if row['source_kind'] == 'observation':
            data = json.loads(row['port_json'])
            source_name, kind, run = row['source'], row['observation_type'], row['scan_run_id']
        else:
            data = {}
            for raw in (row['new_value_json'], row['old_value_json']):
                try:
                    value = json.loads(raw or 'null')
                except (TypeError, ValueError):
                    continue
                if isinstance(value, dict):
                    endpoint = value['port'] if isinstance(value.get('port'), dict) else value
                    if endpoint.get('port') is not None:
                        data = {**endpoint, 'protocol': row['protocol'],
                                'port': row['port'], 'state': row['state']}
                        break
            source_name, kind, run = 'Änderungshistorie', row['change_type'].lower(), row['change_scan_run_id']
        observations.append({'id': event_id(row), 'observed_at': timestamp(row['observed_at']).isoformat(),
                             'source': source_name, 'observation_type': kind, 'scan_run_id': run,
                             'port_data': data})
    return {'observations': observations, 'has_more': len(rows) > limit,
            'next_offset': offset + len(observations) if len(rows) > limit else None}

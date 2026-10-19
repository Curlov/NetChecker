"""Historical topology and per-network layout API."""
import ipaddress
import json
import math
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, root_validator, validator
from web.database import get_connection, get_write_connection
from topology_history import compare_links
from web.access import require_network

router = APIRouter(prefix='/api/topology', tags=['Topology'])
ManualNodeType = Literal[
    'switch', 'router', 'firewall', 'gateway', 'access_point',
    'patchpanel', 'network', 'internet', 'generic',
]
TopologyLinkType = Literal['ethernet', 'fiber', 'wifi', 'logical', 'unknown']
TopologyLinkAnchor = Literal['top', 'right', 'bottom', 'left', 'auto']


class LayoutPosition(BaseModel):
    device_id: int = Field(..., gt=0, strict=True)
    grid_x: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_y: int = Field(..., ge=-1000000, le=1000000, strict=True)

    class Config:
        extra = 'forbid'


class ManualNodePosition(BaseModel):
    manual_node_id: int = Field(..., gt=0, strict=True)
    grid_x: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_y: int = Field(..., ge=-1000000, le=1000000, strict=True)

    class Config:
        extra = 'forbid'


class RoomAssignment(BaseModel):
    room_id: int | None = Field(default=None, gt=0, strict=True)
    device_id: int | None = Field(default=None, gt=0, strict=True)
    manual_node_id: int | None = Field(default=None, gt=0, strict=True)
    grid_x: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)
    grid_y: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)

    @root_validator(skip_on_failure=True)
    def validate_node_ref(cls, values):
        if (values.get('device_id') is None) == (values.get('manual_node_id') is None):
            raise ValueError('Genau eine Geräte- oder manuelle Node-ID ist erforderlich')
        if (values.get('grid_x') is None) != (values.get('grid_y') is None):
            raise ValueError('Rasterposition benötigt X und Y')
        return values

    class Config:
        extra = 'forbid'


class LayoutSaveRequest(BaseModel):
    layout_id: int | None = Field(default=None, gt=0, strict=True)
    positions: list[LayoutPosition] = Field(default_factory=list)
    manual_positions: list[ManualNodePosition] = Field(default_factory=list)
    room_assignments: list[RoomAssignment] = Field(default_factory=list)

    @root_validator(skip_on_failure=True)
    def validate_positions(cls, values):
        positions = values.get('positions') or []
        manual_positions = values.get('manual_positions') or []
        room_assignments = values.get('room_assignments') or []
        if not positions and not manual_positions and not room_assignments:
            raise ValueError('Mindestens eine Position ist erforderlich')
        if len(positions) + len(manual_positions) + len(room_assignments) > 10000:
            raise ValueError('Zu viele Topologiepositionen')
        device_ids = [position.device_id for position in positions]
        if len(device_ids) != len(set(device_ids)):
            raise ValueError('Eine Geräte-ID darf nur einmal vorkommen')
        manual_ids = [position.manual_node_id for position in manual_positions]
        if len(manual_ids) != len(set(manual_ids)):
            raise ValueError('Eine manuelle Node-ID darf nur einmal vorkommen')
        assignment_keys = [
            ('device', item.device_id) if item.device_id is not None
            else ('manual', item.manual_node_id) for item in room_assignments
        ]
        if len(assignment_keys) != len(set(assignment_keys)):
            raise ValueError('Eine Node-Zuordnung darf nur einmal vorkommen')
        cells = [(position.grid_x, position.grid_y) for position in positions]
        cells.extend((position.grid_x, position.grid_y) for position in manual_positions)
        if len(cells) != len(set(cells)):
            raise ValueError('Mehrere Nodes dürfen nicht denselben Rasterplatz belegen')
        return values

    class Config:
        extra = 'forbid'


class RoomCreate(BaseModel):
    layout_id: int | None = Field(default=None, gt=0, strict=True)
    parent_room_id: int | None = Field(default=None, gt=0, strict=True)
    name: str = Field(..., min_length=1, max_length=120, strict=True)
    description: str = Field(default='', max_length=2000, strict=True)
    grid_x: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_y: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_width: int = Field(..., ge=2, le=10000, strict=True)
    grid_height: int = Field(..., ge=1, le=10000, strict=True)
    move_contents: bool = True
    grid_cell_width: int = Field(..., ge=1, le=2000, strict=True)
    grid_cell_height: int = Field(..., ge=1, le=2000, strict=True)

    @validator('name')
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError('Raumname darf nicht leer sein')
        return value.strip()

    @root_validator(skip_on_failure=True)
    def validate_room_bounds(cls, values):
        if values.get('grid_x') is not None and values.get('grid_width') is not None and values['grid_x'] + values['grid_width'] > 1000000:
            raise ValueError('Raumgrenzen liegen außerhalb des gültigen Rasterbereichs')
        if values.get('grid_y') is not None and values.get('grid_height') is not None and values['grid_y'] + values['grid_height'] > 1000000:
            raise ValueError('Raumgrenzen liegen außerhalb des gültigen Rasterbereichs')
        return values

    class Config:
        extra = 'forbid'


class RoomUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120, strict=True)
    description: str | None = Field(default=None, max_length=2000, strict=True)
    move_contents: bool | None = None

    @validator('name')
    def validate_name(cls, value):
        if value is not None and not value.strip():
            raise ValueError('Raumname darf nicht leer sein')
        return value.strip() if value is not None else value

    @root_validator(skip_on_failure=True)
    def require_update(cls, values):
        if all(value is None for value in values.values()):
            raise ValueError('Keine Raumänderung angegeben')
        return values

    class Config:
        extra = 'forbid'


class RoomGeometry(BaseModel):
    grid_x: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_y: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_width: int = Field(..., ge=2, le=10000, strict=True)
    grid_height: int = Field(..., ge=1, le=10000, strict=True)
    parent_room_id: int | None = Field(default=None, gt=0, strict=True)
    move_contents: bool | None = None

    class Config:
        extra = 'forbid'


class ManualNodeCreate(BaseModel):
    node_type: ManualNodeType
    label: str = Field(..., min_length=1, max_length=120, strict=True)
    properties: dict[str, Any] = Field(default_factory=dict)
    linked_device_id: int | None = Field(default=None, gt=0, strict=True)
    grid_x: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)
    grid_y: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)
    layout_id: int | None = Field(default=None, gt=0, strict=True)
    room_id: int | None = Field(default=None, gt=0, strict=True)

    @validator('label')
    def validate_label(cls, value):
        if not value.strip():
            raise ValueError('Bezeichnung darf nicht leer sein')
        return value.strip()

    @validator('properties')
    def validate_properties(cls, value):
        if len(json.dumps(value, ensure_ascii=False)) > 32768:
            raise ValueError('Eigenschaften dürfen höchstens 32 KB groß sein')
        return value

    @root_validator(skip_on_failure=True)
    def validate_grid_pair(cls, values):
        if (values.get('grid_x') is None) != (values.get('grid_y') is None):
            raise ValueError('Rasterposition benötigt X und Y')
        return values

    class Config:
        extra = 'forbid'


class ManualNodeUpdate(BaseModel):
    node_type: ManualNodeType | None = None
    label: str | None = Field(default=None, min_length=1, max_length=120, strict=True)
    properties: dict[str, Any] | None = None
    linked_device_id: int | None = Field(default=None, gt=0, strict=True)
    grid_x: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)
    grid_y: int | None = Field(default=None, ge=-1000000, le=1000000, strict=True)

    @validator('label')
    def validate_label(cls, value):
        if value is not None and not value.strip():
            raise ValueError('Bezeichnung darf nicht leer sein')
        return value.strip() if value is not None else value

    @validator('properties')
    def validate_properties(cls, value):
        if value is not None and len(json.dumps(value, ensure_ascii=False)) > 32768:
            raise ValueError('Eigenschaften dürfen höchstens 32 KB groß sein')
        return value

    @root_validator(skip_on_failure=True)
    def validate_grid_pair(cls, values):
        if (values.get('grid_x') is None) != (values.get('grid_y') is None):
            raise ValueError('Rasterposition benötigt X und Y')
        return values

    class Config:
        extra = 'forbid'


class TopologyLinkEndpoint(BaseModel):
    device_id: int | None = Field(default=None, gt=0, strict=True)
    manual_node_id: int | None = Field(default=None, gt=0, strict=True)
    room_id: int | None = Field(default=None, gt=0, strict=True)
    anchor: TopologyLinkAnchor

    @root_validator(skip_on_failure=True)
    def validate_endpoint_ref(cls, values):
        if sum(values.get(field) is not None for field in
               ('device_id', 'manual_node_id', 'room_id')) != 1:
            raise ValueError('Genau eine Geräte-, manuelle Node- oder Raum-ID ist erforderlich')
        if values.get('room_id') is not None and values.get('anchor') == 'auto':
            raise ValueError('Raumverbindungen benötigen einen Anschluss an einer Raumkante')
        return values

    class Config:
        extra = 'forbid'


class TopologyLinkCreate(BaseModel):
    layout_id: int = Field(..., gt=0, strict=True)
    source: TopologyLinkEndpoint
    target: TopologyLinkEndpoint
    link_type: TopologyLinkType = 'unknown'
    label: str = Field(default='', max_length=120, strict=True)
    description: str = Field(default='', max_length=2000, strict=True)

    @validator('label')
    def normalize_link_label(cls, value):
        return value.strip()

    class Config:
        extra = 'forbid'


class TopologyWaypoint(BaseModel):
    """Canvas-unit offset from the current source anchor of a manual link."""
    x: float
    y: float
    room_axis: Literal['x', 'y'] | None = None
    room_endpoint: Literal['source', 'target'] | None = None

    @validator('x', 'y', pre=True)
    def validate_coordinate(cls, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or \
                not math.isfinite(value) or abs(value) > 10000000:
            raise ValueError('Zwischenpunkte benötigen endliche Koordinaten')
        return value

    class Config:
        extra = 'forbid'


class TopologyLinkUpdate(BaseModel):
    link_type: TopologyLinkType | None = None
    label: str | None = Field(default=None, max_length=120, strict=True)
    description: str | None = Field(default=None, max_length=2000, strict=True)
    waypoints: list[TopologyWaypoint] | None = Field(default=None, max_length=128)
    source_anchor: TopologyLinkAnchor | None = None
    target_anchor: TopologyLinkAnchor | None = None

    @validator('label')
    def normalize_link_label(cls, value):
        return value.strip() if value is not None else value

    @validator('waypoints')
    def validate_waypoints(cls, value):
        if value is None:
            return value
        room_markers = [point for point in value if point.room_axis is not None]
        named_endpoints = [point.room_endpoint for point in room_markers
                           if point.room_endpoint is not None]
        if len(room_markers) > 2 or len(named_endpoints) != len(set(named_endpoints)):
            raise ValueError('Raumanschlüsse dürfen nur einmal je Endpunkt gespeichert werden')
        if any(point.room_endpoint is not None and point.room_axis is None for point in value):
            raise ValueError('Raumanschlüsse benötigen eine gültige Ausrichtungsachse')
        route_points = [point for point in value if point.room_axis is None]
        for before, after in zip(route_points, route_points[1:]):
            if before.x == after.x and before.y == after.y:
                raise ValueError('Zwischenpunkte dürfen sich nicht wiederholen')
            if before.x != after.x and before.y != after.y:
                raise ValueError('Zwischenpunkte müssen orthogonal verbunden sein')
        return value

    class Config:
        extra = 'forbid'


def _topology_link_payload(row):
    item = dict(row)
    source = {'anchor': item['source_anchor']}
    target = {'anchor': item['target_anchor']}
    for field in ('device_id', 'manual_node_id', 'room_id'):
        source_id = item.get(f'source_{field}')
        target_id = item.get(f'target_{field}')
        if source_id is not None:
            source[field] = source_id
        if target_id is not None:
            target[field] = target_id
    return {
        'id': item['id'], 'layout_id': item['layout_id'],
        'source': source, 'target': target,
        'link_type': item['link_type'], 'label': item['label'],
        'description': item['description'], 'evidence_status': item['evidence_status'],
        'waypoints': json.loads(item.get('waypoints_json') or '[]'),
        'created_at': item.get('created_at'), 'updated_at': item.get('updated_at'),
    }


def _link_endpoint_columns(endpoint, side):
    return {
        f'{side}_device_id': endpoint.device_id,
        f'{side}_manual_node_id': endpoint.manual_node_id,
        f'{side}_room_id': endpoint.room_id,
        f'{side}_anchor': endpoint.anchor,
    }


def _link_endpoint_identity(db, layout_id, endpoint):
    if endpoint.device_id is not None:
        return ('device', endpoint.device_id)
    if endpoint.manual_node_id is not None:
        row = db.execute(
            'SELECT linked_device_id FROM topology_manual_nodes WHERE id=? AND layout_id=?',
            (endpoint.manual_node_id, layout_id),
        ).fetchone()
        return ('device', row['linked_device_id']) if row and row['linked_device_id'] is not None \
            else ('manual', endpoint.manual_node_id)
    return ('room', endpoint.room_id)


def _validate_link_endpoint(db, network_id, layout_id, endpoint):
    if endpoint.device_id is not None:
        if not db.execute(
            'SELECT 1 FROM addresses WHERE network_id=? AND device_id=? LIMIT 1',
            (network_id, endpoint.device_id),
        ).fetchone():
            raise HTTPException(404, 'Geräteendpunkt gehört nicht zum gewählten Netzwerk')
        placed = db.execute(
            """SELECT 1 FROM topology_layout_positions
               WHERE layout_id=? AND device_id=?
               UNION ALL
               SELECT 1 FROM topology_manual_nodes
               WHERE layout_id=? AND linked_device_id=? LIMIT 1""",
            (layout_id, endpoint.device_id, layout_id, endpoint.device_id),
        ).fetchone()
        if not placed:
            raise HTTPException(409, 'Nur platzierte Geräte können verbunden werden')
    elif endpoint.manual_node_id is not None:
        if not db.execute(
            'SELECT 1 FROM topology_manual_nodes WHERE id=? AND layout_id=?',
            (endpoint.manual_node_id, layout_id),
        ).fetchone():
            raise HTTPException(404, 'Manueller Endpunkt gehört nicht zu diesem Layout')
    elif not db.execute(
        'SELECT 1 FROM topology_rooms WHERE id=? AND layout_id=?',
        (endpoint.room_id, layout_id),
    ).fetchone():
        raise HTTPException(404, 'Raumendpunkt gehört nicht zu diesem Layout')


def _validate_topology_link(db, layout_id, source, target, *, exclude_link_id=None):
    source_identity = _link_endpoint_identity(db, layout_id, source)
    target_identity = _link_endpoint_identity(db, layout_id, target)
    if source_identity == target_identity:
        raise HTTPException(422, 'Eine Verbindung benötigt zwei verschiedene Endpunkte')
    rows = db.execute(
        'SELECT * FROM topology_layout_links WHERE layout_id=?', (layout_id,),
    ).fetchall()
    for row in rows:
        if exclude_link_id is not None and row['id'] == exclude_link_id:
            continue
        old_source = TopologyLinkEndpoint(
            device_id=row['source_device_id'],
            manual_node_id=row['source_manual_node_id'],
            room_id=row['source_room_id'], anchor=row['source_anchor'],
        )
        old_target = TopologyLinkEndpoint(
            device_id=row['target_device_id'],
            manual_node_id=row['target_manual_node_id'],
            room_id=row['target_room_id'], anchor=row['target_anchor'],
        )
        old_source_identity = _link_endpoint_identity(db, layout_id, old_source)
        old_target_identity = _link_endpoint_identity(db, layout_id, old_target)
        if ((source_identity, target_identity) == (old_source_identity, old_target_identity) or
                (source_identity, target_identity) == (old_target_identity, old_source_identity)):
            raise HTTPException(409, 'Diese Verbindung zwischen den Objekten existiert bereits')


def layout_payload(db, network_id, layout):
    if layout is None:
        return {'layout': None, 'positions': [], 'manual_nodes': [], 'rooms': [],
                'links': [], 'saved': False}
    positions = db.execute(
        """SELECT p.device_id, p.grid_x, p.grid_y, p.updated_at
           FROM topology_layout_positions p
           WHERE p.layout_id = ? AND EXISTS (
               SELECT 1 FROM addresses a
               WHERE a.network_id = ? AND a.device_id = p.device_id
           )
           ORDER BY p.device_id""",
        (layout['id'], network_id),
    ).fetchall()
    manual_nodes = []
    for row in db.execute(
        """SELECT m.*, d.hostname AS linked_device_hostname,
                  n.cidr AS linked_network_cidr,n.gateway AS linked_network_gateway,
                  n.interface AS linked_network_interface,
                  (SELECT COUNT(DISTINCT a.device_id) FROM addresses a
                   WHERE a.network_id=m.linked_network_id) AS linked_network_device_count
           FROM topology_manual_nodes m
           LEFT JOIN devices d ON d.id=m.linked_device_id
           LEFT JOIN networks n ON n.id=m.linked_network_id
           WHERE m.layout_id=? ORDER BY m.id""",
        (layout['id'],),
    ):
        item = dict(row)
        try:
            properties = json.loads(item.pop('properties_json'))
            item['properties'] = properties if isinstance(properties, dict) else {}
        except (TypeError, ValueError):
            item['properties'] = {}
        # Keep legacy visibility state in SQLite for compatibility, but the
        # editor no longer supports hiding topology objects.
        item.pop('is_hidden', None)
        manual_nodes.append(item)
    rooms = [dict(row) for row in db.execute(
        'SELECT * FROM topology_rooms WHERE layout_id=? ORDER BY id', (layout['id'],)
    )]
    device_rooms = db.execute(
        'SELECT room_id,device_id FROM topology_room_devices WHERE layout_id=? ORDER BY device_id',
        (layout['id'],),
    ).fetchall()
    manual_rooms = db.execute(
        'SELECT room_id,manual_node_id FROM topology_room_manual_nodes '
        'WHERE layout_id=? ORDER BY manual_node_id', (layout['id'],),
    ).fetchall()
    links = [_topology_link_payload(row) for row in db.execute(
        'SELECT * FROM topology_layout_links WHERE layout_id=? ORDER BY id', (layout['id'],),
    )]
    by_room = {room['id']: room for room in rooms}
    for room in rooms:
        room['move_contents'] = bool(room['move_contents'])
        room['device_ids'] = []
        room['manual_node_ids'] = []
        room['connection_points'] = {
            'top': {'x':room['grid_x'] + room['grid_width']/2, 'y':room['grid_y']},
            'right': {'x':room['grid_x'] + room['grid_width'], 'y':room['grid_y'] + room['grid_height']/2},
            'bottom': {'x':room['grid_x'] + room['grid_width']/2, 'y':room['grid_y'] + room['grid_height']},
            'left': {'x':room['grid_x'], 'y':room['grid_y'] + room['grid_height']/2},
        }
    for item in device_rooms:
        if item['room_id'] in by_room:
            by_room[item['room_id']]['device_ids'].append(item['device_id'])
    for item in manual_rooms:
        if item['room_id'] in by_room:
            by_room[item['room_id']]['manual_node_ids'].append(item['manual_node_id'])
    return {
        'layout': dict(layout),
        'positions': [dict(row) for row in positions],
        'manual_nodes': manual_nodes,
        'rooms': rooms,
        'links': links,
        'saved': True,
    }


def _ensure_default_layout(db, network_id):
    layout = db.execute(
        'SELECT * FROM topology_layouts WHERE network_id=? AND is_default=1',
        (network_id,),
    ).fetchone()
    if layout is None:
        cursor = db.execute(
            "INSERT INTO topology_layouts(network_id,name,is_default) VALUES(?, 'Standard', 1)",
            (network_id,),
        )
        layout = db.execute(
            'SELECT * FROM topology_layouts WHERE id=?', (cursor.lastrowid,)
        ).fetchone()
    return layout


def _layout_for_network(db, network_id, layout_id=None):
    if layout_id is None:
        layout = _ensure_default_layout(db, network_id)
    else:
        layout = db.execute(
            'SELECT * FROM topology_layouts WHERE id=? AND network_id=?',
            (layout_id, network_id),
        ).fetchone()
        if layout is None:
            raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')
    return layout


def _room_for_network(db, room_id, network_id):
    room = db.execute(
        """SELECT r.*,l.network_id FROM topology_rooms r
           JOIN topology_layouts l ON l.id=r.layout_id
           WHERE r.id=? AND l.network_id=?""",
        (room_id, network_id),
    ).fetchone()
    if room is None:
        raise HTTPException(404, 'Raum gehört nicht zum gewählten Netzwerk')
    return room


def _validate_room_parent(db, layout_id, room_id, parent_room_id, geometry):
    if parent_room_id is None:
        return
    parent = db.execute(
        'SELECT * FROM topology_rooms WHERE id=? AND layout_id=?',
        (parent_room_id, layout_id),
    ).fetchone()
    if parent is None:
        raise HTTPException(404, 'Übergeordneter Raum gehört nicht zum gewählten Layout')
    if room_id is not None:
        if parent_room_id == room_id:
            raise HTTPException(409, 'Ein Raum kann nicht sein eigener Unterraum sein')
        descendant = db.execute(
            """WITH RECURSIVE descendants(id) AS (
                   SELECT id FROM topology_rooms WHERE parent_room_id=?
                   UNION
                   SELECT r.id FROM topology_rooms r
                   JOIN descendants d ON r.parent_room_id=d.id
               )
               SELECT 1 FROM descendants WHERE id=?""",
            (room_id, parent_room_id),
        ).fetchone()
        if descendant:
            raise HTTPException(409, 'Die Raumverschachtelung würde einen Zyklus erzeugen')
    if not (
        geometry['grid_x'] >= parent['grid_x']
        and geometry['grid_y'] >= parent['grid_y']
        and geometry['grid_x'] + geometry['grid_width'] <= parent['grid_x'] + parent['grid_width']
        and geometry['grid_y'] + geometry['grid_height'] <= parent['grid_y'] + parent['grid_height']
    ):
        raise HTTPException(409, 'Der Unterraum muss vollständig innerhalb seines übergeordneten Raums liegen')


def _room_subtree(db, room_id, layout_id):
    return [dict(row) for row in db.execute(
        """WITH RECURSIVE subtree(id) AS (
               SELECT id FROM topology_rooms WHERE id=? AND layout_id=?
               UNION
               SELECT r.id FROM topology_rooms r
               JOIN subtree s ON r.parent_room_id=s.id
               WHERE r.layout_id=?
           )
           SELECT r.* FROM topology_rooms r JOIN subtree s ON s.id=r.id
           WHERE r.layout_id=? ORDER BY r.id""",
        (room_id, layout_id, layout_id, layout_id),
    )]


def _apply_room_assignment(db, network_id, layout_id, assignment):
    room_id = assignment.room_id
    if room_id is not None:
        room = db.execute(
            'SELECT id FROM topology_rooms WHERE id=? AND layout_id=?',
            (room_id, layout_id),
        ).fetchone()
        if room is None:
            raise HTTPException(404, 'Raum gehört nicht zum gewählten Layout')
    if assignment.device_id is not None:
        device_id = assignment.device_id
        belongs = db.execute(
            'SELECT 1 FROM addresses WHERE network_id=? AND device_id=? LIMIT 1',
            (network_id, device_id),
        ).fetchone()
        if belongs is None:
            raise HTTPException(404, 'Gerät gehört nicht zum gewählten Netzwerk')
        linked_manual = db.execute(
            'SELECT id FROM topology_manual_nodes WHERE layout_id=? AND linked_device_id=?',
            (layout_id, device_id),
        ).fetchone()
        if linked_manual is not None:
            db.execute(
                'DELETE FROM topology_room_devices WHERE layout_id=? AND device_id=?',
                (layout_id, device_id),
            )
            if room_id is None:
                db.execute(
                    'DELETE FROM topology_room_manual_nodes WHERE layout_id=? AND manual_node_id=?',
                    (layout_id, linked_manual['id']),
                )
            else:
                db.execute(
                    """INSERT INTO topology_room_manual_nodes(layout_id,room_id,manual_node_id)
                       VALUES(?,?,?) ON CONFLICT(layout_id,manual_node_id)
                       DO UPDATE SET room_id=excluded.room_id""",
                    (layout_id, room_id, linked_manual['id']),
                )
            db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (layout_id,))
            return
        current_position = db.execute(
            'SELECT grid_x,grid_y FROM topology_layout_positions '
            'WHERE layout_id=? AND device_id=?', (layout_id, device_id),
        ).fetchone()
        if current_position is None and assignment.grid_x is not None:
            collision = db.execute(
                """SELECT 1 FROM topology_layout_positions WHERE layout_id=? AND grid_x=? AND grid_y=?
                   UNION ALL
                   SELECT 1 FROM topology_manual_nodes WHERE layout_id=? AND grid_x=? AND grid_y=?
                   LIMIT 1""",
                (layout_id, assignment.grid_x, assignment.grid_y,
                 layout_id, assignment.grid_x, assignment.grid_y),
            ).fetchone()
            if collision:
                raise HTTPException(409, 'Rasterplatz ist bereits belegt')
            db.execute(
                'INSERT INTO topology_layout_positions(layout_id,device_id,grid_x,grid_y) VALUES(?,?,?,?)',
                (layout_id, device_id, assignment.grid_x, assignment.grid_y),
            )
        elif current_position is None and room_id is not None:
            raise HTTPException(409, 'Gerät muss zuerst eine gespeicherte Rasterposition erhalten')
        if room_id is None:
            db.execute(
                'DELETE FROM topology_room_devices WHERE layout_id=? AND device_id=?',
                (layout_id, device_id),
            )
        else:
            db.execute(
                """INSERT INTO topology_room_devices(layout_id,room_id,device_id)
                   VALUES(?,?,?) ON CONFLICT(layout_id,device_id)
                   DO UPDATE SET room_id=excluded.room_id""",
                (layout_id, room_id, device_id),
            )
    else:
        manual_id = assignment.manual_node_id
        manual = db.execute(
            'SELECT 1 FROM topology_manual_nodes WHERE id=? AND layout_id=?',
            (manual_id, layout_id),
        ).fetchone()
        if manual is None:
            raise HTTPException(404, 'Manuelles Objekt gehört nicht zum gewählten Layout')
        linked_device = db.execute(
            'SELECT linked_device_id FROM topology_manual_nodes WHERE id=? AND layout_id=?',
            (manual_id, layout_id),
        ).fetchone()['linked_device_id']
        if linked_device is not None:
            db.execute(
                'DELETE FROM topology_room_devices WHERE layout_id=? AND device_id=?',
                (layout_id, linked_device),
            )
        if room_id is None:
            db.execute(
                'DELETE FROM topology_room_manual_nodes WHERE layout_id=? AND manual_node_id=?',
                (layout_id, manual_id),
            )
        else:
            db.execute(
                """INSERT INTO topology_room_manual_nodes(layout_id,room_id,manual_node_id)
                   VALUES(?,?,?) ON CONFLICT(layout_id,manual_node_id)
                   DO UPDATE SET room_id=excluded.room_id""",
                (layout_id, room_id, manual_id),
            )
    db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (layout_id,))


def _manual_node_payload(db, node_id):
    row = db.execute(
        """SELECT m.*, d.hostname AS linked_device_hostname,
                  n.cidr AS linked_network_cidr,n.gateway AS linked_network_gateway,
                  n.interface AS linked_network_interface,
                  (SELECT COUNT(DISTINCT a.device_id) FROM addresses a
                   WHERE a.network_id=m.linked_network_id) AS linked_network_device_count
           FROM topology_manual_nodes m
           LEFT JOIN devices d ON d.id=m.linked_device_id
           LEFT JOIN networks n ON n.id=m.linked_network_id
           WHERE m.id=?""",
        (node_id,),
    ).fetchone()
    item = dict(row)
    try:
        properties = json.loads(item.pop('properties_json'))
        item['properties'] = properties if isinstance(properties, dict) else {}
    except (TypeError, ValueError):
        item['properties'] = {}
    item.pop('is_hidden', None)
    return item


def _resolve_network_node(db, network_id, node_type, label):
    if node_type != 'network':
        return label, None
    try:
        canonical = str(ipaddress.ip_network(label, strict=False))
    except ValueError as error:
        raise HTTPException(422, 'Netzwerkobjekte benötigen eine gültige CIDR-Adresse') from error

    current = db.execute('SELECT scope_id,cidr FROM networks WHERE id=?', (network_id,)).fetchone()
    if current['cidr'] == canonical:
        return canonical, network_id
    candidates = db.execute(
        'SELECT id FROM networks WHERE scope_id=? AND cidr=? ORDER BY id',
        (current['scope_id'], canonical),
    ).fetchall()
    if len(candidates) > 1:
        raise HTTPException(
            409,
            'Dieses CIDR gehört zu mehreren gespeicherten Netzwerken; die Zuordnung ist nicht eindeutig',
        )
    return canonical, candidates[0]['id'] if candidates else None


def _validate_linked_device(db, network_id, device_id):
    if device_id is None:
        return
    if not db.execute(
        """SELECT 1 FROM addresses a
           JOIN devices d ON d.id=a.device_id
           JOIN networks n ON n.id=a.network_id
           WHERE a.network_id=? AND a.device_id=? AND d.scope_id=n.scope_id LIMIT 1""",
        (network_id, device_id),
    ).fetchone():
        raise HTTPException(404, 'Verknüpftes Gerät gehört nicht zum gewählten Netzwerk')


def _occupied_cells(db, layout_id, *, exclude_manual_id=None):
    cells = {
        (row['grid_x'], row['grid_y'])
        for row in db.execute(
            'SELECT grid_x,grid_y FROM topology_layout_positions WHERE layout_id=?',
            (layout_id,),
        )
    }
    query = 'SELECT id,grid_x,grid_y FROM topology_manual_nodes WHERE layout_id=?'
    parameters = [layout_id]
    if exclude_manual_id is not None:
        query += ' AND id!=?'
        parameters.append(exclude_manual_id)
    cells.update(
        (row['grid_x'], row['grid_y'])
        for row in db.execute(query, parameters)
    )
    return cells


def _first_free_cell(db, layout_id):
    occupied = _occupied_cells(db, layout_id)
    for column in range(len(occupied) + 1):
        if (column, 0) not in occupied:
            return column, 0
    raise HTTPException(409, 'Kein freier Rasterplatz verfügbar')


@router.get('/layout')
def get_layout(
    network_id: int = Query(..., ge=1),
    layout_id: int | None = Query(default=None, ge=1),
):
    """Load a selected layout, or the network's standard layout."""
    with get_connection() as db:
        require_network(db, network_id)
        if layout_id is None:
            layout = db.execute(
                'SELECT * FROM topology_layouts WHERE network_id=? AND is_default=1',
                (network_id,),
            ).fetchone()
        else:
            layout = db.execute(
                'SELECT * FROM topology_layouts WHERE id=? AND network_id=?',
                (layout_id, network_id),
            ).fetchone()
            if layout is None:
                raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')
        return layout_payload(db, network_id, layout)


@router.put('/layout')
def save_layout(
    payload: LayoutSaveRequest,
    network_id: int = Query(..., ge=1),
):
    """Persist a batch of snapped positions in one SQLite transaction."""
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)

        if payload.layout_id is not None:
            layout = db.execute(
                'SELECT * FROM topology_layouts WHERE id=? AND network_id=?',
                (payload.layout_id, network_id),
            ).fetchone()
            if layout is None:
                raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')
        else:
            layout = db.execute(
                'SELECT * FROM topology_layouts WHERE network_id=? AND is_default=1',
                (network_id,),
            ).fetchone()
            if layout is None:
                cursor = db.execute(
                    """INSERT INTO topology_layouts(network_id,name,is_default)
                       VALUES(?, 'Standard', 1)""",
                    (network_id,),
                )
                layout = db.execute(
                    'SELECT * FROM topology_layouts WHERE id=?', (cursor.lastrowid,)
                ).fetchone()

        requested_ids = {position.device_id for position in payload.positions}
        network_device_ids = {
            row['device_id']
            for row in db.execute(
                'SELECT DISTINCT device_id FROM addresses WHERE network_id=?',
                (network_id,),
            )
        }
        if not requested_ids <= network_device_ids:
            raise HTTPException(404, 'Mindestens ein Gerät gehört nicht zum gewählten Netzwerk')

        by_device = {
            row['device_id']: dict(row)
            for row in db.execute(
                'SELECT device_id,grid_x,grid_y,updated_at '
                'FROM topology_layout_positions WHERE layout_id=?',
                (layout['id'],),
            )
        }
        for position in payload.positions:
            by_device[position.device_id] = {
                'device_id': position.device_id,
                'grid_x': position.grid_x,
                'grid_y': position.grid_y,
                'updated_at': None,
            }

        manual_by_id = {
            row['id']: {'grid_x':row['grid_x'], 'grid_y':row['grid_y']}
            for row in db.execute(
                'SELECT id,grid_x,grid_y FROM topology_manual_nodes WHERE layout_id=?',
                (layout['id'],),
            )
        }
        requested_manual_ids = {
            position.manual_node_id for position in payload.manual_positions
        }
        if not requested_manual_ids <= manual_by_id.keys():
            raise HTTPException(404, 'Mindestens ein manuelles Objekt gehört nicht zu diesem Layout')
        for position in payload.manual_positions:
            manual_by_id[position.manual_node_id] = {
                'grid_x':position.grid_x,
                'grid_y':position.grid_y,
            }

        occupied = {}
        for position in by_device.values():
            cell = (position['grid_x'], position['grid_y'])
            if cell in occupied:
                raise HTTPException(409, 'Rasterplatz ist bereits durch einen anderen Node belegt')
            occupied[cell] = ('device', position['device_id'])
        for manual_node_id, position in manual_by_id.items():
            cell = (position['grid_x'], position['grid_y'])
            if cell in occupied:
                raise HTTPException(409, 'Rasterplatz ist bereits durch einen anderen Node belegt')
            occupied[cell] = ('manual', manual_node_id)

        db.execute('DELETE FROM topology_layout_positions WHERE layout_id=?', (layout['id'],))
        db.executemany(
            """INSERT INTO topology_layout_positions(
                   layout_id,device_id,grid_x,grid_y,updated_at
               ) VALUES(?,?,?,?,COALESCE(?,CURRENT_TIMESTAMP))""",
            [
                (layout['id'], row['device_id'], row['grid_x'], row['grid_y'], row['updated_at'])
                for row in by_device.values()
            ],
        )
        for position in payload.manual_positions:
            db.execute(
                """UPDATE topology_manual_nodes
                   SET grid_x=?,grid_y=?,updated_at=CURRENT_TIMESTAMP
                   WHERE id=? AND layout_id=?""",
                (position.grid_x,position.grid_y,position.manual_node_id,layout['id']),
            )
        for assignment in payload.room_assignments:
            _apply_room_assignment(db, network_id, layout['id'], assignment)
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (layout['id'],),
        )
        layout = db.execute(
            'SELECT * FROM topology_layouts WHERE id=?', (layout['id'],)
        ).fetchone()
        response = layout_payload(db, network_id, layout)
    return response


@router.delete('/layout/positions/{device_id}')
def unplace_device(
    device_id: int,
    network_id: int = Query(..., ge=1),
    layout_id: int | None = Query(default=None, ge=1),
):
    """Remove only a device's canvas placement and room membership."""
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        belongs = db.execute(
            'SELECT 1 FROM addresses WHERE network_id=? AND device_id=? LIMIT 1',
            (network_id, device_id),
        ).fetchone()
        if belongs is None:
            raise HTTPException(404, 'Gerät gehört nicht zum gewählten Netzwerk')
        layout = _layout_for_network(db, network_id, layout_id)
        linked = db.execute(
            'SELECT id FROM topology_manual_nodes WHERE layout_id=? AND linked_device_id=?',
            (layout['id'], device_id),
        ).fetchone()
        if linked is not None:
            db.execute(
                'UPDATE topology_manual_nodes SET linked_device_id=NULL,updated_at=CURRENT_TIMESTAMP '
                'WHERE id=? AND layout_id=?',
                (linked['id'],layout['id']),
            )
        db.execute(
            """DELETE FROM topology_layout_links WHERE layout_id=?
               AND (source_device_id=? OR target_device_id=?)""",
            (layout['id'],device_id,device_id),
        )
        db.execute(
            'DELETE FROM topology_layout_positions WHERE layout_id=? AND device_id=?',
            (layout['id'], device_id),
        )
        db.execute(
            'DELETE FROM topology_room_devices WHERE layout_id=? AND device_id=?',
            (layout['id'], device_id),
        )
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (layout['id'],),
        )
        layout = db.execute(
            'SELECT * FROM topology_layouts WHERE id=?', (layout['id'],)
        ).fetchone()
        response = layout_payload(db, network_id, layout)
    return {'deleted': True, **response}


@router.get('/rooms')
def get_rooms(
    network_id: int = Query(..., ge=1),
    layout_id: int | None = Query(default=None, ge=1),
):
    with get_connection() as db:
        require_network(db, network_id)
        layout = _layout_for_network(db, network_id, layout_id) if layout_id is not None else db.execute(
            'SELECT * FROM topology_layouts WHERE network_id=? AND is_default=1',
            (network_id,),
        ).fetchone()
        if layout is None:
            return {'rooms': [], 'layout_id': None}
        result = layout_payload(db, network_id, layout)
        return {'rooms': result['rooms'], 'layout_id': layout['id']}


@router.post('/rooms')
def create_room(payload: RoomCreate, network_id: int = Query(..., ge=1)):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        layout = _layout_for_network(db, network_id, payload.layout_id)
        geometry = {
            'grid_x':payload.grid_x,'grid_y':payload.grid_y,
            'grid_width':payload.grid_width,'grid_height':payload.grid_height,
        }
        _validate_room_parent(db, layout['id'], None, payload.parent_room_id, geometry)
        duplicate = db.execute(
            'SELECT 1 FROM topology_rooms WHERE layout_id=? AND lower(name)=lower(?)',
            (layout['id'], payload.name),
        ).fetchone()
        if duplicate:
            raise HTTPException(409, 'Ein Raum mit diesem Namen existiert bereits')
        db.execute(
            """UPDATE topology_layouts SET
                   grid_cell_width=COALESCE(grid_cell_width,?),
                   grid_cell_height=COALESCE(grid_cell_height,?),
                   updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (payload.grid_cell_width, payload.grid_cell_height, layout['id']),
        )
        cursor = db.execute(
            """INSERT INTO topology_rooms(
                   layout_id,parent_room_id,name,description,grid_x,grid_y,grid_width,grid_height,move_contents
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (layout['id'],payload.parent_room_id,payload.name,payload.description,
             payload.grid_x,payload.grid_y,payload.grid_width,payload.grid_height,
             int(payload.move_contents)),
        )
        layout = db.execute('SELECT * FROM topology_layouts WHERE id=?', (layout['id'],)).fetchone()
        result = layout_payload(db, network_id, layout)
        return {'room': next(room for room in result['rooms'] if room['id'] == cursor.lastrowid),
                'rooms': result['rooms'], 'layout': result['layout']}


@router.put('/rooms/assignment')
def assign_room_member(
    payload: RoomAssignment,
    network_id: int = Query(..., ge=1),
    layout_id: int = Query(..., ge=1),
):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        layout = _layout_for_network(db, network_id, layout_id)
        _apply_room_assignment(db, network_id, layout['id'], payload)
        return layout_payload(db, network_id, layout)['rooms']


@router.put('/rooms/{room_id}')
def update_room(
    room_id: int,
    payload: RoomUpdate,
    network_id: int = Query(..., ge=1),
):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        room = _room_for_network(db, room_id, network_id)
        if payload.name is not None:
            duplicate = db.execute(
                'SELECT 1 FROM topology_rooms WHERE layout_id=? AND lower(name)=lower(?) AND id<>?',
                (room['layout_id'], payload.name, room_id),
            ).fetchone()
            if duplicate:
                raise HTTPException(409, 'Ein Raum mit diesem Namen existiert bereits')
        fields = payload.model_dump(exclude_unset=True)
        updates = {key:value for key,value in fields.items() if value is not None}
        assignments = ','.join(f'{key}=?' for key in updates)
        db.execute(
            f'UPDATE topology_rooms SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (*[int(value) if key == 'move_contents' else value
               for key,value in updates.items()], room_id),
        )
        db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (room['layout_id'],))
        layout = db.execute('SELECT * FROM topology_layouts WHERE id=?', (room['layout_id'],)).fetchone()
        result = layout_payload(db, network_id, layout)
        return next(item for item in result['rooms'] if item['id'] == room_id)


@router.put('/rooms/{room_id}/geometry')
def update_room_geometry(
    room_id: int,
    payload: RoomGeometry,
    network_id: int = Query(..., ge=1),
):
    if payload.grid_x + payload.grid_width > 1000000 or payload.grid_y + payload.grid_height > 1000000:
        raise HTTPException(422, 'Raumgrenzen liegen außerhalb des gültigen Rasterbereichs')
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        room = _room_for_network(db, room_id, network_id)
        fields = payload.model_dump(exclude_unset=True)
        geometry = {
            'grid_x':payload.grid_x,'grid_y':payload.grid_y,
            'grid_width':payload.grid_width,'grid_height':payload.grid_height,
        }
        parent_room_id = fields.get('parent_room_id',room['parent_room_id'])
        _validate_room_parent(
            db,room['layout_id'],room_id,parent_room_id,geometry,
        )
        delta_x = payload.grid_x - room['grid_x']
        delta_y = payload.grid_y - room['grid_y']
        move_contents = payload.move_contents is True
        subtree = _room_subtree(db,room_id,room['layout_id'])
        subtree_ids = [item['id'] for item in subtree]
        room_by_id = {item['id']:item for item in subtree}
        move_rooms = move_contents and bool(delta_x or delta_y)
        moved_room_geometry = {}
        for item in subtree:
            if item['id'] == room_id:
                next_geometry = geometry
            else:
                offset_x,offset_y = (delta_x,delta_y) if move_rooms else (0,0)
                next_geometry = {
                    'grid_x':item['grid_x']+offset_x,
                    'grid_y':item['grid_y']+offset_y,
                    'grid_width':item['grid_width'],
                    'grid_height':item['grid_height'],
                }
            if (next_geometry['grid_x'] < -1000000 or next_geometry['grid_y'] < -1000000 or
                next_geometry['grid_x']+next_geometry['grid_width'] > 1000000 or
                next_geometry['grid_y']+next_geometry['grid_height'] > 1000000):
                raise HTTPException(409, 'Die Raumbewegung überschreitet den gültigen Rasterbereich')
            moved_room_geometry[item['id']] = next_geometry

        # Every nested room remains fully within its immediate parent. A room
        # move translates the whole subtree; a resize leaves descendants still.
        for item in subtree:
            if item['id'] == room_id:
                continue
            parent = room_by_id.get(item['parent_room_id'])
            child_geometry = moved_room_geometry[item['id']]
            parent_geometry = moved_room_geometry.get(item['parent_room_id'])
            if parent is None or parent_geometry is None or not (
                child_geometry['grid_x'] >= parent_geometry['grid_x'] and
                child_geometry['grid_y'] >= parent_geometry['grid_y'] and
                child_geometry['grid_x']+child_geometry['grid_width'] <=
                    parent_geometry['grid_x']+parent_geometry['grid_width'] and
                child_geometry['grid_y']+child_geometry['grid_height'] <=
                    parent_geometry['grid_y']+parent_geometry['grid_height']
            ):
                raise HTTPException(409, 'Die Änderung würde einen Unterraum aus seinem Elternraum verschieben')

        # This flag describes the geometry operation, not the room's saved
        # preference. Resizes omit it; explicit moves translate nested rooms
        # and assigned nodes together. The preference stays editable via RoomUpdate.
        moving_devices = []
        moving_manual = []
        if move_contents and (delta_x or delta_y):
            moving_devices = [dict(row) for row in db.execute(
                """SELECT p.device_id,p.grid_x,p.grid_y FROM topology_room_devices m
                   JOIN topology_layout_positions p ON p.layout_id=m.layout_id AND p.device_id=m.device_id
                   WHERE m.room_id IN (%s) AND m.layout_id=?""" %
                   ','.join('?' for _ in subtree_ids), (*subtree_ids,room['layout_id']))]
            device_members = db.execute(
                """SELECT m.device_id FROM topology_room_devices m
                   LEFT JOIN topology_layout_positions p ON p.layout_id=m.layout_id AND p.device_id=m.device_id
                   WHERE m.room_id IN (%s) AND p.device_id IS NULL""" %
                   ','.join('?' for _ in subtree_ids), subtree_ids
            ).fetchone()
            if device_members:
                raise HTTPException(409, 'Ein enthaltenes Gerät besitzt keine gespeicherte Position')
            moving_manual = [dict(row) for row in db.execute(
                """SELECT n.id AS manual_node_id,n.grid_x,n.grid_y FROM topology_room_manual_nodes m
                   JOIN topology_manual_nodes n ON n.id=m.manual_node_id AND n.layout_id=m.layout_id
                   WHERE m.room_id IN (%s) AND m.layout_id=?""" %
                   ','.join('?' for _ in subtree_ids), (*subtree_ids,room['layout_id']))]
            moving = {('device', row['device_id']) for row in moving_devices}
            moving.update(('manual', row['manual_node_id']) for row in moving_manual)
            target_cells = set()
            for row in moving_devices:
                cell = (row['grid_x'] + delta_x, row['grid_y'] + delta_y)
                if not (-1000000 <= cell[0] <= 1000000 and -1000000 <= cell[1] <= 1000000):
                    raise HTTPException(409, 'Die Gesamtbewegung überschreitet den gültigen Rasterbereich')
                target_cells.add(cell)
            for row in moving_manual:
                cell = (row['grid_x'] + delta_x, row['grid_y'] + delta_y)
                if not (-1000000 <= cell[0] <= 1000000 and -1000000 <= cell[1] <= 1000000):
                    raise HTTPException(409, 'Die Gesamtbewegung überschreitet den gültigen Rasterbereich')
                target_cells.add(cell)
            if len(target_cells) != len(moving_devices) + len(moving_manual):
                raise HTTPException(409, 'Die Gesamtbewegung erzeugt eine Rasterkollision')
            occupied = set()
            current_cells = set()
            for row in db.execute(
                'SELECT device_id,grid_x,grid_y FROM topology_layout_positions WHERE layout_id=?',
                (room['layout_id'],),
            ):
                current_cells.add((row['grid_x'],row['grid_y']))
                if ('device', row['device_id']) not in moving:
                    occupied.add((row['grid_x'], row['grid_y']))
            for row in db.execute(
                'SELECT id,grid_x,grid_y FROM topology_manual_nodes WHERE layout_id=?',
                (room['layout_id'],),
            ):
                current_cells.add((row['grid_x'],row['grid_y']))
                if ('manual', row['id']) not in moving:
                    occupied.add((row['grid_x'], row['grid_y']))
            if target_cells & occupied:
                raise HTTPException(409, 'Die Gesamtbewegung kollidiert mit einem anderen Objekt')
            if moving_devices:
                ids = [row['device_id'] for row in moving_devices]
                db.executemany(
                    'DELETE FROM topology_layout_positions WHERE layout_id=? AND device_id=?',
                    [(room['layout_id'], item) for item in ids],
                )
                db.executemany(
                    """INSERT INTO topology_layout_positions(layout_id,device_id,grid_x,grid_y)
                       VALUES(?,?,?,?)""",
                    [(room['layout_id'], row['device_id'], row['grid_x'] + delta_x,
                      row['grid_y'] + delta_y) for row in moving_devices],
                )
            if moving_manual:
                temporary = current_cells | target_cells
                for index, row in enumerate(moving_manual):
                    x, y = 1000000, 1000000-index
                    while (x, y) in temporary:
                        y -= 1
                        if y < -1000000:
                            x -= 1; y = 1000000
                    temporary.add((x,y))
                    db.execute(
                        'UPDATE topology_manual_nodes SET grid_x=?,grid_y=? WHERE id=? AND layout_id=?',
                        (x,y,row['manual_node_id'],room['layout_id']),
                    )
                db.executemany(
                    """UPDATE topology_manual_nodes SET grid_x=?,grid_y=?,updated_at=CURRENT_TIMESTAMP
                       WHERE id=? AND layout_id=?""",
                    [(row['grid_x'] + delta_x, row['grid_y'] + delta_y,
                      row['manual_node_id'], room['layout_id']) for row in moving_manual],
                )
        if move_rooms and len(subtree) > 1:
            db.executemany(
                """UPDATE topology_rooms SET grid_x=?,grid_y=?,updated_at=CURRENT_TIMESTAMP
                   WHERE id=? AND layout_id=?""",
                [(moved_room_geometry[item['id']]['grid_x'],
                  moved_room_geometry[item['id']]['grid_y'],item['id'],room['layout_id'])
                 for item in subtree if item['id'] != room_id],
            )
        db.execute(
            """UPDATE topology_rooms SET grid_x=?,grid_y=?,grid_width=?,grid_height=?,
                   parent_room_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (payload.grid_x,payload.grid_y,payload.grid_width,payload.grid_height,
             parent_room_id,room_id),
        )
        db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (room['layout_id'],))
        layout = db.execute('SELECT * FROM topology_layouts WHERE id=?', (room['layout_id'],)).fetchone()
        result = layout_payload(db, network_id, layout)
        return {'room': next(item for item in result['rooms'] if item['id'] == room_id),
                'rooms': result['rooms'], 'layout': result['layout']}


@router.post('/rooms/{room_id}/duplicate')
def duplicate_room(room_id: int, network_id: int = Query(..., ge=1)):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        room = _room_for_network(db, room_id, network_id)
        base_name = f"{room['name']} (Kopie)"
        name = base_name
        suffix = 2
        while db.execute(
            'SELECT 1 FROM topology_rooms WHERE layout_id=? AND lower(name)=lower(?)',
            (room['layout_id'],name),
        ).fetchone():
            name = f"{base_name} {suffix}"; suffix += 1
        cursor = db.execute(
            """INSERT INTO topology_rooms(layout_id,parent_room_id,name,description,grid_x,grid_y,
                   grid_width,grid_height,move_contents)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (room['layout_id'],room['parent_room_id'],name,room['description'],room['grid_x'],room['grid_y'],
             room['grid_width'],room['grid_height'],room['move_contents']),
        )
        db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (room['layout_id'],))
        layout = db.execute('SELECT * FROM topology_layouts WHERE id=?', (room['layout_id'],)).fetchone()
        result = layout_payload(db, network_id, layout)
        return {'room': next(item for item in result['rooms'] if item['id'] == cursor.lastrowid),
                'rooms': result['rooms']}


@router.delete('/rooms/{room_id}')
def delete_room(room_id: int, network_id: int = Query(..., ge=1)):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        room = _room_for_network(db, room_id, network_id)
        room_ids = [item['id'] for item in _room_subtree(db, room_id, room['layout_id'])]
        room_marks = ','.join('?' for _ in room_ids)
        members = (room['layout_id'], *room_ids)
        ancestor_ids = [row['id'] for row in db.execute(
            """WITH RECURSIVE ancestors(id,parent_room_id) AS (
                   SELECT id,parent_room_id FROM topology_rooms WHERE id=? AND layout_id=?
                   UNION
                   SELECT r.id,r.parent_room_id FROM topology_rooms r
                   JOIN ancestors a ON r.id=a.parent_room_id WHERE r.layout_id=?
               ) SELECT id FROM ancestors""",
            (room_id,room['layout_id'],room['layout_id']),
        )]
        own_room_ids = sorted(set(room_ids) | set(ancestor_ids))
        own_room_marks = ','.join('?' for _ in own_room_ids)
        bounds = (room['grid_x'],room['grid_x']+room['grid_width'],
                  room['grid_y'],room['grid_y']+room['grid_height'])
        device_ids = {row['device_id'] for row in db.execute(
            f"""SELECT device_id FROM topology_room_devices
                WHERE layout_id=? AND room_id IN ({room_marks})""", members,
        )}
        device_ids.update(row['device_id'] for row in db.execute(
            f"""SELECT p.device_id FROM topology_layout_positions p
                LEFT JOIN topology_room_devices m
                  ON m.layout_id=p.layout_id AND m.device_id=p.device_id
                WHERE p.layout_id=? AND p.grid_x>=? AND p.grid_x<?
                  AND p.grid_y>=? AND p.grid_y<?
                  AND (m.room_id IS NULL OR m.room_id IN ({own_room_marks}))""",
            (room['layout_id'],*bounds,*own_room_ids),
        ))
        manual_rows = {row['manual_node_id']:row['linked_device_id'] for row in db.execute(
            f"""SELECT m.manual_node_id,n.linked_device_id
                FROM topology_room_manual_nodes m
                JOIN topology_manual_nodes n ON n.id=m.manual_node_id AND n.layout_id=m.layout_id
                WHERE m.layout_id=? AND m.room_id IN ({room_marks})""", members,
        )}
        manual_rows.update((row['id'],row['linked_device_id']) for row in db.execute(
            f"""SELECT n.id,n.linked_device_id FROM topology_manual_nodes n
                LEFT JOIN topology_room_manual_nodes m
                  ON m.layout_id=n.layout_id AND m.manual_node_id=n.id
                WHERE n.layout_id=? AND n.grid_x>=? AND n.grid_x<?
                  AND n.grid_y>=? AND n.grid_y<?
                  AND (m.room_id IS NULL OR m.room_id IN ({own_room_marks}))""",
            (room['layout_id'],*bounds,*own_room_ids),
        ))
        manual_ids = sorted(manual_rows)
        device_ids.update(device_id for device_id in manual_rows.values() if device_id is not None)
        if device_ids:
            device_list = sorted(device_ids)
            device_marks = ','.join('?' for _ in device_list)
            devices = (room['layout_id'], *device_list)
            db.execute(
                f"""DELETE FROM topology_layout_links WHERE layout_id=?
                    AND (source_device_id IN ({device_marks})
                         OR target_device_id IN ({device_marks}))""",
                (room['layout_id'], *device_list, *device_list),
            )
            db.execute(
                f'DELETE FROM topology_layout_positions WHERE layout_id=? AND device_id IN ({device_marks})',
                devices,
            )
            db.execute(
                f'DELETE FROM topology_room_devices WHERE layout_id=? AND device_id IN ({device_marks})',
                devices,
            )
            db.execute(
                f"""UPDATE topology_manual_nodes SET linked_device_id=NULL,
                    updated_at=CURRENT_TIMESTAMP
                    WHERE layout_id=? AND linked_device_id IN ({device_marks})""",
                devices,
            )
        if manual_ids:
            manual_marks = ','.join('?' for _ in manual_ids)
            db.execute(
                f'DELETE FROM topology_manual_nodes WHERE layout_id=? AND id IN ({manual_marks})',
                (room['layout_id'], *manual_ids),
            )
        db.execute(
            f'DELETE FROM topology_rooms WHERE layout_id=? AND id IN ({room_marks})',
            members,
        )
        db.execute('UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (room['layout_id'],))
        layout = db.execute('SELECT * FROM topology_layouts WHERE id=?', (room['layout_id'],)).fetchone()
        return layout_payload(db, network_id, layout)


@router.post('/manual-nodes')
def create_manual_node(
    payload: ManualNodeCreate,
    network_id: int = Query(..., ge=1),
):
    """Create a topology-only object without adding scanner inventory rows."""
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        if payload.layout_id is None:
            layout = _ensure_default_layout(db, network_id)
        else:
            layout = db.execute(
                'SELECT * FROM topology_layouts WHERE id=? AND network_id=?',
                (payload.layout_id, network_id),
            ).fetchone()
            if layout is None:
                raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')

        label, linked_network_id = _resolve_network_node(
            db, network_id, payload.node_type, payload.label
        )
        _validate_linked_device(db, network_id, payload.linked_device_id)
        if payload.node_type == 'network' and db.execute(
            """SELECT 1 FROM topology_manual_nodes
               WHERE layout_id=? AND node_type='network' AND lower(label)=lower(?)""",
            (layout['id'], label),
        ).fetchone():
            raise HTTPException(409, 'Dieses Netzwerkobjekt existiert in diesem Layout bereits')
        if payload.linked_device_id is not None and db.execute(
            'SELECT 1 FROM topology_manual_nodes WHERE layout_id=? AND linked_device_id=?',
            (layout['id'],payload.linked_device_id),
        ).fetchone():
            raise HTTPException(409, 'Dieses Gerät ist bereits mit einem manuellen Objekt verknüpft')

        if payload.grid_x is None:
            grid_x, grid_y = _first_free_cell(db, layout['id'])
        else:
            grid_x, grid_y = payload.grid_x, payload.grid_y
        if (grid_x,grid_y) in _occupied_cells(db, layout['id']):
            raise HTTPException(409, 'Rasterplatz ist bereits durch einen anderen Node belegt')

        cursor = db.execute(
            """INSERT INTO topology_manual_nodes(
                   layout_id,node_type,label,properties_json,linked_device_id,
                   linked_network_id,grid_x,grid_y
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (layout['id'],payload.node_type,label,
             json.dumps(payload.properties,ensure_ascii=False,sort_keys=True),
             payload.linked_device_id,linked_network_id,grid_x,grid_y),
        )
        if payload.room_id is not None:
            _apply_room_assignment(
                db, network_id, layout['id'],
                RoomAssignment(room_id=payload.room_id, manual_node_id=cursor.lastrowid),
            )
        return {'node':_manual_node_payload(db,cursor.lastrowid)}


@router.put('/manual-nodes/{manual_node_id}')
def update_manual_node(
    manual_node_id: int,
    payload: ManualNodeUpdate,
    network_id: int = Query(..., ge=1),
):
    """Edit properties, association, or snapped position."""
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, 'Keine Änderungen angegeben')
    if ('node_type' in changes and changes['node_type'] is None) or (
        'label' in changes and changes['label'] is None
    ) or ('properties' in changes and changes['properties'] is None) or (
        'grid_x' in changes and changes['grid_x'] is None
    ) or (
        'grid_y' in changes and changes['grid_y'] is None
    ):
        raise HTTPException(422, 'Typ, Bezeichnung, Eigenschaften und Rasterposition dürfen nicht null sein')

    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        node = db.execute(
            """SELECT m.*,l.network_id FROM topology_manual_nodes m
               JOIN topology_layouts l ON l.id=m.layout_id
               WHERE m.id=? AND l.network_id=?""",
            (manual_node_id,network_id),
        ).fetchone()
        if node is None:
            raise HTTPException(404, 'Manuelles Objekt gehört nicht zum gewählten Netzwerk')

        node_type = changes.get('node_type',node['node_type'])
        label = changes.get('label',node['label'])
        label, linked_network_id = _resolve_network_node(db,network_id,node_type,label)
        if node_type == 'network' and db.execute(
            """SELECT 1 FROM topology_manual_nodes
               WHERE layout_id=? AND node_type='network' AND lower(label)=lower(?) AND id!=?""",
            (node['layout_id'],label,manual_node_id),
        ).fetchone():
            raise HTTPException(409, 'Dieses Netzwerkobjekt existiert in diesem Layout bereits')

        linked_device_id = changes.get('linked_device_id',node['linked_device_id'])
        _validate_linked_device(db,network_id,linked_device_id)
        if linked_device_id is not None and db.execute(
            'SELECT 1 FROM topology_manual_nodes WHERE layout_id=? AND linked_device_id=? AND id!=?',
            (node['layout_id'],linked_device_id,manual_node_id),
        ).fetchone():
            raise HTTPException(409, 'Dieses Gerät ist bereits mit einem manuellen Objekt verknüpft')

        grid_x = changes.get('grid_x',node['grid_x'])
        grid_y = changes.get('grid_y',node['grid_y'])
        occupied = _occupied_cells(db,node['layout_id'],exclude_manual_id=manual_node_id)
        link_changed = 'linked_device_id' in changes and linked_device_id != node['linked_device_id']
        if (link_changed and linked_device_id is not None and
            'grid_x' not in changes and 'grid_y' not in changes and
            (grid_x,grid_y) in occupied):
            grid_x,grid_y = _first_free_cell(db,node['layout_id'])
        if (('grid_x' in changes or 'grid_y' in changes) and (grid_x,grid_y) in occupied):
            raise HTTPException(409, 'Rasterplatz ist bereits durch einen anderen Node belegt')
        properties = changes.get('properties')
        properties_json = (
            json.dumps(properties,ensure_ascii=False,sort_keys=True)
            if properties is not None else node['properties_json']
        )
        db.execute(
            """UPDATE topology_manual_nodes SET node_type=?,label=?,properties_json=?,
               linked_device_id=?,linked_network_id=?,grid_x=?,grid_y=?,
               updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (node_type,label,properties_json,linked_device_id,linked_network_id,
             grid_x,grid_y,manual_node_id),
        )
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (node['layout_id'],),
        )
        return {'node':_manual_node_payload(db,manual_node_id)}


@router.delete('/manual-nodes/{manual_node_id}')
def delete_manual_node(
    manual_node_id: int,
    network_id: int = Query(..., ge=1),
):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db,network_id)
        node = db.execute(
            """SELECT m.id,m.layout_id FROM topology_manual_nodes m
               JOIN topology_layouts l ON l.id=m.layout_id
               WHERE m.id=? AND l.network_id=?""",
            (manual_node_id,network_id),
        ).fetchone()
        if node is None:
            raise HTTPException(404, 'Manuelles Objekt gehört nicht zum gewählten Netzwerk')
        db.execute('DELETE FROM topology_manual_nodes WHERE id=?',(manual_node_id,))
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (node['layout_id'],),
        )
    return {'deleted':True,'id':manual_node_id}


@router.get('/links')
def get_layout_links(
    network_id: int = Query(..., ge=1),
    layout_id: int | None = Query(default=None, ge=1),
):
    """Load only the explicitly documented links belonging to a layout."""
    with get_connection() as db:
        require_network(db, network_id)
        if layout_id is None:
            layout = db.execute(
                'SELECT id FROM topology_layouts WHERE network_id=? AND is_default=1',
                (network_id,),
            ).fetchone()
        else:
            layout = db.execute(
                'SELECT id FROM topology_layouts WHERE id=? AND network_id=?',
                (layout_id, network_id),
            ).fetchone()
            if layout is None:
                raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')
        links = [] if layout is None else [
            _topology_link_payload(row) for row in db.execute(
                'SELECT * FROM topology_layout_links WHERE layout_id=? ORDER BY id',
                (layout['id'],),
            )
        ]
    return {'links':links, 'layout_id':layout['id'] if layout else None}


@router.post('/links', status_code=201)
def create_layout_link(
    payload: TopologyLinkCreate,
    network_id: int = Query(..., ge=1),
):
    """Create a user-drawn link; scanner evidence is never assigned here."""
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        layout = db.execute(
            'SELECT * FROM topology_layouts WHERE id=? AND network_id=?',
            (payload.layout_id, network_id),
        ).fetchone()
        if layout is None:
            raise HTTPException(404, 'Layout gehört nicht zum gewählten Netzwerk')
        _validate_link_endpoint(db, network_id, layout['id'], payload.source)
        _validate_link_endpoint(db, network_id, layout['id'], payload.target)
        _validate_topology_link(db, layout['id'], payload.source, payload.target)
        columns = {
            **_link_endpoint_columns(payload.source, 'source'),
            **_link_endpoint_columns(payload.target, 'target'),
        }
        cursor = db.execute(
            """INSERT INTO topology_layout_links(
                   layout_id,source_device_id,source_manual_node_id,source_room_id,
                   target_device_id,target_manual_node_id,target_room_id,
                   source_anchor,target_anchor,link_type,label,description,
                   evidence_status,relation,waypoints_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'manual','[]')""",
            (layout['id'],columns['source_device_id'],columns['source_manual_node_id'],
             columns['source_room_id'],columns['target_device_id'],
             columns['target_manual_node_id'],columns['target_room_id'],
             payload.source.anchor,payload.target.anchor,payload.link_type,payload.label,
             payload.description,'manual_documented'),
        )
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (layout['id'],),
        )
        link = db.execute(
            'SELECT * FROM topology_layout_links WHERE id=?', (cursor.lastrowid,),
        ).fetchone()
    return {'link':_topology_link_payload(link)}


@router.put('/links/{link_id}')
def update_layout_link(
    link_id: int,
    payload: TopologyLinkUpdate,
    network_id: int = Query(..., ge=1),
):
    """Edit documentation and manual routing without changing evidence provenance."""
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, 'Keine Verbindungsänderung angegeben')
    if any(value is None for value in changes.values()):
        raise HTTPException(422, 'Verbindungsfelder dürfen nicht null sein')
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        link = db.execute(
            """SELECT x.* FROM topology_layout_links x
               JOIN topology_layouts l ON l.id=x.layout_id
               WHERE x.id=? AND l.network_id=?""",
            (link_id,network_id),
        ).fetchone()
        if link is None:
            raise HTTPException(404, 'Verbindung gehört nicht zum gewählten Netzwerk')
        for point in payload.waypoints or []:
            if point.room_axis is None:
                continue
            if point.room_endpoint == 'source' and link['source_room_id'] is None or \
                    point.room_endpoint == 'target' and link['target_room_id'] is None or \
                    point.room_endpoint is None and not (
                        link['source_room_id'] is not None and link['target_room_id'] is not None
                    ):
                raise HTTPException(422, 'Die Ausrichtung muss zu einem Raum-Endpunkt passen')
        for endpoint, anchor_field in (('source', 'source_anchor'), ('target', 'target_anchor')):
            if changes.get(anchor_field) == 'auto' and link[f'{endpoint}_room_id'] is not None:
                raise HTTPException(422, 'Raumverbindungen benötigen einen Anschluss an einer Raumkante')
        fields = {
            'link_type':'link_type', 'label':'label', 'description':'description',
            'waypoints':'waypoints_json', 'source_anchor':'source_anchor',
            'target_anchor':'target_anchor',
        }
        assignments = ','.join(f'{column}=?' for column in (fields[key] for key in changes))
        values = [json.dumps(
            [{name:item for name,item in waypoint.items() if item is not None}
             for waypoint in value], separators=(',',':')) if key == 'waypoints' else value
            for key, value in changes.items()]
        db.execute(
            f'UPDATE topology_layout_links SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (*values,link_id),
        )
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (link['layout_id'],),
        )
        result = db.execute(
            'SELECT * FROM topology_layout_links WHERE id=?', (link_id,),
        ).fetchone()
    return {'link':_topology_link_payload(result)}


@router.delete('/links/{link_id}')
def delete_layout_link(
    link_id: int,
    network_id: int = Query(..., ge=1),
):
    with get_write_connection() as db:
        db.execute('BEGIN IMMEDIATE')
        require_network(db, network_id)
        link = db.execute(
            """SELECT x.id,x.layout_id FROM topology_layout_links x
               JOIN topology_layouts l ON l.id=x.layout_id
               WHERE x.id=? AND l.network_id=?""",
            (link_id,network_id),
        ).fetchone()
        if link is None:
            raise HTTPException(404, 'Verbindung gehört nicht zum gewählten Netzwerk')
        db.execute('DELETE FROM topology_layout_links WHERE id=?', (link_id,))
        db.execute(
            'UPDATE topology_layouts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (link['layout_id'],),
        )
    return {'deleted':True, 'id':link_id}


@router.get('/snapshots')
def get_snapshots(network_id: int = Query(..., ge=1), limit: int = Query(100, ge=1, le=1000)):
    with get_connection() as db:
        require_network(db, network_id)
        rows = db.execute("""SELECT id,created_at,completed_at,status,source_summary_json
            FROM topology_snapshots WHERE network_id=? ORDER BY id DESC LIMIT ?""",
            (network_id,limit)).fetchall()
    return {'snapshots':[dict(row) for row in rows]}


@router.get('')
def get_topology(network_id: int = Query(..., ge=1), snapshot_id: int | None = Query(None, ge=1)):
    with get_connection() as db:
        require_network(db, network_id)
        snapshot = db.execute("""SELECT * FROM topology_snapshots WHERE network_id=?
            AND (? IS NULL OR id=?) AND (? IS NOT NULL OR status IN ('complete','partial')) ORDER BY id DESC LIMIT 1""",
            (network_id,snapshot_id,snapshot_id,snapshot_id)).fetchone()
        if not snapshot:
            raise HTTPException(404, 'Kein Topologie-Snapshot für dieses Netzwerk')
        report = {'snapshot':dict(snapshot)}
        for name in ('routes','neighbors','segments','interfaces','links','endpoint_interfaces','policies','identity_candidates'):
            report[name] = [dict(row) for row in db.execute('SELECT * FROM topology_' + name + ' WHERE snapshot_id=? ORDER BY id', (snapshot['id'],))]
        # Hints are time-varying state and must not be presented as part of an
        # old snapshot. The original link/raw evidence remains in its snapshot.
    return report


@router.get('/compare')
def compare_topology(network_id: int = Query(..., ge=1), before: int = Query(..., ge=1),
                     after: int = Query(..., ge=1)):
    with get_connection() as db:
        require_network(db, network_id)
        snapshots = []
        links = []
        for identifier in (before, after):
            snapshot = db.execute('SELECT * FROM topology_snapshots WHERE id=? AND network_id=?',
                                  (identifier,network_id)).fetchone()
            if snapshot is None:
                raise HTTPException(404, 'Snapshot gehört nicht zum gewählten Netzwerk')
            snapshots.append(dict(snapshot))
            links.append([dict(row) for row in db.execute('SELECT * FROM topology_links WHERE snapshot_id=? ORDER BY id', (identifier,))])
        return dict(compare_links(*links), before=snapshots[0], after=snapshots[1])

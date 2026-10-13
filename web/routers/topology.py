"""Historical topology and per-network layout API."""
import ipaddress
import json
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
    name: str = Field(..., min_length=1, max_length=120, strict=True)
    description: str = Field(default='', max_length=2000, strict=True)
    grid_x: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_y: int = Field(..., ge=-1000000, le=1000000, strict=True)
    grid_width: int = Field(..., ge=2, le=10000, strict=True)
    grid_height: int = Field(..., ge=2, le=10000, strict=True)
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
    grid_height: int = Field(..., ge=2, le=10000, strict=True)
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
    is_hidden: bool | None = None

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


def layout_payload(db, network_id, layout):
    if layout is None:
        return {'layout': None, 'positions': [], 'manual_nodes': [], 'rooms': [], 'saved': False}
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
        item['is_hidden'] = bool(item['is_hidden'])
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
    item['is_hidden'] = bool(item['is_hidden'])
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
                   layout_id,name,description,grid_x,grid_y,grid_width,grid_height,move_contents
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (layout['id'], payload.name, payload.description, payload.grid_x, payload.grid_y,
             payload.grid_width, payload.grid_height, int(payload.move_contents)),
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
        delta_x = payload.grid_x - room['grid_x']
        delta_y = payload.grid_y - room['grid_y']
        # This flag describes this geometry operation, not the room's saved
        # preference. Resizes omit it; only an explicit move request may
        # translate assigned nodes. The preference stays editable via RoomUpdate.
        move_contents = payload.move_contents is True
        moving_devices = []
        moving_manual = []
        if move_contents and (delta_x or delta_y):
            moving_devices = [dict(row) for row in db.execute(
                """SELECT p.device_id,p.grid_x,p.grid_y FROM topology_room_devices m
                   JOIN topology_layout_positions p ON p.layout_id=m.layout_id AND p.device_id=m.device_id
                   WHERE m.room_id=? AND m.layout_id=?""", (room_id, room['layout_id']))]
            device_members = db.execute(
                """SELECT m.device_id FROM topology_room_devices m
                   LEFT JOIN topology_layout_positions p ON p.layout_id=m.layout_id AND p.device_id=m.device_id
                   WHERE m.room_id=? AND p.device_id IS NULL""", (room_id,)
            ).fetchone()
            if device_members:
                raise HTTPException(409, 'Ein enthaltenes Gerät besitzt keine gespeicherte Position')
            moving_manual = [dict(row) for row in db.execute(
                """SELECT n.id AS manual_node_id,n.grid_x,n.grid_y FROM topology_room_manual_nodes m
                   JOIN topology_manual_nodes n ON n.id=m.manual_node_id AND n.layout_id=m.layout_id
                   WHERE m.room_id=? AND m.layout_id=?""", (room_id, room['layout_id']))]
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
        db.execute(
            """UPDATE topology_rooms SET grid_x=?,grid_y=?,grid_width=?,grid_height=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (payload.grid_x,payload.grid_y,payload.grid_width,payload.grid_height,room_id),
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
            """INSERT INTO topology_rooms(layout_id,name,description,grid_x,grid_y,
                   grid_width,grid_height,move_contents)
               VALUES(?,?,?,?,?,?,?,?)""",
            (room['layout_id'],name,room['description'],room['grid_x'],room['grid_y'],
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
        db.execute('DELETE FROM topology_rooms WHERE id=?', (room_id,))
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
    """Edit properties, association, visibility, or snapped position."""
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, 'Keine Änderungen angegeben')
    if ('node_type' in changes and changes['node_type'] is None) or (
        'label' in changes and changes['label'] is None
    ) or ('properties' in changes and changes['properties'] is None) or (
        'is_hidden' in changes and changes['is_hidden'] is None
    ) or ('grid_x' in changes and changes['grid_x'] is None) or (
        'grid_y' in changes and changes['grid_y'] is None
    ):
        raise HTTPException(422, 'Typ, Bezeichnung, Eigenschaften und Sichtbarkeit dürfen nicht null sein')

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
        is_hidden = bool(changes.get('is_hidden',node['is_hidden']))
        occupied = _occupied_cells(db,node['layout_id'],exclude_manual_id=manual_node_id)
        link_changed = 'linked_device_id' in changes and linked_device_id != node['linked_device_id']
        if (link_changed and linked_device_id is not None and
            'grid_x' not in changes and 'grid_y' not in changes and
            (grid_x,grid_y) in occupied):
            grid_x,grid_y = _first_free_cell(db,node['layout_id'])
        if ((('grid_x' in changes or 'grid_y' in changes) or
             ('is_hidden' in changes and not is_hidden)) and (grid_x,grid_y) in occupied):
            if bool(node['is_hidden']) and not is_hidden and not (
                'grid_x' in changes or 'grid_y' in changes
            ):
                # A hidden node may have had its former cell reused. Put it on
                # the first free cell so re-showing it always remains possible.
                grid_x,grid_y = _first_free_cell(db,node['layout_id'])
            else:
                raise HTTPException(409, 'Rasterplatz ist bereits durch einen anderen Node belegt')
        properties = changes.get('properties')
        properties_json = (
            json.dumps(properties,ensure_ascii=False,sort_keys=True)
            if properties is not None else node['properties_json']
        )
        db.execute(
            """UPDATE topology_manual_nodes SET node_type=?,label=?,properties_json=?,
               linked_device_id=?,linked_network_id=?,grid_x=?,grid_y=?,is_hidden=?,
               updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (node_type,label,properties_json,linked_device_id,linked_network_id,
             grid_x,grid_y,int(is_hidden),manual_node_id),
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

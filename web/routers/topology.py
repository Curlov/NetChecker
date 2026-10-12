"""Read-only historical topology API. All requests require a network."""
from fastapi import APIRouter, HTTPException, Query
from web.database import get_connection
from topology_history import compare_links
from web.access import require_network

router = APIRouter(prefix='/api/topology', tags=['Topology'])


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

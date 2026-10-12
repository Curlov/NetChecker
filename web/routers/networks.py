
from fastapi import APIRouter
from web.database import get_connection
from web.access import allowed_scopes

router = APIRouter(
    prefix="/api/networks",
    tags=["Networks"]
)


@router.get("")
def get_networks():
    with get_connection() as db:
        rows = db.execute("""
            SELECT
                n.id,
                n.cidr,
                n.interface,
                n.gateway,
                n.first_seen,
                n.last_seen,
                n.scope_id,
                s.name AS scope_name,
                s.customer,
                s.site,
                COUNT(DISTINCT a.device_id) AS device_count
            FROM networks n
            JOIN network_scopes s ON s.id=n.scope_id
            LEFT JOIN addresses a
                ON a.network_id = n.id
            GROUP BY n.id
            ORDER BY n.id
        """).fetchall()

        scopes = allowed_scopes(db)
        rows = [row for row in rows if row['scope_id'] in scopes]

    return {
        "count": len(rows),
        "networks": [dict(row) for row in rows]
    }


@router.get('/scopes')
def get_scopes():
    with get_connection() as db:
        allowed = allowed_scopes(db)
        return {'scopes': [dict(row) for row in db.execute('SELECT * FROM network_scopes ORDER BY id') if row['id'] in allowed]}

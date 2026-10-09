
from fastapi import APIRouter
from web.database import get_connection

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
                COUNT(DISTINCT a.device_id) AS device_count
            FROM networks n
            LEFT JOIN addresses a
                ON a.network_id = n.id
            GROUP BY n.id
            ORDER BY n.id
        """).fetchall()

    return {
        "count": len(rows),
        "networks": [dict(row) for row in rows]
    }

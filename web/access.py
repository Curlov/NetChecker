"""Optional per-installation access control, independent of customer identifiers."""
import os
from fastapi import HTTPException


def allowed_scopes(connection):
    configured = os.environ.get('NETCHECKER_ALLOWED_SCOPES', '').strip()
    if not configured:
        return {row[0] for row in connection.execute('SELECT id FROM network_scopes')}
    try:
        return {int(value.strip()) for value in configured.split(',') if int(value.strip()) > 0}
    except ValueError as error:
        raise HTTPException(503, 'Ungültige Bereichskonfiguration') from error


def require_network(connection, network_id):
    row = connection.execute('SELECT scope_id FROM networks WHERE id=?', (network_id,)).fetchone()
    if row is None or row['scope_id'] not in allowed_scopes(connection):
        raise HTTPException(404, 'Netzwerk nicht gefunden')

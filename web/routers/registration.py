"""Employee registration tied to the request's source address."""
import ipaddress
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from web.access import allowed_scopes
from web.database import get_connection, get_write_connection
from web.routers.devices import save_device_name

router = APIRouter(tags=['Registration'])
templates = Jinja2Templates(directory=Path(__file__).resolve().parents[1] / 'templates')
MAX_FORM_BYTES = 4096


def page(request, *, message='', error=False, name=''):
    return templates.TemplateResponse(
        request=request, name='register.html',
        context={'message': message, 'error': error, 'name': name},
        status_code=400 if error else 200,
    )


@router.get('/registrieren', response_class=HTMLResponse)
async def registration_page(request: Request):
    return page(request)


@router.post('/registrieren', response_class=HTMLResponse)
async def register_employee(request: Request):
    content_type = request.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    if content_type != 'application/x-www-form-urlencoded':
        return page(request, message='Bitte das Formular erneut absenden.', error=True)
    try:
        content_length = int(request.headers.get('content-length', '0'))
    except ValueError:
        content_length = MAX_FORM_BYTES + 1
    if content_length > MAX_FORM_BYTES:
        return page(request, message='Das Formular ist zu groß.', error=True)
    try:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_FORM_BYTES:
                return page(request, message='Das Formular ist zu groß.', error=True)
        form = parse_qs(body.decode('utf-8'), keep_blank_values=True, max_num_fields=5)
    except (UnicodeDecodeError, ValueError):
        return page(request, message='Ungültige Formulardaten.', error=True)
    values = form.get('name', [])
    if len(values) != 1:
        return page(request, message='Bitte genau einen Namen eingeben.', error=True)
    name = values[0].strip()
    if not name:
        return page(request, message='Bitte einen Namen eingeben.', error=True)

    peer = request.client.host if request.client else ''
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return page(request, message='Die Quell-IP-Adresse konnte nicht ermittelt werden.', error=True,
                    name=name)
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        return page(request, message='Die Quell-IP-Adresse konnte nicht zugeordnet werden.', error=True,
                    name=name)
    source_ip = address.compressed

    with get_connection() as db:
        scopes = sorted(allowed_scopes(db))
        if not scopes:
            matches = []
        else:
            placeholders = ','.join('?' for _ in scopes)
            matches = db.execute(f'''SELECT DISTINCT d.id,a.network_id,a.last_seen
                FROM addresses a JOIN devices d ON d.id=a.device_id
                JOIN networks n ON n.id=a.network_id
                WHERE a.ip=? AND n.scope_id IN ({placeholders})''',
                (source_ip, *scopes)).fetchall()
        device_ids = {row['id'] for row in matches}

    if not matches:
        return page(request, message='Für diese IP-Adresse ist kein Gerät bekannt.', error=True,
                    name=name)
    if len(device_ids) != 1:
        return page(request, message='Diese IP-Adresse ist mehreren Geräten zugeordnet. Bitte Support kontaktieren.',
                    error=True, name=name)

    # One device can have addresses in several visible networks. Choose its
    # most recently observed address record; the name itself is stored by ID.
    match = max(matches, key=lambda row: (row['last_seen'], row['network_id']))
    try:
        with get_write_connection() as db:
            result = save_device_name(db, match['id'], match['network_id'], name)
    except HTTPException as error:
        return page(request, message=error.detail, error=True, name=name)
    return page(request, message='Registrierung gespeichert.', name=result['display_name'])

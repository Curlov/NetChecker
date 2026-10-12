
from pathlib import Path
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from web.routers import devices, networks
from web.routers import topology
from web.database import get_connection
from web.access import allowed_scopes


WEB_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="NetChecker API",
    description="Netzwerküberwachung und Geräteverwaltung",
    version="0.3.0"
)


@app.middleware('http')
async def protect_api(request, call_next):
    key = os.environ.get('NETCHECKER_API_KEY', '')
    if request.url.path.startswith('/api/') and key:
        supplied = request.headers.get('x-netchecker-key', '')
        if not secrets.compare_digest(supplied.encode(), key.encode()):
            return JSONResponse({'detail':'API-Anmeldung erforderlich'}, status_code=401)
    return await call_next(request)

app.include_router(devices.router)
app.include_router(networks.router)
app.include_router(topology.router)

app.mount(
    "/static",
    StaticFiles(directory=WEB_DIR / "static"),
    name="static"
)

templates = Jinja2Templates(
    directory=WEB_DIR / "templates"
)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )


@app.get("/api/health")
def health():
    with get_connection() as db:
        scopes = allowed_scopes(db)
        last = db.execute('SELECT r.id,r.scan_type,r.status,r.finished_at FROM scan_runs r '
            'JOIN networks n ON n.id=r.network_id WHERE n.scope_id IN (' + ','.join('?' for _ in scopes) +
            ') ORDER BY r.id DESC LIMIT 1', tuple(scopes)).fetchone() if scopes else None
        return {'status':'ok', 'database':'ready', 'last_scan':dict(last) if last else None}

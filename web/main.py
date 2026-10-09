
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from web.routers import devices, networks


WEB_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="NetChecker API",
    description="Netzwerküberwachung und Geräteverwaltung",
    version="0.3.0"
)

app.include_router(devices.router)
app.include_router(networks.router)

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
    return {"status": "ok"}

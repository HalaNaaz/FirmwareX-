"""FastAPI server setup and application factory for FirmwareX."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from firmwarex import __version__
from firmwarex.api.routes import api_router
from firmwarex.config import WORKSPACE_ROOT, ensure_directories

# Initialize templates
TEMPLATES_DIR = WORKSPACE_ROOT / "firmwarex" / "web" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def create_app() -> FastAPI:
    """Build and configure the FirmwareX FastAPI application."""
    ensure_directories()

    app = FastAPI(
        title="FirmwareX API",
        description="Automated IoT / Embedded Firmware Attack Surface & Vulnerability Analysis Engine",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Restrict CORS to loopback development origins
    allowed_origins = [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Mount API routes
    app.include_router(api_router)

    # Root route serves dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_index(request: Request):
        return templates.TemplateResponse(request=request, name="index.html", context={"version": __version__})

    # Standard health check endpoints
    @app.get("/healthz")
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "version": __version__}

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    from firmwarex.config import SERVER_HOST, SERVER_PORT
    uvicorn.run("firmwarex.api.server:app", host=SERVER_HOST, port=SERVER_PORT, reload=True)

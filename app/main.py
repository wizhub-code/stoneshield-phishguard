"""
Stoneshield PhishGuard — FastAPI Application
=============================================
Run with: uvicorn app.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.openapi.utils import get_openapi
import os

from app.core.config import settings
from app.core.database import init_db
from app.routers import auth, scan, email_scan, api_keys, subscriptions

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Stoneshield PhishGuard API\n\n"
        "## Authentication\n"
        "1. POST /api/v1/auth/signup or /api/v1/auth/login to get a token\n"
        "2. Click Authorize and paste your token\n\n"
        "## Plans\n"
        "- **Free**: 100 scans/month, 1 API key\n"
        "- **Pro**: 5,000 scans/month, email scanning, 5 API keys\n"
        "- **Enterprise**: Unlimited everything\n\n"
        "## Testing Email Scanning Locally\n"
        "POST /api/v1/subscriptions/simulate-upgrade with `{\"plan\": \"pro\"}` first"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Paste your JWT token here (without the word Bearer)",
        }
    }
    for path_data in schema["paths"].values():
        for operation in path_data.values():
            if isinstance(operation, dict) and "security" in operation:
                operation["security"] = [{"BearerAuth": []}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(scan.router, prefix=API_PREFIX)
app.include_router(email_scan.router, prefix=API_PREFIX)
app.include_router(api_keys.router, prefix=API_PREFIX)
app.include_router(subscriptions.router, prefix=API_PREFIX)


@app.on_event("startup")
def on_startup():
    init_db()
    print(f"✅ {settings.APP_NAME} v{settings.APP_VERSION} started")
    print(f"📖 Docs:       http://localhost:8000/docs")
    print(f"🖥️  Dashboard:  http://localhost:8000/dashboard")


@app.get("/dashboard", tags=["System"])
def dashboard():
    for path in ["index.html", "stoneshield-phishguard.html", "phishguard-connected.html"]:
        if os.path.exists(path):
            return FileResponse(path)
    return JSONResponse(status_code=404, content={"error": "Dashboard HTML file not found."})


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "operational", "app": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/", tags=["System"])
def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "docs": "/docs", "dashboard": "/dashboard", "version": settings.APP_VERSION}

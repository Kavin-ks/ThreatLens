from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.api.health import router as health_router
from app.api.v1.router import api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Pre-load scanner registry so the /scanners endpoint is populated immediately
    from scanners.registry import scanner_registry
    scanner_registry.autodiscover()
    yield


app = FastAPI(
    title="ThreatLens API",
    description=(
        "Automated application security assessment platform. "
        "Evidence-driven vulnerability detection with full lifecycle tracking."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(api_v1_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)

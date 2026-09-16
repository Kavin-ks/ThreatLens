from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.config import settings
from app.core.database import get_db

router = APIRouter()


@router.get("/health", tags=["health"])
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint. Returns application status and component connectivity."""
    db_ok = False
    db_error = None
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_error = str(e)

    status = "healthy" if db_ok else "degraded"

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.APP_VERSION,
        "components": {
            "database": {"status": "ok" if db_ok else "error", "error": db_error},
        },
    }


@router.get("/health/ready", tags=["health"])
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe — returns 200 if the service can handle requests."""
    db.execute(text("SELECT 1"))
    return {"ready": True}

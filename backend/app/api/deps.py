from typing import Generator
from sqlalchemy.orm import Session
from fastapi import Depends
from app.core.database import get_db

# Re-export for convenience
DBSession = Depends(get_db)

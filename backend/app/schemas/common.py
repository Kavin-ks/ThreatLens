from typing import TypeVar, Generic, Optional, Any
from pydantic import BaseModel

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    data: T
    error: Optional[str] = None
    meta: Optional[dict] = None


class PaginationMeta(BaseModel):
    total: int
    page: int
    per_page: int
    pages: int


class MessageResponse(BaseModel):
    message: str

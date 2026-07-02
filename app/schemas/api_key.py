from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class APIKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = None  # None = never expires


class APIKeyOut(BaseModel):
    id: str
    name: str
    key_preview: str
    is_active: bool
    total_requests: int
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreated(APIKeyOut):
    """Returned only once at creation — includes the full key."""
    full_key: str


class APIKeyRevoke(BaseModel):
    key_id: str

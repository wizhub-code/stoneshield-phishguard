from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator


class EmailScanRequest(BaseModel):
    raw_content: str
    sender_email: Optional[str] = None
    sender_name: Optional[str] = None
    subject: Optional[str] = None
    reply_to: Optional[str] = None

    @field_validator("raw_content")
    @classmethod
    def content_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Email content cannot be empty")
        if len(v) > 100000:
            raise ValueError("Content too long (max 100,000 characters)")
        return v.strip()


class EmailFlag(BaseModel):
    flag: str
    label: str
    detail: str
    severity: str


class EmailScanResult(BaseModel):
    id: str
    risk_level: str
    risk_score: int
    flagged_categories: List[str]
    detection_results: Dict[str, Any]
    email_specific_flags: List[EmailFlag]
    sender_email: Optional[str]
    sender_name: Optional[str]
    sender_domain: Optional[str]
    reply_to: Optional[str]
    subject: Optional[str]
    platform: Optional[str]
    content_preview: str
    scan_duration_ms: int
    created_at: datetime
    recommendation: str

    class Config:
        from_attributes = True


class EmailScanListItem(BaseModel):
    id: str
    risk_level: str
    risk_score: int
    sender_email: Optional[str]
    subject: Optional[str]
    flagged_categories: List[str]
    content_preview: str
    created_at: datetime

    class Config:
        from_attributes = True

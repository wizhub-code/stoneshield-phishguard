from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator


# --- Request ---

class ScanRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Content cannot be empty")
        if len(v) > 50000:
            raise ValueError("Content too long (max 50,000 characters)")
        return v.strip()


# --- Response ---

class DetectionCategory(BaseModel):
    label: str
    score: int
    match_count: int
    matches: List[str]


class ScanResult(BaseModel):
    id: str
    risk_level: str
    risk_score: int
    flagged_categories: List[str]
    detection_results: Dict[str, DetectionCategory]
    content_preview: str
    scan_duration_ms: int
    created_at: datetime
    recommendation: str
    platform: Optional[str] = None

    class Config:
        from_attributes = True


class ScanListItem(BaseModel):
    id: str
    risk_level: str
    risk_score: int
    flagged_categories: List[str]
    content_preview: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanStats(BaseModel):
    total: int
    safe: int
    suspicious: int
    dangerous: int
    threat_breakdown: Dict[str, int]
    risk_distribution: Dict[str, float]
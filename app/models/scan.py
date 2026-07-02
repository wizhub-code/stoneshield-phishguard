import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    # Input
    content = Column(Text, nullable=False)
    content_preview = Column(String(200))  # First 200 chars for table views

    # Results
    risk_level = Column(String, nullable=False)  # SAFE | SUSPICIOUS | DANGEROUS
    risk_score = Column(Integer, nullable=False)  # 0–100

    # Detailed detection breakdown (stored as JSON)
    detection_results = Column(JSON, nullable=True)
    flagged_categories = Column(JSON, nullable=True)  # list of flagged category names

    # Metadata
    scan_duration_ms = Column(Integer, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User", back_populates="scans")

    def __repr__(self):
        return f"<Scan id={self.id} risk={self.risk_level} score={self.risk_score}>"

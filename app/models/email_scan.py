import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class EmailScan(Base):
    __tablename__ = "email_scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    # Email metadata (parsed from raw email or provided)
    sender_email = Column(String, nullable=True)
    sender_name = Column(String, nullable=True)
    sender_domain = Column(String, nullable=True)
    reply_to = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    raw_content = Column(Text, nullable=False)
    content_preview = Column(String(200), nullable=True)

    # Results
    risk_level = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    detection_results = Column(JSON, nullable=True)
    flagged_categories = Column(JSON, nullable=True)
    email_specific_flags = Column(JSON, nullable=True)  # spoofed sender, mismatched domains etc
    platform = Column(String, nullable=True)

    scan_duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="email_scans")

    def __repr__(self):
        return f"<EmailScan id={self.id} risk={self.risk_level} from={self.sender_email}>"

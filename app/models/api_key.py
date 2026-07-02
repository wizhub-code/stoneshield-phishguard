import uuid
import secrets
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from app.core.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    name = Column(String, nullable=False)               # e.g. "My App", "Production"
    key_prefix = Column(String, nullable=False)         # First 8 chars shown in UI e.g. "sg_live_"
    key_hash = Column(String, nullable=False, unique=True)  # bcrypt hash of full key
    key_preview = Column(String, nullable=False)        # e.g. "sg_live_ab12****"

    is_active = Column(Boolean, default=True)
    total_requests = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey id={self.id} name={self.name} user={self.user_id}>"

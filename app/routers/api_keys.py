"""
API Key Management Router
Users can generate keys to integrate PhishGuard into their own apps.
"""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, hash_password, verify_password
from app.models.api_key import APIKey
from app.models.user import User
from app.models.subscription import Subscription, PLANS
from app.schemas.api_key import APIKeyCreate, APIKeyOut, APIKeyCreated

router = APIRouter(prefix="/api-keys", tags=["API Keys"])

PREFIX = "sg_live_"


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (full_key, key_hash, key_preview)
    Full key shown only once at creation — then only hash stored.
    """
    raw = secrets.token_urlsafe(32)
    full_key = f"{PREFIX}{raw}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_preview = f"{PREFIX}{raw[:6]}{'*' * 20}"
    return full_key, key_hash, key_preview


def check_key_limit(user: User, db: Session):
    """Check if user can create more API keys based on their plan."""
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    plan_name = sub.plan if sub else user.plan
    plan = PLANS.get(plan_name, PLANS["free"])
    limit = plan["api_keys_allowed"]

    if limit == -1:
        return  # Unlimited

    active_keys = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True
    ).count()

    if active_keys >= limit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": f"Your {plan_name} plan allows {limit} API key(s). Upgrade to create more.",
                "current_keys": active_keys,
                "limit": limit,
                "upgrade_url": "/api/v1/subscriptions/plans",
            }
        )


@router.post("/", response_model=APIKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate a new API key.

    The full key is returned ONLY ONCE — store it securely.
    After this, only a preview (sg_live_ab12****) is shown.

    Use the key in requests:
    Header: X-API-Key: sg_live_your_key_here
    """
    check_key_limit(current_user, db)

    full_key, key_hash, key_preview = generate_api_key()

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days)

    api_key = APIKey(
        user_id=current_user.id,
        name=payload.name.strip(),
        key_prefix=PREFIX,
        key_hash=key_hash,
        key_preview=key_preview,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return APIKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_preview=api_key.key_preview,
        full_key=full_key,
        is_active=api_key.is_active,
        total_requests=api_key.total_requests,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
    )


@router.get("/", response_model=List[APIKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all API keys for current user."""
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).order_by(APIKey.created_at.desc()).all()
    return [APIKeyOut.model_validate(k) for k in keys]


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke (delete) an API key. This cannot be undone."""
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(key)
    db.commit()


@router.patch("/{key_id}/deactivate", response_model=APIKeyOut)
def deactivate_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Temporarily deactivate an API key without deleting it."""
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    db.refresh(key)
    return APIKeyOut.model_validate(key)


# ─── API Key Auth Dependency (for external API consumers) ────────────────────

def get_user_by_api_key(api_key: str, db: Session) -> Optional[User]:
    """
    Validate an API key and return the associated user.
    Used by external integrations sending X-API-Key header.
    """
    if not api_key or not api_key.startswith(PREFIX):
        return None

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_obj = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True,
    ).first()

    if not key_obj:
        return None

    # Check expiry
    if key_obj.expires_at and key_obj.expires_at < datetime.utcnow():
        return None

    # Update usage stats
    key_obj.total_requests += 1
    key_obj.last_used_at = datetime.utcnow()
    db.commit()

    return db.query(User).filter(User.id == key_obj.user_id).first()

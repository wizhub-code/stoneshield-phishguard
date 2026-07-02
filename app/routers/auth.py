from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import TokenOut, UserOut, UserSignup

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def signup(payload: UserSignup, db: Session = Depends(get_db)):
    """
    Register a new user account.
    - Validates email uniqueness
    - Hashes password with bcrypt
    - Returns JWT access token immediately (auto-login after signup)
    """
    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=payload.email.lower(),
        name=payload.name.strip(),
        organization=payload.organization,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.post("/token", response_model=TokenOut)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    OAuth2-compatible login endpoint.
    Accepts form fields: username (email), password.
    Returns JWT bearer token.
    """
    user = db.query(User).filter(User.email == form_data.username.lower()).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact support.",
        )

    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.id})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut)
def login_json(payload: dict, db: Session = Depends(get_db)):
    """
    JSON-based login (for frontend SPA convenience alongside OAuth2 form endpoint).
    Body: { "email": "...", "password": "..." }
    """
    email = payload.get("email", "").lower()
    password = payload.get("password", "")

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.id})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return UserOut.model_validate(current_user)


@router.put("/me", response_model=UserOut)
def update_me(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update current user's name or organization."""
    if "name" in payload and payload["name"].strip():
        current_user.name = payload["name"].strip()
    if "organization" in payload:
        current_user.organization = payload["organization"]
    db.commit()
    db.refresh(current_user)
    return UserOut.model_validate(current_user)

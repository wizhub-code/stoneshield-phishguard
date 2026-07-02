from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


# --- Request schemas ---

class UserSignup(BaseModel):
    name: str
    email: EmailStr
    password: str
    organization: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()


class UserLogin(BaseModel):
    email: EmailStr
    password: str


# --- Response schemas ---

class UserOut(BaseModel):
    id: str
    name: str
    email: str
    organization: Optional[str]
    plan: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class TokenData(BaseModel):
    user_id: Optional[str] = None

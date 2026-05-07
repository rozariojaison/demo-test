"""
User schemas — two response shapes depending on mode.

UserVulnerable: includes sensitive internal fields (password_hash, is_admin,
                internal_id, login_count, failed_login_count) — used in vulnerable mode.
UserPublic:     stripped of all sensitive fields — used in secured mode.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str


# Secured mode: fields admin can set
class UserUpdateSecured(BaseModel):
    email: EmailStr | None = None
    username: str | None = None


# Vulnerable mode: accepts ANY dict field (used in router directly)
class UserUpdateVulnerable(BaseModel):
    model_config = ConfigDict(extra="allow")


# ── Response schemas ──────────────────────────────────────────────────────────

class UserPublic(BaseModel):
    """Secured mode response — no sensitive fields."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime


class UserVulnerable(BaseModel):
    """Vulnerable mode response — exposes internal fields intentionally."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    internal_id: uuid.UUID
    username: str
    email: str
    password_hash: str          # Excessive data exposure
    is_admin: bool              # Excessive data exposure
    is_active: bool
    login_count: int            # Audit metadata exposure
    failed_login_count: int     # Audit metadata exposure
    last_login: datetime | None
    created_at: datetime
    updated_at: datetime


class UserAdmin(UserPublic):
    """Admin view — includes is_admin flag but not password_hash."""
    is_admin: bool
    login_count: int
    failed_login_count: int
    last_login: datetime | None
    internal_id: uuid.UUID

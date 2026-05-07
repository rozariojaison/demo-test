"""User CRUD service — branches on MODE for mass-assignment protection."""
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import MODE
from app.models.user import User

# Fields that are NEVER mass-assignable even in vulnerable mode
_IMMUTABLE_FIELDS = {"id", "internal_id", "password_hash", "created_at"}


async def get_user(user_id: int, db: AsyncSession) -> User:
    result = await db.execute(
        select(User).where(User.id == user_id).options(selectinload(User.user_roles))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def list_users(db: AsyncSession, skip: int = 0, limit: int = 50) -> list[User]:
    result = await db.execute(
        select(User).offset(skip).limit(limit).options(selectinload(User.user_roles))
    )
    return list(result.scalars().all())


async def update_user_vulnerable(user_id: int, payload: dict, db: AsyncSession) -> User:
    """Vulnerable: accepts any field including is_admin, role."""
    user = await get_user(user_id, db)
    for field, value in payload.items():
        if field not in _IMMUTABLE_FIELDS and hasattr(user, field):
            setattr(user, field, value)
    await db.flush()
    return user


async def update_user_secured(user_id: int, email: str | None, username: str | None, db: AsyncSession) -> User:
    """Secured: only email and username are writable."""
    user = await get_user(user_id, db)
    if email is not None:
        user.email = email
    if username is not None:
        user.username = username
    await db.flush()
    return user


async def delete_user(user_id: int, db: AsyncSession) -> None:
    user = await get_user(user_id, db)
    await db.delete(user)
    await db.flush()

"""Admin service — stats and audit log retrieval."""
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.audit_log import AuditLog
from app.models.order import Order
from app.models.product import Product
from app.models.user import User


async def get_stats(db: AsyncSession) -> dict:
    user_count = (await db.execute(select(func.count(User.id)))).scalar()
    order_count = (await db.execute(select(func.count(Order.id)))).scalar()
    product_count = (await db.execute(select(func.count(Product.id)))).scalar()
    return {"users": user_count, "orders": order_count, "products": product_count}


async def list_all_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> list[User]:
    result = await db.execute(
        select(User).offset(skip).limit(limit).options(selectinload(User.user_roles))
    )
    return list(result.scalars().all())


async def list_audit_logs(
    db: AsyncSession, skip: int = 0, limit: int = 100, user_id: int | None = None
) -> list[AuditLog]:
    q = select(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
    if user_id:
        q = q.where(AuditLog.user_id == user_id)
    result = await db.execute(q)
    return list(result.scalars().all())

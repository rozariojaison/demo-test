"""Order CRUD service — ownership check gated by MODE."""
from decimal import Decimal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import MODE
from app.models.order import Order
from app.models.order_item import OrderItem
from app.models.product import Product
from app.schemas.order import OrderCreate


async def get_order(order_id: int, requesting_user_id: int, db: AsyncSession) -> Order:
    result = await db.execute(
        select(Order).where(Order.id == order_id).options(selectinload(Order.items))
    )
    order = result.scalar_one_or_none()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # Ownership check only enforced in secured mode
    if MODE == "secured" and order.user_id != requesting_user_id:
        raise HTTPException(status_code=403, detail="Access denied — not your order")

    return order


async def list_user_orders(user_id: int, db: AsyncSession) -> list[Order]:
    result = await db.execute(
        select(Order).where(Order.user_id == user_id).options(selectinload(Order.items))
    )
    return list(result.scalars().all())


async def create_order(payload: OrderCreate, user_id: int, db: AsyncSession) -> Order:
    order = Order(
        user_id=user_id,
        shipping_address=payload.shipping_address,
        total=Decimal("0"),
    )
    db.add(order)
    await db.flush()

    total = Decimal("0")
    for item_data in payload.items:
        product = await db.get(Product, item_data.product_id)
        if product is None:
            raise HTTPException(status_code=404, detail=f"Product {item_data.product_id} not found")
        unit_price = product.price
        item = OrderItem(
            order_id=order.id,
            product_id=item_data.product_id,
            quantity=item_data.quantity,
            unit_price=unit_price,
        )
        db.add(item)
        total += unit_price * item_data.quantity

    order.total = total
    await db.flush()
    return order

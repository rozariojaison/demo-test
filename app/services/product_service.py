"""Product CRUD service."""
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.product import Product
from app.schemas.product import ProductCreate


async def get_product(product_id: int, db: AsyncSession) -> Product:
    product = await db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


async def list_products(db: AsyncSession, skip: int = 0, limit: int = 50) -> list[Product]:
    result = await db.execute(
        select(Product).where(Product.is_active == True).offset(skip).limit(limit)  # noqa: E712
    )
    return list(result.scalars().all())


async def create_product(payload: ProductCreate, owner_id: int, db: AsyncSession) -> Product:
    product = Product(
        name=payload.name,
        sku=payload.sku,
        description=payload.description,
        price=payload.price,
        stock=payload.stock,
        owner_id=owner_id,
    )
    db.add(product)
    await db.flush()
    return product

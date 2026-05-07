"""
Products router — dual-mode.

Vulnerable: sequential integer IDs returned, internal_cost exposed.
Secured:    responses use ProductPublic (no internal_cost, no owner_id).
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.schemas.product import ProductCreate, ProductPublic, ProductVulnerable
from app.services import product_service

vulnerable_router = APIRouter()
secured_router = APIRouter()


# ── Vulnerable ─────────────────────────────────────────────────────────────

@vulnerable_router.get("/", response_model=list[ProductVulnerable])
async def list_products_vulnerable(
    skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await product_service.list_products(db, skip, limit)


@vulnerable_router.get("/{product_id}", response_model=ProductVulnerable)
async def get_product_vulnerable(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Sequential ID — enumerable without ownership check
    return await product_service.get_product(product_id, db)


@vulnerable_router.post("/", response_model=ProductVulnerable)
async def create_product_vulnerable(
    payload: ProductCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await product_service.create_product(payload, current_user.id, db)


# ── Secured ────────────────────────────────────────────────────────────────

@secured_router.get("/", response_model=list[ProductPublic])
async def list_products_secured(
    skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await product_service.list_products(db, skip, limit)


@secured_router.get("/{product_id}", response_model=ProductPublic)
async def get_product_secured(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await product_service.get_product(product_id, db)


@secured_router.post("/", response_model=ProductPublic)
async def create_product_secured(
    payload: ProductCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "manager")),
):
    return await product_service.create_product(payload, current_user.id, db)

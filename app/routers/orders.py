"""
Orders router — BOLA demonstration endpoint.

Vulnerable: GET /api/orders/{id} returns any order regardless of who owns it.
Secured:    ownership enforced — 403 if order.user_id != current_user.id.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.schemas.order import OrderCreate, OrderWithItems
from app.services import order_service

vulnerable_router = APIRouter()
secured_router = APIRouter()


# ── Vulnerable ─────────────────────────────────────────────────────────────

@vulnerable_router.get("/{order_id}", response_model=OrderWithItems)
async def get_order_vulnerable(
    order_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # BOLA: passes current_user.id but order_service in vuln mode ignores it
    return await order_service.get_order(order_id, current_user.id, db)


@vulnerable_router.get("/", response_model=list[OrderWithItems])
async def list_orders_vulnerable(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await order_service.list_user_orders(current_user.id, db)


@vulnerable_router.post("/", response_model=OrderWithItems)
async def create_order_vulnerable(
    payload: OrderCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await order_service.create_order(payload, current_user.id, db)


# ── Secured ────────────────────────────────────────────────────────────────

@secured_router.get("/{order_id}", response_model=OrderWithItems)
async def get_order_secured(
    order_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # order_service enforces ownership in secured mode
    return await order_service.get_order(order_id, current_user.id, db)


@secured_router.get("/", response_model=list[OrderWithItems])
async def list_orders_secured(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await order_service.list_user_orders(current_user.id, db)


@secured_router.post("/", response_model=OrderWithItems)
async def create_order_secured(
    payload: OrderCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await order_service.create_order(payload, current_user.id, db)

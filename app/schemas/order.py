import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict


class OrderItemCreate(BaseModel):
    product_id: int
    quantity: int


class OrderCreate(BaseModel):
    items: list[OrderItemCreate]
    shipping_address: dict | None = None


class OrderItemPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    product_id: int
    quantity: int
    unit_price: Decimal


class OrderPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    status: str
    total: Decimal
    created_at: datetime


class OrderWithItems(OrderPublic):
    items: list[OrderItemPublic] = []
    shipping_address: dict | None = None  # PII — exposed in vulnerable mode

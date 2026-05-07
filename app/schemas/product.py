import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict


class ProductCreate(BaseModel):
    name: str
    sku: str
    description: str | None = None
    price: Decimal
    stock: int = 0


class ProductPublic(BaseModel):
    """Secured mode — no internal_cost."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    sku: str
    description: str | None
    price: Decimal
    stock: int
    is_active: bool
    created_at: datetime


class ProductVulnerable(ProductPublic):
    """Vulnerable mode — exposes internal_cost and owner_id."""
    internal_cost: Decimal | None
    owner_id: int
    uuid: uuid.UUID

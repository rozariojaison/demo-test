"""
User model.
Sequential integer PKs are intentional — they enable BOLA/IDOR enumeration attacks
in vulnerable mode. UUIDs are not used here so the attack surface is realistic.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    # Sequential ID — intentional BOLA target
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Internal UUID — exposed in vulnerable mode (excessive data exposure)
    internal_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), default=uuid.uuid4, nullable=False, unique=True
    )

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Exposed in vulnerable admin endpoint (excessive data exposure)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Mass-assignable in vulnerable mode
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Audit metadata — exposed in vulnerable mode
    login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole", back_populates="user", foreign_keys="UserRole.user_id"
    )
    orders: Mapped[list["Order"]] = relationship("Order", back_populates="user")
    products: Mapped[list["Product"]] = relationship("Product", back_populates="owner")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user")

    @property
    def roles(self):
        return [ur.role for ur in self.user_roles]

    @property
    def role_names(self) -> list[str]:
        return [r.name for r in self.roles]

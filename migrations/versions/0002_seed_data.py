"""Seed data for reproducible attack demonstrations.

15 users with sequential IDs (1-15), 3 roles, 20 products, 30 orders.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from passlib.context import CryptContext

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def upgrade() -> None:
    conn = op.get_bind()

    # ── Roles ─────────────────────────────────────────────────────────────────
    conn.execute(sa.text("""
        INSERT INTO roles (id, name, description) VALUES
        (1, 'user', 'Standard user'),
        (2, 'manager', 'Manager with elevated privileges'),
        (3, 'admin', 'System administrator')
        ON CONFLICT (id) DO NOTHING
    """))

    # ── Permissions ───────────────────────────────────────────────────────────
    conn.execute(sa.text("""
        INSERT INTO permissions (name, resource, action) VALUES
        ('users:read', 'users', 'read'),
        ('users:write', 'users', 'write'),
        ('users:delete', 'users', 'delete'),
        ('orders:read', 'orders', 'read'),
        ('orders:write', 'orders', 'write'),
        ('products:read', 'products', 'read'),
        ('products:write', 'products', 'write'),
        ('admin:access', 'admin', 'admin')
        ON CONFLICT (name) DO NOTHING
    """))

    # ── Users (IDs 1-15 — sequential for BOLA demos) ──────────────────────────
    users = []
    for i in range(1, 16):
        if i <= 10:
            role_id = 1  # user
        elif i <= 13:
            role_id = 2  # manager
        else:
            role_id = 3  # admin

        is_admin = (i >= 14)
        users.append({
            "username": f"user{i}",
            "email": f"user{i}@lab.local",
            "password_hash": pwd_context.hash(f"password{i}"),
            "is_admin": is_admin,
        })

    for idx, u in enumerate(users, start=1):
        conn.execute(sa.text("""
            INSERT INTO users (id, username, email, password_hash, is_admin)
            VALUES (:id, :username, :email, :password_hash, :is_admin)
            ON CONFLICT (id) DO NOTHING
        """), {"id": idx, **u})

    # Assign roles
    for idx in range(1, 11):
        conn.execute(sa.text(
            "INSERT INTO user_roles (user_id, role_id) VALUES (:uid, 1) ON CONFLICT DO NOTHING"
        ), {"uid": idx})
    for idx in range(11, 14):
        conn.execute(sa.text(
            "INSERT INTO user_roles (user_id, role_id) VALUES (:uid, 2) ON CONFLICT DO NOTHING"
        ), {"uid": idx})
    for idx in range(14, 16):
        conn.execute(sa.text(
            "INSERT INTO user_roles (user_id, role_id) VALUES (:uid, 3) ON CONFLICT DO NOTHING"
        ), {"uid": idx})

    # ── Products (IDs 1-20, owned by admin user 14) ───────────────────────────
    products = [
        {"name": f"Product {i}", "sku": f"SKU-{i:03d}",
         "price": float(9.99 + i * 5), "stock": 100, "internal_cost": float(3.00 + i * 2),
         "owner_id": 14}
        for i in range(1, 21)
    ]
    for idx, p in enumerate(products, start=1):
        conn.execute(sa.text("""
            INSERT INTO products (id, name, sku, price, stock, internal_cost, owner_id)
            VALUES (:id, :name, :sku, :price, :stock, :internal_cost, :owner_id)
            ON CONFLICT (id) DO NOTHING
        """), {"id": idx, **p})

    # ── Orders (2 per user 1-10 = 20 orders; + 10 more for demo variety) ──────
    order_id = 1
    for user_id in range(1, 11):
        for _ in range(2):
            conn.execute(sa.text("""
                INSERT INTO orders (id, user_id, status, total, shipping_address)
                VALUES (:id, :uid, 'delivered', :total, :addr)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": order_id,
                "uid": user_id,
                "total": float(49.99 + order_id * 10),
                "addr": f'{{"street": "{order_id} Main St", "city": "Labville", "zip": "L{order_id:04d}B"}}',
            })

            # Two order items per order
            conn.execute(sa.text("""
                INSERT INTO order_items (order_id, product_id, quantity, unit_price)
                VALUES (:oid, :pid, 1, :price)
                ON CONFLICT DO NOTHING
            """), {"oid": order_id, "pid": ((order_id % 20) + 1), "price": 19.99})
            conn.execute(sa.text("""
                INSERT INTO order_items (order_id, product_id, quantity, unit_price)
                VALUES (:oid, :pid, 2, :price)
                ON CONFLICT DO NOTHING
            """), {"oid": order_id, "pid": ((order_id % 20) + 2 if (order_id % 20) + 2 <= 20 else 1), "price": 9.99})

            order_id += 1

    # Extra 10 orders for users 11-15
    for user_id in range(11, 16):
        for _ in range(2):
            conn.execute(sa.text("""
                INSERT INTO orders (id, user_id, status, total, shipping_address)
                VALUES (:id, :uid, 'pending', :total, :addr)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": order_id,
                "uid": user_id,
                "total": float(29.99 + order_id * 5),
                "addr": f'{{"street": "{order_id} Lab Ave", "city": "Testcity", "zip": "T{order_id:04d}C"}}',
            })
            order_id += 1


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("DELETE FROM order_items"))
    conn.execute(sa.text("DELETE FROM orders"))
    conn.execute(sa.text("DELETE FROM products"))
    conn.execute(sa.text("DELETE FROM user_roles"))
    conn.execute(sa.text("DELETE FROM users"))
    conn.execute(sa.text("DELETE FROM permissions"))
    conn.execute(sa.text("DELETE FROM roles"))

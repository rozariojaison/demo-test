"""
Standalone database seeder — inserts demo data for attack demonstrations.
Can be run independently to reset the database to a known state.

Usage: python scripts/seed_db.py
       DATABASE_URL=postgresql+asyncpg://... python scripts/seed_db.py
"""
import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://lab:labpass@localhost:5432/app_db",
)


async def seed(db: AsyncSession) -> None:
    from passlib.context import CryptContext
    pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

    print("[*] Seeding roles...")
    await db.execute(text("""
        INSERT INTO roles (id, name, description) VALUES
        (1, 'user', 'Standard user'),
        (2, 'manager', 'Manager with elevated privileges'),
        (3, 'admin', 'System administrator')
        ON CONFLICT DO NOTHING
    """))

    print("[*] Seeding permissions...")
    perms = [
        ("users:read", "users", "read"),
        ("users:write", "users", "write"),
        ("orders:read", "orders", "read"),
        ("orders:write", "orders", "write"),
        ("products:read", "products", "read"),
        ("products:write", "products", "write"),
        ("admin:access", "admin", "admin"),
    ]
    for name, resource, action in perms:
        await db.execute(text(
            "INSERT INTO permissions (name, resource, action) VALUES (:n, :r, :a) ON CONFLICT DO NOTHING"
        ), {"n": name, "r": resource, "a": action})

    print("[*] Seeding 15 users (sequential IDs 1-15)...")
    for i in range(1, 16):
        is_admin = i >= 14
        await db.execute(text("""
            INSERT INTO users (id, username, email, password_hash, is_admin)
            VALUES (:id, :username, :email, :hash, :is_admin)
            ON CONFLICT (id) DO NOTHING
        """), {
            "id": i,
            "username": f"user{i}",
            "email": f"user{i}@lab.local",
            "hash": pwd.hash(f"password{i}"),
            "is_admin": is_admin,
        })

        role_id = 3 if i >= 14 else (2 if i >= 11 else 1)
        await db.execute(text(
            "INSERT INTO user_roles (user_id, role_id) VALUES (:uid, :rid) ON CONFLICT DO NOTHING"
        ), {"uid": i, "rid": role_id})

    print("[*] Seeding 20 products...")
    for i in range(1, 21):
        await db.execute(text("""
            INSERT INTO products (id, name, sku, price, stock, internal_cost, owner_id)
            VALUES (:id, :name, :sku, :price, :stock, :cost, :owner)
            ON CONFLICT (id) DO NOTHING
        """), {
            "id": i,
            "name": f"Product {i}",
            "sku": f"SKU-{i:03d}",
            "price": float(9.99 + i * 5),
            "stock": 100,
            "cost": float(3.00 + i * 2),
            "owner": 14,
        })

    print("[*] Seeding 30 orders...")
    order_id = 1
    for user_id in range(1, 11):
        for _ in range(2):
            await db.execute(text("""
                INSERT INTO orders (id, user_id, status, total, shipping_address)
                VALUES (:id, :uid, 'delivered', :total, CAST(:addr AS jsonb))
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": order_id,
                "uid": user_id,
                "total": float(49.99 + order_id * 10),
                "addr": f'{{"street": "{order_id} Main St", "city": "Labville", "zip": "L{order_id:04d}B"}}',
            })
            pid1 = (order_id % 20) + 1
            pid2 = (order_id % 19) + 2
            await db.execute(text(
                "INSERT INTO order_items (order_id, product_id, quantity, unit_price) "
                "VALUES (:oid, :pid, 1, 19.99) ON CONFLICT DO NOTHING"
            ), {"oid": order_id, "pid": pid1})
            await db.execute(text(
                "INSERT INTO order_items (order_id, product_id, quantity, unit_price) "
                "VALUES (:oid, :pid, 2, 9.99) ON CONFLICT DO NOTHING"
            ), {"oid": order_id, "pid": pid2 if pid2 <= 20 else 1})
            order_id += 1

    await db.commit()
    print(f"[+] Seeding complete: 15 users, 20 products, {order_id - 1} orders.")


async def main():
    engine = create_async_engine(DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as db:
        await seed(db)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

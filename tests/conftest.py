"""
Shared pytest fixtures for all test modules.
"""
import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

TEST_DATABASE_URL = "postgresql+asyncpg://lab:labpass@localhost:5432/test_db"

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    from app.database import Base
    import app.models  # noqa: F401

    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(bind=db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    from app.database import get_db
    from app.main import app

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Token factories ────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerable_user1_token():
    """HS256 token for user ID 1 — no expiration (vulnerable mode)."""
    return jwt.encode({"sub": "1", "roles": ["user"], "is_admin": False}, "secret", algorithm="HS256")


@pytest.fixture
def vulnerable_admin_token():
    """HS256 token for admin user ID 14."""
    return jwt.encode({"sub": "14", "roles": ["admin"], "is_admin": True}, "secret", algorithm="HS256")


@pytest.fixture
def tampered_admin_token():
    """User 1 token with role manually changed to admin — wrong secret."""
    return jwt.encode(
        {"sub": "1", "roles": ["admin"], "is_admin": True},
        "wrong_secret_to_test_signature",
        algorithm="HS256",
    )


@pytest.fixture
def none_alg_token():
    """Token with alg=none — classic attack."""
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1","roles":["admin"],"is_admin":true}').rstrip(b"=").decode()
    return f"{header}.{payload}."


# ── Convenience aliases used by integration tests ─────────────────────────────

@pytest.fixture
def user_token(vulnerable_user1_token):
    """Alias for vulnerable_user1_token — used in mode-agnostic integration tests."""
    return vulnerable_user1_token


@pytest.fixture
def admin_token(vulnerable_admin_token):
    """Alias for vulnerable_admin_token — used in mode-agnostic integration tests."""
    return vulnerable_admin_token

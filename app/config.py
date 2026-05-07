"""
Central configuration for the API Security Lab.
APP_MODE controls all security behaviour throughout the application.
"""
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Mode ──────────────────────────────────────────────────────────────────
    APP_MODE: Literal["vulnerable", "secured"] = "vulnerable"

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://lab:labpass@localhost:5432/app_db"

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379"

    # ── JWT — Vulnerable mode (intentionally weak) ────────────────────────────
    JWT_SECRET: str = "secret"
    JWT_ALGORITHM: str = "HS256"

    # ── JWT — Secured mode ────────────────────────────────────────────────────
    JWT_PRIVATE_KEY_PATH: str = "secrets/private.pem"
    JWT_PUBLIC_KEY_PATH: str = "secrets/public.pem"
    JWT_ISSUER: str = "api-security-lab"
    JWT_AUDIENCE: str = "api-security-lab-users"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Rate limiting (secured mode / Kong) ───────────────────────────────────
    RATE_LIMIT_LOGIN: int = 5       # requests per minute per IP on /auth/login
    RATE_LIMIT_API: int = 100       # requests per minute per consumer on /api/*
    RATE_LIMIT_ADMIN: int = 10      # requests per minute per consumer on /admin/*

    # ── Application ───────────────────────────────────────────────────────────
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    APP_TITLE: str = "API Security Lab"
    APP_VERSION: str = "1.0.0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# Shorthand imported throughout the codebase
MODE: str = settings.APP_MODE

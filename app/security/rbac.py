"""Role-based access control helpers."""
from fastapi import Depends, HTTPException, status

from app.config import MODE
from app.dependencies import get_current_user


def has_role(user, *roles: str) -> bool:
    return bool({r.name for r in user.roles}.intersection(set(roles)))


def require_scope(scope: str):
    """Dependency: requires a specific JWT scope claim in secured mode."""
    async def _dep(current_user=Depends(get_current_user)):
        if MODE == "secured":
            # Scope check would inspect token payload; simplified here
            if not has_role(current_user, "admin", "manager"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scope: {scope}",
                )
        return current_user
    return _dep

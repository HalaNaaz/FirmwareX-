"""Authentication and Role-Based Authorization for FirmwareX Gated Endpoints (PRD SC-3.3).

Enforces:
- SC-3.3: Access to any unredacted artefact is gated and audited.
- Role-based access control (RBAC):
    * 'analyst', 'admin': Authorized to access unredacted artefacts and reveal secrets.
    * 'viewer', 'guest': Unauthorized (HTTP 403 Forbidden).
    * Missing/Invalid Token: HTTP 401 Unauthorized.
- Strict token validation via 'X-API-Key' or 'Authorization: Bearer <token>' headers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from fastapi import Header, HTTPException, Request


@dataclass(frozen=True)
class UserIdentity:
    """Authenticated user context."""
    user_id: str
    role: str
    is_authenticated: bool

    def has_role(self, *required_roles: str) -> bool:
        return self.role in required_roles


# Known API tokens mapped to (user_id, role)
DEFAULT_TOKEN_REGISTRY: dict[str, tuple[str, str]] = {
    # Default built-in keys for Unit 42 Analyst and Administrator roles
    "fwx-analyst-key-v1": ("analyst-unit42", "analyst"),
    "fwx-admin-key-v1": ("admin-unit42", "admin"),
    "fwx-viewer-key-v1": ("viewer-auditor", "viewer"),
    # Test convenience tokens
    "analyst-token": ("analyst-test", "analyst"),
    "admin-token": ("admin-test", "admin"),
    "viewer-token": ("viewer-test", "viewer"),
}


def get_token_registry() -> dict[str, tuple[str, str]]:
    """Return active token registry combining defaults and environment variables."""
    registry = dict(DEFAULT_TOKEN_REGISTRY)
    env_analyst = os.environ.get("FWX_ANALYST_TOKEN")
    if env_analyst:
        registry[env_analyst] = ("analyst-env", "analyst")
    env_admin = os.environ.get("FWX_ADMIN_TOKEN")
    if env_admin:
        registry[env_admin] = ("admin-env", "admin")
    return registry


def extract_token_from_headers(
    x_api_key: str | None = None,
    authorization: str | None = None,
) -> str | None:
    """Extract raw token string from X-API-Key or Authorization Bearer header."""
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        parts = authorization.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return parts[0].strip()
    return None


def get_current_user_optional(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None, alias="Authorization"),
) -> UserIdentity | None:
    """Extract and validate credentials if present; return None if omitted."""
    raw_token = extract_token_from_headers(x_api_key, authorization)
    if not raw_token:
        return None

    registry = get_token_registry()
    if raw_token in registry:
        user_id, role = registry[raw_token]
        return UserIdentity(user_id=user_id, role=role, is_authenticated=True)

    return None


def require_roles(*allowed_roles: str) -> Callable[[Request, str | None, str | None], UserIdentity]:
    """Dependency factory enforcing authentication and role membership (PRD SC-3.3)."""

    def dependency(
        request: Request,
        x_api_key: str | None = Header(None, alias="X-API-Key"),
        authorization: str | None = Header(None, alias="Authorization"),
    ) -> UserIdentity:
        raw_token = extract_token_from_headers(x_api_key, authorization)
        if not raw_token:
            raise HTTPException(
                status_code=401,
                detail="Authentication required: Provide a valid 'X-API-Key' or 'Authorization: Bearer' token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        registry = get_token_registry()
        if raw_token not in registry:
            raise HTTPException(
                status_code=401,
                detail="Invalid or revoked authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id, role = registry[raw_token]
        if allowed_roles and role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Role '{role}' is not authorized to access unredacted artefacts. Required: {list(allowed_roles)}.",
            )

        return UserIdentity(user_id=user_id, role=role, is_authenticated=True)

    return dependency

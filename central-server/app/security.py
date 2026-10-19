"""Central registration-key signing and admin authentication helpers."""
import hashlib
import hmac
import secrets

from fastapi import Header, HTTPException, status

from app.config import settings


def create_signed_api_key(organization_id: int) -> str:
    payload = f"{organization_id}.{secrets.token_urlsafe(32)}"
    signature = hmac.new(
        settings.CENTRAL_SIGNING_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"cnm_{payload}.{signature}"


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key_signature(api_key: str) -> bool:
    if not api_key.startswith("cnm_"):
        return False
    payload, separator, signature = api_key[4:].rpartition(".")
    if not separator or not payload or len(signature) != 64:
        return False
    expected = hmac.new(
        settings.CENTRAL_SIGNING_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return secrets.compare_digest(signature, expected)


def require_central_admin(
    x_central_admin_token: str | None = Header(default=None),
) -> None:
    if not x_central_admin_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Central admin token required",
        )
    if not secrets.compare_digest(
        x_central_admin_token,
        settings.CENTRAL_ADMIN_TOKEN,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Central admin access required",
        )

import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import Header, HTTPException

from .config import settings


def _sign(payload: str) -> str:
    return hmac.new(settings.signing_key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_token(ttl: int = 8 * 3600) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + ttl}).encode()).decode()
    return f"{payload}.{_sign(payload)}"


def _valid(token: str) -> bool:
    try:
        payload, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _sign(payload)):
            return False
        return json.loads(base64.urlsafe_b64decode(payload))["exp"] > time.time()
    except Exception:
        return False


def require_admin(authorization: str = Header(default=""), x_api_key: str = Header(default="")):
    """Accepts either the dashboard's Bearer token or the X-API-Key (handy for Swagger/scripts)."""
    if x_api_key and settings.api_key_enabled and secrets.compare_digest(x_api_key.encode(), settings.admin_api_key.encode()):
        return
    if authorization.startswith("Bearer ") and _valid(authorization[7:]):
        return
    raise HTTPException(status_code=401, detail="Admin authentication required")

import secrets
import time

from fastapi import APIRouter, HTTPException, Request

from ..config import settings
from ..schemas import LoginIn
from ..security import make_token

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])
_fails: dict[str, list[float]] = {}


@router.post("/login")
def login(body: LoginIn, request: Request):
    if not settings.admin_login_enabled:
        raise HTTPException(503, "Admin sign-in is not set up yet. The site owner must set ADMIN_PASSCODE in .env (run: python -m scripts.make_env).")
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 300]
    if len(recent) >= 5:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    if not secrets.compare_digest(body.passcode.encode(), settings.admin_passcode.encode()):
        _fails[ip] = recent + [now]
        raise HTTPException(401, "Invalid passcode")
    _fails.pop(ip, None)
    return {"token": make_token(), "expires_in": 8 * 3600}

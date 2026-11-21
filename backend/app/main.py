import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import Base, engine
from .ml import predict
from .routers import admin, auth, reports, scan
from .services import feeds, phone_lookup

log = logging.getLogger("confirmam")


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = settings.problems()
    for p in problems:
        log.warning("CONFIG: %s", p)
    if settings.app_env.lower() == "production" and any("DISABLED" in p or "SECRET_KEY" in p or "CORS" in p for p in problems):
        raise RuntimeError("Refusing to start in production with weak settings:\n - " + "\n - ".join(problems))
    Base.metadata.create_all(engine)  # swap for Alembic migrations once the schema settles
    predict.warm_up()  # load the AI models now so the first scan is fast
    if settings.load_feeds_on_start:
        threading.Thread(target=feeds.startup_job, daemon=True).start()  # threat feeds load in the background
    threading.Thread(target=phone_lookup.startup_job, daemon=True).start()  # reported scam numbers
    yield


app = FastAPI(title="ConfirmAm API", version="0.3.0",
              description="ConfirmAm: cybercrime prevention and digital fraud detection. Backend and scam database.",
              lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list, allow_methods=["*"], allow_headers=["*"])  # set CORS_ORIGINS in .env

app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(auth.router)
app.include_router(admin.router)


@app.get("/health", tags=["Meta"])
def health():
    return {"status": "ok", "service": "ConfirmAm"}


@app.get("/api/v1/ai/status", tags=["Meta"], summary="Which AI models are loaded and how they scored in testing")
def ai_status():
    return predict.status()


# Serve the frontend from the same server: open http://127.0.0.1:8000/
_frontend = Path(__file__).resolve().parent.parent / "frontend"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")

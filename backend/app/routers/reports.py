import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import ReportIn, ReportReceipt
from ..services.indicators import parse_indicators

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])
_recent: dict[str, list[float]] = {}
MAX_REPORTS_PER_HOUR = 10  # per IP address, so nobody can flood the admin queue


@router.post("", response_model=ReportReceipt, status_code=201)
def submit_report(body: ReportIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _recent.get(ip, []) if now - t < 3600]
    if len(hits) >= MAX_REPORTS_PER_HOUR:
        raise HTTPException(429, "Too many reports from this connection. Please try again later.")
    _recent[ip] = hits + [now]
    report = models.Report(
        category=body.category.strip(), indicator=body.indicator.strip(), details=body.details.strip(),
        reporter_contact=body.reporter_contact, amount_lost=body.amount_lost,
        indicators=parse_indicators(body.indicator),
    )
    db.add(report)
    db.commit()
    return ReportReceipt(id=report.id, status=report.status)

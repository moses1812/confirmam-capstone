from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..config import settings
from ..schemas import IndicatorIn, IndicatorOut, ReportOut, ReportReview
from ..security import require_admin
from ..services import phone_lookup
from ..services.indicators import add_indicator, parse_indicators, publish_report_indicators, unpublish_report_indicators

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"], dependencies=[Depends(require_admin)])


def to_out(r: models.Report) -> ReportOut:
    return ReportOut(id=r.id, category=r.category, indicator=r.indicator, details=r.details, status=r.status,
                     date=r.created_at.strftime("%Y-%m-%d"), created_at=r.created_at,
                     indicators=r.indicators or [], review_note=r.review_note)


@router.get("/reports", response_model=list[ReportOut])
def list_reports(status: str | None = None, limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    q = db.query(models.Report)
    if status:
        q = q.filter(models.Report.status == status)
    rows = q.order_by(models.Report.created_at.desc(), models.Report.id.desc()).offset(offset).limit(min(limit, 500)).all()
    return [to_out(r) for r in rows]


@router.patch("/reports/{report_id}", response_model=ReportOut)
def review_report(report_id: int, body: ReportReview, db: Session = Depends(get_db)):
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    was_verified = report.status == "Verified"
    report.status, report.review_note = body.status, body.review_note
    report.reviewed_at = datetime.now(timezone.utc)
    if body.status == "Verified":  # verified reports feed the scam database
        publish_report_indicators(db, report)
    elif was_verified:  # changed your mind: remove what this report added
        unpublish_report_indicators(db, report)
    db.commit()
    return to_out(report)


@router.post("/seed-demo", summary="Demo only: loads two sample reports (needs ENABLE_DEMO_SEED=true)")
def seed_demo(db: Session = Depends(get_db)):
    if not settings.enable_demo_seed:
        raise HTTPException(404, "Not found")
    samples = [
        ("Ponzi / Fake Investment Platform", "http://naija-wealth-double.xyz",
         "Promises 100% ROI in 24 hours via WhatsApp broadcast and blocks withdrawals.", "Pending"),
        ("Fake Bank / Fintech Impersonation", "08012345678 / http://opay-bvn-link.top",
         "SMS claiming OPay wallet is blocked and requesting 6-digit OTP.", "Verified"),
    ]
    added = 0
    for cat, ind, det, status in samples:
        if db.query(models.Report).filter_by(indicator=ind).first():
            continue
        r = models.Report(category=cat, indicator=ind, details=det, status=status, indicators=parse_indicators(ind))
        db.add(r)
        db.flush()
        if status == "Verified":
            publish_report_indicators(db, r)
        added += 1
    db.commit()
    return {"added": added}


@router.get("/indicators", response_model=list[IndicatorOut])
def list_indicators(type: str | None = None, q: str | None = None, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(models.Indicator)
    if type:
        query = query.filter(models.Indicator.type == type)
    if q:
        query = query.filter(models.Indicator.value.contains(q.lower()))
    return query.order_by(models.Indicator.created_at.desc()).limit(min(limit, 500)).all()


@router.post("/indicators", response_model=IndicatorOut, status_code=201)
def create_indicator(body: IndicatorIn, db: Session = Depends(get_db)):
    if not add_indicator(db, body.type, body.value, body.category, "admin"):
        raise HTTPException(409, "Indicator already exists")
    db.commit()
    return db.query(models.Indicator).filter_by(type=body.type, value=body.value.strip().lower()).one()


@router.delete("/indicators/{indicator_id}", status_code=204)
def delete_indicator(indicator_id: int, db: Session = Depends(get_db)):
    row = db.get(models.Indicator, indicator_id)
    if not row:
        raise HTTPException(404, "Not found")
    db.delete(row)
    db.commit()


def _count_by(db: Session, col) -> dict:
    return {k: v for k, v in db.query(col, func.count()).group_by(col).all()}


@router.get("/stats", summary="Numbers for the dashboard stat cards")
def stats(db: Session = Depends(get_db)):
    by_status = _count_by(db, models.Report.status)
    return {
        "total": sum(by_status.values()),
        "pending": by_status.get("Pending", 0),
        "verified": by_status.get("Verified", 0),
        "rejected": by_status.get("Rejected", 0),
        "reports_by_category": _count_by(db, models.Report.category),
        "indicators_by_type": _count_by(db, models.Indicator.type),
        "scans_by_level": _count_by(db, models.ScanLog.level),
        "total_scans": db.query(func.count(models.ScanLog.id)).scalar(),
        "total_reported_loss": db.query(func.coalesce(func.sum(models.Report.amount_lost), 0)).scalar(),
    }


@router.get("/phone-list", summary="Status of the NigeriaPhoneBook reported-number list")
def phone_list_status():
    return phone_lookup.status()


@router.post("/phone-list/sync", summary="Download the reported-number list now")
def phone_list_sync():
    try:
        phone_lookup.refresh()
    except Exception as exc:
        raise HTTPException(502, f"Could not update the list: {exc}") from exc
    return phone_lookup.status()

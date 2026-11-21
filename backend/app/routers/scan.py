from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..schemas import CheckResult, DomainCheck, MessageCheck, PhoneCheck, ScanIn, ScanResult, UrlCheck
from ..services import checker

router = APIRouter(prefix="/api/v1", tags=["Scan"])


@router.post("/scan", response_model=ScanResult, summary="Unified scanner (used by the ConfirmAm frontend)")
async def scan(body: ScanIn, db: Session = Depends(get_db)):
    return await checker.scan(db, body.input)


@router.post("/check/url", response_model=CheckResult)
async def check_url(body: UrlCheck, db: Session = Depends(get_db)):
    return await checker.check_url(db, body.url)


@router.post("/check/domain", response_model=CheckResult)
async def check_domain(body: DomainCheck, db: Session = Depends(get_db)):
    return await checker.check_domain(db, body.domain)


@router.post("/check/phone", response_model=CheckResult)
async def check_phone(body: PhoneCheck, db: Session = Depends(get_db)):
    return await checker.check_phone(db, body.phone)


@router.post("/check/message", response_model=CheckResult)
async def check_message(body: MessageCheck, db: Session = Depends(get_db)):
    return await checker.check_message(db, body.text, body.sender)

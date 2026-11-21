from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

IndicatorType = Literal["url", "domain", "phone", "email", "brand"]


class UrlCheck(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class DomainCheck(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class PhoneCheck(BaseModel):
    phone: str = Field(min_length=7, max_length=20)


class MessageCheck(BaseModel):
    text: str = Field(min_length=5, max_length=10000)
    sender: str | None = None


class ScanIn(BaseModel):
    """What the frontend scanner box sends: a link, a message, an email or a phone number."""
    input: str = Field(min_length=3, max_length=10000)


class SignalOut(BaseModel):
    code: str
    weight: int
    detail: str
    source: str


class CheckResult(BaseModel):
    target: str
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    signals: list[SignalOut]
    recommendations: list[str]
    providers_used: list[str]
    ai: dict = {}  # AI model probabilities, e.g. {"message_scam_probability": 0.93}


class ScanResult(CheckResult):
    input_type: Literal["url", "domain", "phone", "email", "message"]
    verdict: str


class IndicatorIn(BaseModel):
    type: IndicatorType
    value: str = Field(min_length=2, max_length=512)
    category: str = Field(default="scam", max_length=100)


class IndicatorOut(IndicatorIn):
    id: int
    source: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ReportIn(BaseModel):
    """Matches the Report page form: category, indicator, details."""
    category: str = Field(min_length=2, max_length=100)
    indicator: str = Field(min_length=2, max_length=512)
    details: str = Field(min_length=3, max_length=5000)
    reporter_contact: str | None = Field(default=None, max_length=128)
    amount_lost: int | None = Field(default=None, ge=0)


class ReportReceipt(BaseModel):
    id: int
    status: str
    message: str = "Report received and queued for admin verification."


class ReportOut(BaseModel):
    id: int
    category: str
    indicator: str
    details: str
    status: str
    date: str
    created_at: datetime
    indicators: list[dict]
    review_note: str | None = None


class ReportReview(BaseModel):
    status: Literal["Verified", "Rejected"]
    review_note: str | None = None


class LoginIn(BaseModel):
    passcode: str = Field(min_length=1, max_length=200)

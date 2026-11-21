from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now():
    return datetime.now(timezone.utc)


class Indicator(Base):
    """A verified scam indicator: url, domain, phone, email or brand."""
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    category: Mapped[str] = mapped_column(String(100), default="scam")
    source: Mapped[str] = mapped_column(String(64), default="admin")  # admin | report:<id>
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Report(Base):
    """Victim-submitted scam report (the Report page form) awaiting admin review."""
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(100))
    indicator: Mapped[str] = mapped_column(String(512))  # exactly what the user typed
    details: Mapped[str] = mapped_column(Text)
    indicators: Mapped[list] = mapped_column(JSON, default=list)  # parsed: [{"type","value"}]
    reporter_contact: Mapped[str | None] = mapped_column(String(128), nullable=True)
    amount_lost: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="Pending", index=True)  # Pending | Verified | Rejected
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanLog(Base):
    """Every scan performed (summary only)."""
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    target: Mapped[str] = mapped_column(String(256))
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FeedDomain(Base):
    """Hostnames from public phishing/malware feeds (Phishing.Database, OpenPhish, URLhaus). Machine-fed, not human-verified."""
    __tablename__ = "feed_domains"

    host: Mapped[str] = mapped_column(String(255), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)

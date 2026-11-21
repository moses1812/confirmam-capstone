"""Parsing and normalising what users type (Report form 'indicator' field, scanner input)."""
import re

from sqlalchemy.orm import Session

from .. import models
from . import redirects, url_analyzer

PHONE_RE = re.compile(r"^(?:\+?234|0)[789][01]\d{8}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
DOMAIN_RE = re.compile(r"^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/\S*)?$", re.I)


def normalise_phone(raw: str) -> str:
    d = "".join(ch for ch in raw if ch.isdigit())
    if d.startswith("234"):
        return "+" + d
    if d.startswith("0") and len(d) == 11:
        return "+234" + d[1:]
    return "+" + d if raw.strip().startswith("+") else d


def canon_url(u: str) -> str:
    return url_analyzer.normalise_url(u).lower().rstrip("/")


def classify_token(tok: str) -> tuple[str, str] | None:
    t = tok.strip().strip(".,;()[]<>\"'")
    if not t:
        return None
    if PHONE_RE.match(re.sub(r"[\s\-()]", "", t)):
        return "phone", normalise_phone(t)
    if EMAIL_RE.match(t):
        return "email", t.lower()
    if re.match(r"^https?://", t, re.I):
        return "url", canon_url(t)
    if DOMAIN_RE.match(t):
        return ("url", canon_url(t)) if "/" in t else ("domain", url_analyzer.registered_domain(t))
    return None


def parse_indicators(raw: str) -> list[dict]:
    """'08012345678 / http://opay-bvn-link.top' -> [{phone}, {url}]; free text -> a brand indicator."""
    out: list[dict] = []
    for part in re.split(r"\s+/\s+|[|,;\n]+", raw):
        part = part.strip()
        if not part:
            continue
        found = [c for c in (classify_token(t) for t in part.split()) if c]
        if found:
            out += [{"type": t, "value": v} for t, v in found]
        elif len(part) <= 80:
            out.append({"type": "brand", "value": part.lower()})
    seen, unique = set(), []
    for i in out:
        key = (i["type"], i["value"])
        if key not in seen:
            seen.add(key)
            unique.append(i)
    return unique[:10]


def add_indicator(db: Session, typ: str, value: str, category: str, source: str) -> bool:
    value = value.strip().lower()
    if db.query(models.Indicator).filter_by(type=typ, value=value).first():
        return False
    db.add(models.Indicator(type=typ, value=value, category=category[:100], source=source))
    return True


def publish_report_indicators(db: Session, report: models.Report) -> None:
    """Verified report -> its indicators join the scam database (URLs also add their domain)."""
    src = f"report:{report.id}"
    for i in report.indicators:
        add_indicator(db, i["type"], i["value"], report.category, src)
        if i["type"] == "url":
            dom = url_analyzer.registered_domain(i["value"])
            if dom and not redirects.is_shortener(dom):  # never blacklist a whole shortener service
                add_indicator(db, "domain", dom, report.category, src)


def unpublish_report_indicators(db: Session, report: models.Report) -> int:
    """A report that was Verified and is later Rejected: take its indicators back out of the scam database."""
    rows = db.query(models.Indicator).filter(models.Indicator.source == f"report:{report.id}").all()
    for row in rows:
        db.delete(row)
    return len(rows)

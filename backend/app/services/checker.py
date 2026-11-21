"""Orchestrates: verified scam DB -> threat feeds -> rules -> AI models -> external intel -> score (strict mode)."""
import re
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .. import models
from ..ml import predict
from ..schemas import CheckResult, ScanResult, SignalOut
from . import feeds, message_analyzer, phone_lookup, redirects, threat_intel, url_analyzer
from .indicators import canon_url, classify_token, normalise_phone
from .scoring import Signal, combine, recommendations

VERDICTS = {
    "critical": "HIGH RISK — LIKELY SCAM",
    "high": "HIGH RISK — LIKELY SCAM",
    "medium": "MEDIUM RISK — PROCEED WITH CAUTION",
    "low": "LOW RISK — NO OBVIOUS THREATS",
}
FEED_NAMES = {"seed": "Phishing.Database snapshot", "phishdb": "Phishing.Database", "openphish": "OpenPhish", "urlhaus": "URLhaus"}


def db_hits(db: Session, pairs: list[tuple[str, str]]) -> list[Signal]:
    sigs = []
    for typ, val in pairs:
        row = db.query(models.Indicator).filter_by(type=typ, value=val.lower()).first()
        if row:
            sigs.append(Signal("verified_scam_indicator", 90, f'CONFIRMED SCAM: flagged in the ConfirmAm database under "{row.category}"', "scam_db"))
    return sigs


def finish(db: Session, kind: str, target: str, signals: list[Signal], used: list[str], ai: dict | None = None) -> CheckResult:
    score, level = combine(signals)
    db.add(models.ScanLog(kind=kind, target=target[:256], score=score, level=level))
    db.commit()
    return CheckResult(
        target=target, risk_score=score, risk_level=level,
        signals=[SignalOut(**s.__dict__) for s in signals],
        recommendations=recommendations(level, kind), providers_used=used, ai=ai or {},
    )


def _has_scheme(raw: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw.strip()))


def _analyse_host(db: Session, url_or_host: str, signals: list[Signal], ai: dict, full_url: bool = True, bare: bool = False) -> None:
    """Rules + threat feeds + AI for one web address. Trusted/official domains skip the strict checks."""
    host = url_analyzer.host_of(url_or_host)
    src = feeds.lookup(db, host)
    if src:
        signals.append(Signal("threat_feed", 85, f"Listed in a public phishing/malware feed ({FEED_NAMES.get(src, src)})", "threat_feed"))
    if url_analyzer.is_trusted(url_or_host) and not src:
        signals.append(Signal("trusted_domain", 0, "Official or well-known domain", "heuristic"))
        return
    signals += url_analyzer.analyse_url(url_or_host if full_url else host, bare=bare)
    p = predict.url_scam_probability(host)
    if p is not None:
        ai["url_scam_probability"] = round(max(p, ai.get("url_scam_probability", 0)), 4)
        w = predict.to_weight(p, 50)
        if w:
            signals.append(Signal("ai_url_model", w, f"AI model: {p:.0%} likelihood this web address belongs to a scam or phishing site", "ai"))


async def check_url(db: Session, url: str) -> CheckResult:
    bare = not _has_scheme(url)
    url = url_analyzer.normalise_url(url)
    ai: dict = {}
    signals = db_hits(db, [("url", canon_url(url)), ("domain", url_analyzer.registered_domain(url))])
    _analyse_host(db, url, signals, ai, bare=bare)
    target = url
    if redirects.is_shortener(urlparse(url).hostname or ""):
        signals.append(Signal("url_shortener", 15, "Shortened link hides the real destination"))
        chain = await redirects.expand(url)
        if len(chain) > 1:
            target = chain[-1]
            signals.append(Signal("redirect_chain", 0, f"Redirects to {target}"))
            signals += db_hits(db, [("url", canon_url(target)), ("domain", url_analyzer.registered_domain(target))])
            _analyse_host(db, target, signals, ai, bare=False)
        else:
            signals.append(Signal("unresolved_shortener", 30, "Could not follow this shortened link, so the real destination is unknown"))
    ext, used = await threat_intel.lookup_url(target)
    return finish(db, "url", url, signals + ext, ["scam_db", "threat_feeds", "heuristics", "ai", *used], ai)


async def check_domain(db: Session, domain: str) -> CheckResult:
    domain = url_analyzer.registered_domain(domain)
    ai: dict = {}
    signals = db_hits(db, [("domain", domain)])
    _analyse_host(db, domain, signals, ai, full_url=False, bare=True)
    ext, used = await threat_intel.lookup_domain(domain)
    return finish(db, "domain", domain, signals + ext, ["scam_db", "threat_feeds", "heuristics", "ai", *used], ai)


async def check_email(db: Session, email: str) -> CheckResult:
    email = email.strip().lower()
    dom = url_analyzer.registered_domain(email.split("@")[-1])
    ai: dict = {}
    signals = db_hits(db, [("email", email), ("domain", dom)])
    _analyse_host(db, dom, signals, ai, full_url=False, bare=True)
    ext, used = await threat_intel.lookup_domain(dom)
    return finish(db, "email", email, signals + ext, ["scam_db", "threat_feeds", "heuristics", "ai", *used], ai)


async def check_phone(db: Session, phone: str) -> CheckResult:
    phone = normalise_phone(phone)
    signals = db_hits(db, [("phone", phone)])
    signals += phone_lookup.signals_for(phone)
    ext, used = await threat_intel.lookup_phone(phone)
    if not signals and not ext:
        signals.append(Signal("unlisted_number", 0, "Not currently listed in the verified scam blacklist or in public reported-number lists, but exercise caution with unknown callers."))
    lists = ["scam_db"] + (["nigeriaphonebook"] if phone_lookup.is_ready() else [])
    return finish(db, "phone", phone, signals + ext, [*lists, *used])


async def check_message(db: Session, text: str, sender: str | None = None) -> CheckResult:
    signals, found = message_analyzer.analyse_message(text)
    signals += message_analyzer.sender_signals(sender, text)
    ai: dict = {}
    p = predict.message_scam_probability(text)
    if p is not None:
        ai["message_scam_probability"] = round(p, 4)
        w = predict.to_weight(p, 65, lo=0.4)
        if w:
            signals.append(Signal("ai_message_model", w, f"AI model: {p:.0%} likelihood this message is a scam", "ai"))
    pairs = [("url", canon_url(u)) for u in found["urls"]] + [("phone", normalise_phone(p_)) for p_ in found["phones"]] \
        + [("email", e.lower()) for e in found["emails"]]
    signals += db_hits(db, pairs)
    for ph in found["phones"]:  # numbers written inside the message
        signals += phone_lookup.signals_for(normalise_phone(ph), "Number in the message:")
    sender_tok = classify_token(sender) if sender else None
    if sender_tok and sender_tok[0] == "phone":  # sender is a phone number
        signals += db_hits(db, [("phone", sender_tok[1])]) + phone_lookup.signals_for(sender_tok[1], "Sender:")
    lowered = text.lower()
    for b in db.query(models.Indicator).filter_by(type="brand").all():  # verified scam brand/business names
        if b.value in lowered:
            signals += db_hits(db, [("brand", b.value)])
    used = ["scam_db", "heuristics", "ai"]
    for u in found["urls"]:  # scan embedded links too, at 3/4 weight
        sub = await check_url(db, u)
        used += [x for x in sub.providers_used if x not in used]
        if "url_scam_probability" in sub.ai:
            ai["url_scam_probability"] = max(ai.get("url_scam_probability", 0), sub.ai["url_scam_probability"])
        top = sorted(sub.signals, key=lambda s: -s.weight)[:4]
        signals += [Signal(f"link:{s.code}", max(1, s.weight * 3 // 4), f"Link {u}: {s.detail}", s.source) for s in top if s.weight > 0]
    return finish(db, "message", (text[:80] + "...") if len(text) > 80 else text, signals, used, ai)


async def scan(db: Session, raw: str) -> ScanResult:
    """Single entry point for the scanner box: auto-detects phone / email / link / message."""
    raw = raw.strip()
    kind, res = "message", None
    c = classify_token(raw)
    if c and " " in raw and c[0] != "phone":
        c = None  # only phone numbers may contain spaces; anything else with spaces is a message
    if c:
        kind = {"url": "url", "domain": "domain", "phone": "phone", "email": "email"}[c[0]]
        fn = {"url": check_url, "domain": check_domain, "phone": check_phone, "email": check_email}[kind]
        res = await fn(db, raw if kind != "phone" else c[1])
    else:
        res = await check_message(db, raw)
    return ScanResult(**res.model_dump(), input_type=kind, verdict=VERDICTS[res.risk_level])

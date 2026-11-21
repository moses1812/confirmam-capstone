"""Third-party threat-intelligence adapters. Every provider is optional:
no API key -> skipped; network error -> skipped (never breaks a check)."""
import asyncio
import base64
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from ..config import settings
from .scoring import Signal
from .url_analyzer import domain_age_signal, registered_domain


async def safe_browsing(c: httpx.AsyncClient, url: str):
    if not settings.google_safe_browsing_key:
        return None
    body = {
        "client": {"clientId": "confirmam", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = await c.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_key}", json=body)
    r.raise_for_status()
    matches = r.json().get("matches", [])
    sig = [Signal("google_safe_browsing", 80, f"Flagged by Google Safe Browsing: {matches[0]['threatType']}", "google_safe_browsing")] if matches else []
    return "google_safe_browsing", sig


async def virustotal(c: httpx.AsyncClient, url: str):
    if not settings.virustotal_key:
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": settings.virustotal_key})
    if r.status_code == 404:
        return "virustotal", []  # never scanned before; you could POST /urls to submit it
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
    if bad >= 3:
        return "virustotal", [Signal("virustotal", 70, f"{bad} security engines flag this URL", "virustotal")]
    if bad >= 1:
        return "virustotal", [Signal("virustotal_low", 25, f"{bad} security engine(s) flag this URL", "virustotal")]
    return "virustotal", []


async def urlhaus(c: httpx.AsyncClient, url: str):
    if not settings.urlhaus_auth_key:
        return None
    r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": settings.urlhaus_auth_key})
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") == "ok":
        return "urlhaus", [Signal("urlhaus", 75, f"Listed in URLhaus (abuse.ch) as {data.get('threat', 'malicious')}", "urlhaus")]
    return "urlhaus", []


async def ipqs_url(c: httpx.AsyncClient, url: str):
    if not settings.ipqs_key:
        return None
    r = await c.get(f"https://www.ipqualityscore.com/api/json/url/{settings.ipqs_key}/{quote(url, safe='')}")
    r.raise_for_status()
    d = r.json()
    sigs = []
    if d.get("phishing"):
        sigs.append(Signal("ipqs_phishing", 70, "IPQualityScore marks this as phishing", "ipqs"))
    elif d.get("suspicious") or d.get("risk_score", 0) >= 75:
        sigs.append(Signal("ipqs_suspicious", 35, f"IPQualityScore risk score {d.get('risk_score')}", "ipqs"))
    return "ipqs", sigs


async def ipqs_phone(c: httpx.AsyncClient, phone: str):
    if not settings.ipqs_key:
        return None
    r = await c.get(f"https://www.ipqualityscore.com/api/json/phone/{settings.ipqs_key}/{quote(phone, safe='')}")
    r.raise_for_status()
    d = r.json()
    sigs = []
    if d.get("fraud_score", 0) >= 75 or d.get("recent_abuse"):
        sigs.append(Signal("ipqs_phone_fraud", 55, f"Phone has high fraud score ({d.get('fraud_score')})", "ipqs"))
    if d.get("VOIP"):
        sigs.append(Signal("voip_number", 10, "Number is VoIP (easy to spoof/disposable)", "ipqs"))
    if d.get("valid") is False:
        sigs.append(Signal("invalid_number", 15, "Number is not a valid phone number", "ipqs"))
    return "ipqs", sigs


async def domain_age(c: httpx.AsyncClient, domain: str):
    """Free RDAP lookup (no key) -> registration age in days."""
    r = await c.get(f"https://rdap.org/domain/{domain}", follow_redirects=True)
    if r.status_code != 200:
        return "rdap", []
    for ev in r.json().get("events", []):
        if ev.get("eventAction") == "registration":
            reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            sig = domain_age_signal((datetime.now(timezone.utc) - reg).days)
            return "rdap", [sig] if sig else []
    return "rdap", []


async def _run(coros) -> tuple[list[Signal], list[str]]:
    signals, used = [], []
    for res in await asyncio.gather(*coros, return_exceptions=True):
        if res is None or isinstance(res, Exception):
            continue  # provider skipped / failed
        name, sigs = res
        used.append(name)
        signals.extend(sigs)
    return signals, used


async def lookup_url(url: str):
    async with httpx.AsyncClient(timeout=settings.http_timeout) as c:
        return await _run([safe_browsing(c, url), virustotal(c, url), urlhaus(c, url), ipqs_url(c, url), domain_age(c, registered_domain(url))])


async def lookup_domain(domain: str):
    async with httpx.AsyncClient(timeout=settings.http_timeout) as c:
        return await _run([domain_age(c, registered_domain(domain))])


async def lookup_phone(phone: str):
    async with httpx.AsyncClient(timeout=settings.http_timeout) as c:
        return await _run([ipqs_phone(c, phone)])

"""Community-reported scam numbers from https://nigeriaphonebook.com/scam-numbers

 * The list is downloaded page by page (about 20 numbers per page), saved to data/feeds/scam_numbers.json
   and kept in memory, so a scan never waits on the network.
 * The server refreshes it in the background every PHONE_LIST_REFRESH_HOURS (0 = never go online).
 * Admins can also refresh it from the dashboard ("Sync now") or with:   python -m app.services.phone_lookup
 * These are COMMUNITY reports that the source site has not always verified, so they are weighted below
   ConfirmAm's own verified scam database.
"""
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

import httpx

from ..config import settings
from .scoring import Signal

log = logging.getLogger("confirmam.phones")

SOURCE_URL = "https://nigeriaphonebook.com/scam-numbers"
CACHE_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "feeds" / "scam_numbers.json"
HEADERS = {"User-Agent": "ConfirmAm/0.3 (+scam-check app; contact the site owner if you want us to stop)"}
MAX_PAGES = 60      # safety limit
PAUSE = 0.7         # seconds between page downloads (be polite to the source site)
CATEGORIES = [
    "Financial Fraud / Money Scam", "Impersonation (Bank, Government, etc.)", "Romance Scam",
    "Advance Fee Fraud (419)", "Phishing / Identity Theft", "Kidnapping / Ransom Call",
    "Spam / Telemarketing", "Threat / Harassment", "Other",
]

_numbers: dict[str, dict] = {}
_fetched_at = 0.0
_loaded = False
_lock = threading.Lock()
_refresh_lock = threading.Lock()
_loop_started = False


def normalize(raw: str) -> str:
    """0803..., +234803..., 234803... and 803... all become 0803... Foreign numbers stay as full digits."""
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("234") and len(digits) == 13:
        return "0" + digits[3:]
    if len(digits) == 10 and digits[0] in "789":
        return "0" + digits
    return digits


class _PageParser(HTMLParser):
    """Collects every link to /number/<digits> with its visible text, plus the page's plain text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href") or ""
            self._href = href if "/number/" in href else None
            self._buf = []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(" ".join(self._buf).split())))
            self._href = None


def parse_page(html: str) -> tuple[dict[str, dict], int]:
    """-> ({number: {"reports": int, "category": str}}, total_pages)"""
    p = _PageParser()
    p.feed(html)
    found: dict[str, dict] = {}
    for href, text in p.links:
        num = normalize(unquote(href.split("?")[0].split("#")[0]).rsplit("/", 1)[-1])
        if len(num) < 10 or len(num) > 15:
            continue
        counts = re.findall(r"(\d+)\s+reports?\b", text, re.I)
        category = next((c for c in CATEGORIES if c.lower() in text.lower()), "Other")
        found[num] = {"reports": max(1, int(counts[-1])) if counts else 1, "category": category}
    m = re.search(r"Page\s+\d+\s+of\s+(\d+)", " ".join(p.text))
    return found, int(m.group(1)) if m else 1


def _save(numbers: dict, stamp: float) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"fetched_at": stamp, "source": SOURCE_URL, "numbers": numbers}), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def load_from_disk() -> int:
    global _numbers, _fetched_at, _loaded
    _loaded = True
    if not CACHE_FILE.exists():
        return 0
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        with _lock:
            _numbers, _fetched_at = data["numbers"], float(data["fetched_at"])
    except Exception:
        log.exception("Could not read %s", CACHE_FILE)
    return len(_numbers)


def refresh() -> int:
    """Download every page of the list. Raises on network errors. Returns how many numbers are now stored."""
    global _numbers, _fetched_at
    if not _loaded:
        load_from_disk()
    with _refresh_lock:  # one download at a time
        found: dict[str, dict] = {}
        page, last = 1, 1
        with httpx.Client(timeout=20, headers=HEADERS, follow_redirects=True) as client:
            while page <= min(last, MAX_PAGES):
                r = client.get(SOURCE_URL, params={"page": page} if page > 1 else None)
                r.raise_for_status()
                nums, last = parse_page(r.text)
                found.update(nums)
                page += 1
                if page <= min(last, MAX_PAGES):
                    time.sleep(PAUSE)
        # If the site changed its layout we would find (almost) nothing: keep the old list instead of wiping it.
        if len(found) < 5 or (_numbers and len(found) < len(_numbers) * 0.5):
            raise RuntimeError(f"Source page looked different than expected (found {len(found)} numbers); kept the previous list.")
        now = time.time()
        with _lock:
            _numbers, _fetched_at = found, now
        _save(found, now)
        log.info("Scam number list refreshed: %s numbers", len(found))
        return len(found)


def lookup(number: str) -> dict | None:
    """{'reports': int, 'category': str} if the number is on the list, else None."""
    if not settings.phone_list_enabled:
        return None
    if not _loaded:
        load_from_disk()
    return _numbers.get(normalize(number))


def is_ready() -> bool:
    if not _loaded:
        load_from_disk()
    return settings.phone_list_enabled and bool(_numbers)


def signals_for(number: str, where: str = "") -> list[Signal]:
    """Risk signals for one phone number. `where` is a prefix such as 'Number in the message'."""
    info = lookup(number)
    if not info:
        return []
    n = info["reports"]
    weight = 45 if n >= 5 else 35 if n >= 3 else 25 if n >= 2 else 20
    prefix = (where + " ") if where else ""
    detail = (f"{prefix}{number} has been reported {n} time{'s' if n != 1 else ''} by users as \"{info['category']}\" "
              f"(NigeriaPhoneBook community reports, not independently verified)")
    return [Signal("reported_number", weight, detail, "nigeriaphonebook")]


def status() -> dict:
    if not _loaded:
        load_from_disk()
    return {
        "enabled": settings.phone_list_enabled,
        "count": len(_numbers),
        "last_sync": datetime.fromtimestamp(_fetched_at, timezone.utc).isoformat() if _fetched_at else None,
        "source": SOURCE_URL,
        "refresh_hours": settings.phone_list_refresh_hours,
    }


def _loop():
    while True:
        try:
            stale = (not _fetched_at) or time.time() - _fetched_at > settings.phone_list_refresh_hours * 3600
            if stale:
                refresh()
        except Exception as exc:  # offline / site down / layout changed: keep serving the saved list
            log.warning("Scam number list refresh skipped: %s", exc)
        time.sleep(3600)  # check again in an hour


def startup_job():
    """Run in a background thread at server start. Loads the saved list at once, then keeps it fresh."""
    global _loop_started
    if not settings.phone_list_enabled or _loop_started:
        return
    _loop_started = True
    log.info("Scam number list loaded from disk: %s numbers", load_from_disk())
    if settings.phone_list_refresh_hours > 0:
        _loop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"Saved {refresh()} numbers to {CACHE_FILE}")

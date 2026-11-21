"""Public threat feeds -> feed_domains table.

 * First run: loads data/feeds/phishing_domains_seed.txt.gz (~390k active phishing hostnames, works offline).
 * Online refresh (needs internet): Phishing.Database, OpenPhish, URLhaus. Run manually with
       python -m app.services.feeds sync
   or let the server refresh automatically every FEED_REFRESH_HOURS.
"""
import gzip
import logging
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..models import FeedDomain
from .url_analyzer import host_of, is_trusted

log = logging.getLogger("confirmam.feeds")
DATA = Path(__file__).resolve().parent.parent.parent / "data"
STAMP = DATA / "feeds" / ".last_sync"
SOURCES = {
    "phishdb": ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", "hosts"),
    "openphish": ("https://openphish.com/feed.txt", "urls"),
    "urlhaus": ("https://urlhaus.abuse.ch/downloads/text_online/", "urls"),
}
_popular: set[str] | None = None


def _popular_hosts() -> set[str]:
    """Top sites: URL feeds must never blacklist a whole popular site just because one page there is bad."""
    global _popular
    if _popular is None:
        p = DATA / "benign_hosts.txt"
        _popular = {l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()} if p.exists() else set()
    return _popular


def _clean_hosts(lines, kind: str) -> set[str]:
    out = set()
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        host = (urlparse(line).hostname or "") if kind == "urls" else line
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host or len(host) > 250:
            continue
        if kind == "urls" and (host in _popular_hosts() or is_trusted(host)):
            continue
        out.add(host)
    return out


def _replace_source(db: Session, source: str, hosts: set[str]) -> int:
    db.execute(delete(FeedDomain).where(FeedDomain.source == source))
    db.commit()
    rows = [{"host": h, "source": source} for h in hosts]
    stmt = FeedDomain.__table__.insert().prefix_with("OR IGNORE") if db.bind.dialect.name == "sqlite" else FeedDomain.__table__.insert()
    for i in range(0, len(rows), 10000):
        db.execute(stmt, rows[i:i + 10000])
        db.commit()  # small transactions so web requests are never blocked for long
    return len(rows)


def load_seed(db: Session) -> int:
    seed = DATA / "feeds" / "phishing_domains_seed.txt.gz"
    if not seed.exists():
        return 0
    with gzip.open(seed, "rt", encoding="utf-8", errors="ignore") as f:
        hosts = _clean_hosts(f, "hosts")
    return _replace_source(db, "seed", hosts)


def sync_online(db: Session) -> dict[str, int | str]:
    results: dict[str, int | str] = {}
    for name, (url, kind) in SOURCES.items():
        try:
            r = httpx.get(url, timeout=60, follow_redirects=True, headers={"User-Agent": "ConfirmAm/0.3"})
            r.raise_for_status()
            hosts = _clean_hosts(r.text.splitlines(), kind)
            if hosts:
                results[name] = _replace_source(db, name, hosts)
        except Exception as exc:  # one broken feed must not stop the others
            results[name] = f"failed: {exc.__class__.__name__}"
    if any(isinstance(v, int) for v in results.values()):
        db.execute(delete(FeedDomain).where(FeedDomain.source == "seed"))  # online data supersedes the offline snapshot
        db.commit()
        STAMP.write_text(str(time.time()))
    return results


def feed_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(FeedDomain)) or 0


def startup_job():
    """Runs in a background thread at server start so the site is available immediately."""
    try:
        with SessionLocal() as db:
            if feed_count(db) == 0:
                log.info("Loading offline phishing seed ...")
                log.info("Seed loaded: %s hosts", load_seed(db))
            stale = (not STAMP.exists()) or (time.time() - float(STAMP.read_text() or 0)) > settings.feed_refresh_hours * 3600
            if settings.feed_refresh_hours > 0 and stale:
                log.info("Refreshing online feeds: %s", sync_online(db))
    except Exception:
        log.exception("Feed startup job failed")


def lookup(db: Session, host: str) -> str | None:
    """Return the feed source if the host, or any parent domain of it, is listed."""
    parts = host.lower().removeprefix("www.").split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    if not candidates:
        return None
    return db.scalar(select(FeedDomain.source).where(FeedDomain.host.in_(candidates)).limit(1))


if __name__ == "__main__":
    from ..db import Base, engine
    Base.metadata.create_all(engine)
    with SessionLocal() as s:
        if len(sys.argv) > 1 and sys.argv[1] == "seed":
            print("seed:", load_seed(s))
        else:
            print(sync_online(s))
        print("feed rows:", feed_count(s))

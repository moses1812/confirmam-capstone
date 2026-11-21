import os

os.environ["DATABASE_URL"] = "sqlite:///./test_phone.db"
os.environ["LOAD_FEEDS_ON_START"] = "false"
os.environ["PHONE_LIST_ENABLED"] = "true"
os.environ["PHONE_LIST_REFRESH_HOURS"] = "0"

from app.config import settings  # noqa: E402
from app.services import phone_lookup as pl  # noqa: E402

# Shaped like the real page: one link per number, with category, brand and report count inside the link text.
PAGE = """
<html><body><h1>Reported Scam Numbers</h1>
<a href="/number/08170870100">Reported number 0817-087-0100 Suspicious Phishing / Identity Theft 9Mobile <span>7 reports</span>·3 Nov 2026 View</a>
<a href="https://nigeriaphonebook.com/number/09129818330">Trending 0912-981-8330 1 Report Threat / Harassment Airtel 1 report·13 Nov 2026 View</a>
<a href="/number/%2B19132379246">+1913-237-9246 Financial Fraud / Money Scam 3 reports</a>
<a href="/about">About us</a>
<p>Page 1 of 9</p></body></html>
"""


def test_parse_page():
    found, pages = pl.parse_page(PAGE)
    assert pages == 9
    assert found["08170870100"] == {"reports": 7, "category": "Phishing / Identity Theft"}
    assert found["09129818330"] == {"reports": 1, "category": "Threat / Harassment"}
    assert found["19132379246"]["reports"] == 3
    assert len(found) == 3


def test_normalize_variants():
    assert pl.normalize("+234 817 087 0100") == pl.normalize("0817-087-0100") == pl.normalize("2348170870100") == "08170870100"


def test_signals(monkeypatch):
    monkeypatch.setattr(pl, "_numbers", {"08170870100": {"reports": 7, "category": "Romance Scam"}, "09129818330": {"reports": 1, "category": "Other"}})
    monkeypatch.setattr(pl, "_loaded", True)
    assert settings.phone_list_enabled
    strong = pl.signals_for("+2348170870100")[0]
    assert strong.weight == 45 and strong.source == "nigeriaphonebook" and "7 times" in strong.detail
    assert pl.signals_for("09129818330")[0].weight == 20
    assert pl.signals_for("08000000000") == []

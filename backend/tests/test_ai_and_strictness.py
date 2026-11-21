import gzip
import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./test_ai.db"
os.environ["ADMIN_API_KEY"] = "test-api-key-for-ci-0123456789"
os.environ["PHONE_LIST_ENABLED"] = "false"
os.environ["LOAD_FEEDS_ON_START"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services import feeds  # noqa: E402

SCAM = [
    "http://secure-gtbank-login.xyz",
    "https://opay-bonus-claim.top/verify",
    "naija-wealth-double.xyz",
    "http://zenithbank-verify.online/account",
    "https://paypa1.com/login",
    "http://bit.ly/3xYzAb",  # shortener: unknown destination is treated as risky
    "http://192.0.2.15/bank/login.php",
    "URGENT: Dear Customer, your GTBank account will be blocked today. Verify your BVN and OTP immediately at http://gtb-security-update.xyz to avoid suspension.",
    "Congratulations! You have won N500,000 in the MTN promo. Pay N5,000 activation fee to 0123456789 to claim your prize.",
    "Invest N50,000 today and get 100% returns in 7 days guaranteed. Join our WhatsApp group now.",
    "I am Barrister Okafor. You are the beneficiary of $4.8m. Pay the clearance fee to receive it.",
    "Your account will be restricted. Reply with your OTP to cancel the transaction.",
    "Hello, we are hiring. Salary N150k. Send N10,000 for training.",
    "https://linkurlpro.com/50kng",
]
LEGIT = [
    "https://www.google.com",
    "https://gtbank.com",
    "https://jumia.com.ng/phones",
    "https://www.bbc.com/news",
    "Hello, we are hiring. Please come with your CV on Monday. No fees at any stage.",
    "https://github.com/anthropics",
    "Hi mum, I have reached school safely. Will call later.",
    "Your verification code is 482913. Do not share it with anyone.",
    "Never share your PIN or OTP with anyone. Stay safe from fraud. - Access Bank",
    "Please send me the report before 5pm. Thanks.",
    "Dear customer, your account has been credited with N30,000 from Ada. Balance N45,200.",
]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_ai_models_loaded(client):
    st = client.get("/api/v1/ai/status").json()
    assert st["url_model"] and st["message_model"], st


@pytest.mark.parametrize("text", SCAM)
def test_scams_are_flagged_strictly(client, text):
    r = client.post("/api/v1/scan", json={"input": text}).json()
    assert r["risk_level"] in ("high", "critical"), (text, r["risk_score"], [s["code"] for s in r["signals"]])


@pytest.mark.parametrize("text", LEGIT)
def test_legit_stays_low(client, text):
    r = client.post("/api/v1/scan", json={"input": text}).json()
    assert r["risk_level"] == "low", (text, r["risk_score"], [(s["code"], s["weight"]) for s in r["signals"]])


def test_threat_feed_seed_hit(client):
    with gzip.open(Path("data/feeds/phishing_domains_seed.txt.gz"), "rt") as f:
        host = next(l.strip() for l in f if l.strip().count(".") == 1 and l.strip().endswith(".com"))
    with SessionLocal() as db:
        assert feeds.load_seed(db) > 100000
    r = client.post("/api/v1/scan", json={"input": f"https://{host}"}).json()
    assert "threat_feed" in {s["code"] for s in r["signals"]} and r["risk_level"] in ("high", "critical"), r


def test_unknown_obscure_domain_is_cautioned_but_not_called_a_scam(client):
    r = client.post("/api/v1/scan", json={"input": "adebayo-and-sons.com"}).json()
    assert r["risk_level"] in ("low", "medium"), r

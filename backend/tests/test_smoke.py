import os

os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["ADMIN_API_KEY"] = "test-api-key-for-ci-0123456789"
os.environ["ADMIN_PASSCODE"] = "test-passcode-for-ci-123"
os.environ["SECRET_KEY"] = "test-secret-key-for-ci-0123456789-abcdef"
os.environ["ENABLE_DEMO_SEED"] = "true"
os.environ["PHONE_LIST_ENABLED"] = "false"
os.environ["LOAD_FEEDS_ON_START"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def test_frontend_flow():
    with TestClient(app) as c:
        # frontend is served
        assert "ConfirmAm" in c.get("/").text

        # sample bank-alert from the scanner page
        sample = ("URGENT: Dear Customer, your GTBank account will be blocked today. Verify your BVN and OTP immediately "
                  "at http://gtb-security-update.xyz to avoid suspension.")
        r = c.post("/api/v1/scan", json={"input": sample}).json()
        assert r["input_type"] == "message" and r["risk_level"] in ("high", "critical"), r
        assert r["verdict"].startswith("HIGH RISK")

        # link / phone auto-detection
        assert c.post("/api/v1/scan", json={"input": "naija-wealth-double.xyz"}).json()["input_type"] == "domain"
        ph = c.post("/api/v1/scan", json={"input": "0801 234 5678"}).json()
        assert ph["input_type"] == "phone" and ph["risk_level"] == "low" and ph["signals"], ph

        # report form
        rep = c.post("/api/v1/reports", json={"category": "Fake Bank / Fintech Impersonation",
                     "indicator": "08012345678 / http://opay-bvn-link.top", "details": "SMS claiming OPay wallet is blocked"})
        assert rep.status_code == 201

        # admin gate
        assert c.get("/api/v1/admin/reports").status_code == 401
        assert c.post("/api/v1/admin/login", json={"passcode": "wrong"}).status_code == 401
        assert c.post("/api/v1/admin/login", json={"passcode": "admin123"}).status_code == 401  # old default no longer works
        token = c.post("/api/v1/admin/login", json={"passcode": "test-passcode-for-ci-123"}).json()["token"]
        H = {"Authorization": f"Bearer {token}"}

        c.post("/api/v1/admin/seed-demo", headers=H)
        reports = c.get("/api/v1/admin/reports", headers=H).json()
        assert {"id", "category", "indicator", "details", "status", "date"} <= set(reports[0])
        stats = c.get("/api/v1/admin/stats", headers=H).json()
        assert stats["pending"] >= 2 and stats["total"] == stats["pending"] + stats["verified"] + stats["rejected"]

        # approve our report -> its phone, url and domain join the scam DB
        rid = rep.json()["id"]
        assert c.patch(f"/api/v1/admin/reports/{rid}", headers=H, json={"status": "Verified"}).json()["status"] == "Verified"
        assert c.get("/api/v1/admin/stats", headers=H).json()["verified"] >= 1
        assert c.post("/api/v1/scan", json={"input": "08012345678"}).json()["risk_score"] >= 90
        assert c.post("/api/v1/scan", json={"input": "http://opay-bvn-link.top"}).json()["risk_score"] >= 90
        assert c.post("/api/v1/scan", json={"input": "Please call 0801 234 5678 now"}).json()["risk_score"] >= 90

        # shortener is never fully "low" even if unresolvable
        s = c.post("/api/v1/scan", json={"input": "https://linkurlpro.com/50kng"}).json()
        assert "url_shortener" in {x["code"] for x in s["signals"]} and s["risk_level"] != "low"

        # legit site stays low
        assert c.post("/api/v1/scan", json={"input": "https://www.python.org"}).json()["risk_level"] == "low"

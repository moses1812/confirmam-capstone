"""Create or repair your .env with strong random secrets.

    python -m scripts.make_env

 * Keeps everything that is already fine in .env (database URL, API keys, ...).
 * Replaces missing, default or weak values (admin123, change-me, ...).
 * Asks you to choose the admin passcode (press Enter to get a random one, shown once).
"""
import getpass
import re
import secrets
import sys
from pathlib import Path

from app.config import DEFAULT_API_KEYS, DEFAULT_SECRETS, WEAK_PASSCODES

ENV = Path(__file__).resolve().parent.parent / ".env"

TEMPLATE = """# ConfirmAm settings. Never share or commit this file.
APP_ENV={APP_ENV}
DATABASE_URL={DATABASE_URL}
ADMIN_PASSCODE={ADMIN_PASSCODE}
SECRET_KEY={SECRET_KEY}
ADMIN_API_KEY={ADMIN_API_KEY}
CORS_ORIGINS={CORS_ORIGINS}
ENABLE_DEMO_SEED={ENABLE_DEMO_SEED}
# Optional threat-intel keys (leave empty to skip a provider)
GOOGLE_SAFE_BROWSING_KEY={GOOGLE_SAFE_BROWSING_KEY}
VIRUSTOTAL_KEY={VIRUSTOTAL_KEY}
URLHAUS_AUTH_KEY={URLHAUS_AUTH_KEY}
IPQS_KEY={IPQS_KEY}
FEED_REFRESH_HOURS={FEED_REFRESH_HOURS}
PHONE_LIST_ENABLED={PHONE_LIST_ENABLED}
PHONE_LIST_REFRESH_HOURS={PHONE_LIST_REFRESH_HOURS}
"""
DEFAULTS = {
    "APP_ENV": "development", "DATABASE_URL": "sqlite:///./confirmam.db", "CORS_ORIGINS": "*", "ENABLE_DEMO_SEED": "false",
    "GOOGLE_SAFE_BROWSING_KEY": "", "VIRUSTOTAL_KEY": "", "URLHAUS_AUTH_KEY": "", "IPQS_KEY": "",
    "FEED_REFRESH_HOURS": "24", "PHONE_LIST_ENABLED": "true", "PHONE_LIST_REFRESH_HOURS": "12",
}


def read_env() -> dict:
    out = {}
    if ENV.exists():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*([A-Z_]+)\s*=\s*(.*?)\s*$", line)
            if m and not line.lstrip().startswith("#"):
                out[m.group(1)] = m.group(2).strip("\"'")
    return out


def main() -> None:
    cur = read_env()
    vals = {**DEFAULTS, **{k: v for k, v in cur.items() if k in DEFAULTS}}

    shown = None
    pw = cur.get("ADMIN_PASSCODE", "")
    if len(pw) < 10 or pw.lower() in WEAK_PASSCODES:
        print("Choose an admin passcode (10+ characters). Press Enter to generate one.")
        pw = getpass.getpass("Admin passcode: ").strip()
        if pw:
            if len(pw) < 10 or pw.lower() in WEAK_PASSCODES:
                sys.exit("That passcode is too short or too common. Run the command again.")
            if getpass.getpass("Repeat it: ").strip() != pw:
                sys.exit("The two entries did not match. Run the command again.")
        else:
            pw = shown = secrets.token_urlsafe(12)
    vals["ADMIN_PASSCODE"] = pw

    key = cur.get("SECRET_KEY", "")
    vals["SECRET_KEY"] = key if len(key) >= 32 and key.lower() not in DEFAULT_SECRETS and key != "put-a-long-random-string-here" else secrets.token_urlsafe(48)
    api = cur.get("ADMIN_API_KEY", "")
    vals["ADMIN_API_KEY"] = api if len(api) >= 20 and api.lower() not in DEFAULT_API_KEYS else secrets.token_urlsafe(32)

    ENV.write_text(TEMPLATE.format(**vals), encoding="utf-8")
    print(f"\nWrote {ENV}")
    if shown:
        print(f"Your admin passcode is:  {shown}\n(Write it down now. It is not shown again, but you can read it in .env.)")
    print("Restart the server (uvicorn app.main:app --reload) for the new values to apply.")


if __name__ == "__main__":
    main()

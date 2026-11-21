# ConfirmAm (Backend + AI + Frontend)

FastAPI backend, scam database and AI models for ConfirmAm. `frontend/` is the team's HTML/JS site wired to the API.

## Run (VS Code terminal)
    python -m venv venv
    venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
    pip install -r requirements.txt   # now includes scikit-learn (AI)
    python -m scripts.make_env     # creates/repairs .env with strong secrets and asks you for the admin passcode
    uvicorn app.main:app --reload

- Website:  http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs
- AI status + test scores: http://127.0.0.1:8000/api/v1/ai/status
- Tests: `pytest -q`
- Admin page: http://127.0.0.1:8000/admin.html (sign in with the passcode you set in `.env`; there is no built-in default)

First start: the ~390,000-domain phishing snapshot loads in the background (about 15 seconds). The site works meanwhile.
If you have internet, the server also refreshes Phishing.Database, OpenPhish and URLhaus every 24 hours (FEED_REFRESH_HOURS in .env, 0 = off).

## Settings (.env)
| Key | Needed? | What it is |
|---|---|---|
| ADMIN_PASSCODE | YES | Admin sign-in. 10+ characters, not a common word. Empty or weak = admin sign-in is disabled |
| SECRET_KEY | YES | 32+ random characters, signs admin sessions |
| ADMIN_API_KEY | no | 20+ random characters for the X-API-Key header (scripts, /docs). Empty = off |
| APP_ENV | no | `development` (default) or `production`. Production refuses to start with weak settings |
| CORS_ORIGINS | production | Your site's address, e.g. `https://confirmam.ng` (`*` = any site) |
| DATABASE_URL | no | SQLite by default; PostgreSQL URL for production |
| ENABLE_DEMO_SEED | no | Keep `false`. `true` allows loading fake sample reports |
| GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_KEY, URLHAUS_AUTH_KEY, IPQS_KEY | optional | Extra threat-intel providers. Leave empty to skip |
| PHONE_LIST_ENABLED, PHONE_LIST_REFRESH_HOURS | no | Reported scam numbers from nigeriaphonebook.com |

`python -m scripts.make_env` fills in the required values for you and keeps anything already set.

## Reported scam numbers (nigeriaphonebook.com)
`app/services/phone_lookup.py` downloads the public list, saves it to `data/feeds/scam_numbers.json` and checks every phone number
(scanned directly, written inside a message, or given as the sender). Matches score 20-45 depending on the number of reports, because
these are community reports and not verified by ConfirmAm. Refresh now: admin dashboard -> "Sync now", or `python -m app.services.phone_lookup`.
Check that you are allowed to use their data (their terms, or ask them for an API/data feed) before launching publicly.

## How a scan works (strict mode)
1. **Verified scam database** (reports your admins approved): a hit scores 90+.
2. **Public threat feeds** (390k+ phishing hosts): a hit scores 85. Reported phone numbers (NigeriaPhoneBook) add 20-45.
3. **Rules**: URL structure, look-alike brands (paypa1, gtb-security-update...), free hosting, risky endings, open redirects,
   message patterns (OTP/BVN requests, advance fees, fake jobs, Ponzi wording...). Official domains in data/ng_trusted_seed.txt skip these.
4. **AI models** (scikit-learn):
   - URL model: character patterns of the hostname + 21 numeric features -> P(phishing)
   - Message model: word and character TF-IDF -> P(scam message)
   Each adds up to 50-65 points depending on confidence.
5. **External intel** (optional keys in .env): Google Safe Browsing, VirusTotal, URLhaus, IPQualityScore, RDAP domain age.
6. Shortened links are followed to the real destination first. A shortener that cannot be followed counts as risky.

Levels: 0-19 low, 20-44 medium, 45-69 high, 70+ critical. (The old limits were 25 / 50 / 75.)

## AI model results (honest numbers)
| Model | Test method | Result |
|---|---|---|
| URL | registered domains never seen in training | ROC-AUC 0.92. At the 0.8 cut-off: 94% precision, 59% recall |
| Message, real SMS data | held-out messages | ROC-AUC 0.99 |
| Message, Nigerian-style data | held-out TEMPLATES (not just held-out rows) | ROC-AUC 0.97, about 83% precision and recall |

Read these carefully:
- The Nigerian training messages are **synthetic** (written by us). The real SMS corpus is mostly UK/US. So the message model
  is a solid starting point, but it has not been proven on real Nigerian scams. The best improvement you can make is real data.
- The URL model only sees the hostname. That is why rules, feeds and the scam database sit beside it.
- Obscure but legitimate domains can score "medium" (caution). That is intentional in strict mode.

## Improve the AI with real data (do this!)
1. Create `data/extra_messages.csv` with columns `text,label` (1 = scam, 0 = legitimate). Put in real scam SMS/WhatsApp
   messages that victims reported (approved reports' details are perfect) and real legitimate messages.
2. Run `python -m train.train_all` (about 2 minutes). The new models go to `models/`. Restart the server.
3. Check `/api/v1/ai/status` or `models/*_metrics.json` to compare scores.
If the server says it could not load a model (for example after a Python or scikit-learn upgrade), run the same command.

## Frontend -> API map
| Page | Action | Endpoint |
|---|---|---|
| index.html | Confirm Am Now | POST /api/v1/scan |
| report.html | Submit report | POST /api/v1/reports |
| admin.html | Unlock | POST /api/v1/admin/login |
| admin.html | List / stats | GET /api/v1/admin/reports?status=, /admin/stats |
| admin.html | Scam number list | GET /api/v1/admin/phone-list, POST /api/v1/admin/phone-list/sync |
| admin.html | Approve / Reject | PATCH /api/v1/admin/reports/{id} |

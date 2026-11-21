import re

from .scoring import Signal

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|(?<![@\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|ng|net|org|xyz|top|click|info|co|site|online|link|shop|icu|live|club|cfd|me|io|app|dev|ly|gl|cc|tk|ml|ga|gq|biz|vip|work|support)\b(?:/[^\s<>\"']*)?",
    re.I,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?234[\s-]?|0)[789][01]\d[\s-]?\d{3}[\s-]?\d{4}(?!\d)")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

# (code, regex, weight, explanation)
RULES = [
    ("urgency", r"\b(urgent|immediately|within \d+ ?(hours?|mins?|minutes?)|last chance|act now|expires? (today|soon)|final warning)\b", 12, "Creates false urgency"),
    ("credential_request", r"\b(otp|one[- ]time (password|code)|bvn|pin|cvv|password|verification code|card number|secret code)\b", 30, "Asks for sensitive credentials (OTP/BVN/PIN/password)"),
    ("guaranteed_returns", r"(guarantee[d]?|risk[- ]free|100% (profit|return)|double your (money|investment)|daily (profit|returns?)|\d{2,3}% (weekly|daily|monthly|roi))", 30, "Promises unrealistic investment returns"),
    ("crypto_forex_bait", r"\b(crypto|bitcoin|usdt|forex|trading signals?|mining|binary options?|ponzi)\b", 8, "Crypto/forex investment pitch"),
    ("advance_fee", r"\b(processing fee|clearance fee|release fee|pay a (small )?fee|claim (your )?(prize|reward|winnings?)|you (have )?won|lottery|inheritance|beneficiary)\b", 28, "Advance-fee or prize/lottery pattern"),
    ("payment_pressure", r"\b(gift ?cards?|send (the )?money|western union|moneygram|itunes card|paste the code)\b", 20, "Pushes unusual payment method"),
    ("account_threat", r"(account (has been |will be )?(suspended|blocked|locked|deactivated|restricted)|unusual activity|security alert|verify your account)", 22, "Threatens account suspension"),
    ("impersonation_authority", r"\b(cbn|efcc|police|customs|nimc|firs|immigration|bank (official|manager)|customer (care|service)|support team|ceo|managing director)\b", 12, "Claims to be an authority, bank or company"),
    ("secrecy", r"(do not tell|keep (this )?(secret|confidential)|don'?t (tell|inform) anyone)", 18, "Asks you to keep it secret"),
    ("romance_hardship", r"\b(stranded|hospital bills?|customs fee|army (officer|general)|widow|my late husband)\b", 18, "Emotional/romance-scam storyline"),
     ("job_scam", r"(work from home|no experience needed|registration fee|training fee)", 14, "Typical job-offer scam wording"),
    ("pay_to_account", r"\b(send|pay|transfer|deposit)\b[^.]{0,80}\b\d{10,11}\b", 25, "Asks you to send money to an account or phone number"),
    ("prize_bait", r"(congratulations.{0,80}\b(won|winner|selected)\b|\b(mega|grand) draw\b|lucky (winner|draw)|been selected)", 15, "Unexpected prize or winner announcement"),
    ("personal_info_request", r"\b(whatsapp|send|reply with|provide)\b[^.]{0,40}\b(full name|home address|address|account details|id card|selfie)\b", 15, "Asks for personal details"),
    ("upfront_fee", r"\b(registration|activation|admin|delivery|customs|training|verification) fee\b|\bcustoms duty\b", 20, "Asks for an upfront fee"),
    ("pay_for_job", r"(hiring|recruit\w*|vacanc\w*|job offer|employment|shortlisted|appointment letter)[\s\S]{0,160}?\b(send|pay|deposit|transfer)\b[^.]{0,60}(\bn|₦|#|ngn|\$)\s?\d", 30, "Asks you to pay money to get a job"),
    ("fee_for_purpose", r"\b(send|pay|transfer|deposit)\b[^.]{0,40}(\bn|₦|#|ngn)\s?\d[\d,.]*k?\b[^.]{0,40}\b(for|as)\s+(a\s+)?(training|registration|processing|activation|clearance|delivery|insurance|verification|admin|application|form|slot|uniform|medical|documentation|release|unlock)", 28, "Asks for an upfront fee before you receive anything"),
    ("brand_mention", r"\b(mtn|airtel|glo|9mobile|gtbank|access bank|zenith|first bank|uba|opay|palmpay|moniepoint|kuda|dhl|nnpc)\b", 8, "Mentions a well-known brand (often impersonated)"),

]


WARNING_CONTEXT = re.compile(r"(never|do not|don'?t|should not|shouldn'?t|will not|won'?t|not to)\s+(share|disclose|give|reveal|send|provide|tell|ask)|never ask|will never (call|ask|request)|beware of|fraud(ulent)? (alert|awareness)|scam awareness|stay safe", re.I)


def analyse_message(text: str) -> tuple[list[Signal], dict]:
    is_warning = bool(WARNING_CONTEXT.search(text))
    signals = [Signal(code, w, detail) for code, pat, w, detail in RULES
               if re.search(pat, text, re.I) and not (is_warning and code in ("credential_request", "account_threat", "urgency"))]
    letters = sum(c.isalpha() for c in text)
    if len(text) > 40 and letters and sum(c.isupper() for c in text) > 0.4 * letters:
        signals.append(Signal("shouting", 6, "Excessive capital letters"))
    extracted = {
        "urls": list(dict.fromkeys(m.group(0).rstrip(".,)") for m in URL_RE.finditer(text)))[:5],
        "phones": list(dict.fromkeys(m.group(0) for m in PHONE_RE.finditer(text)))[:5],
        "emails": list(dict.fromkeys(EMAIL_RE.findall(text)))[:5],
    }
    return signals, extracted


def sender_signals(sender: str | None, text: str) -> list[Signal]:
    """Impersonation: free-mail sender claiming to be an organisation."""
    if sender and re.search(r"@(gmail|yahoo|outlook|hotmail|proton(mail)?)\.", sender, re.I) and re.search(
        r"\b(bank|support|security|customer|official|team)\b", text, re.I
    ):
        return [Signal("free_mail_official", 20, "Claims to be an organisation but uses a free email address")]
    return []

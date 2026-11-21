from dataclasses import dataclass


@dataclass
class Signal:
    code: str
    weight: int
    detail: str
    source: str = "heuristic"


def level_for(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def combine(signals: list[Signal]) -> tuple[int, str]:
    """Sum of weights capped at 100. Tune the weights with labelled examples."""
    score = min(100, sum(s.weight for s in signals))
    return score, level_for(score)


def recommendations(level: str, kind: str) -> list[str]:
    if level in ("high", "critical"):
        recs = [
            "Do NOT click links, reply, or send money, OTPs, PINs, BVN or card details.",
            "If you already paid or shared details, freeze your account (use your bank's USSD code) and call their fraud desk immediately.",
            "Report it to the police/EFCC and your bank, and submit it on the ConfirmAm 'Report a Scam' page.",
            "Change passwords on any account that shares the same login and enable 2FA.",
        ]
        if kind == "phone":
            recs.append("Block the number and report it to your telecom provider.")
        return recs
    if level == "medium":
        return [
            "Treat this as suspicious: verify through the organisation's official website or phone number (not the one in the message).",
            "Do not share personal or payment details until verified.",
            "Report it here if you later confirm it is a scam.",
        ]
    return ["No strong fraud signals found, but no check is perfect. Stay cautious with unexpected requests for money or personal data."]

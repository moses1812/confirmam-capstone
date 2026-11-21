"""Loads the trained models and turns them into scam probabilities. Never raises: if a model is missing or
incompatible the app keeps working with rules + threat feeds only (retrain with: python -m train.train_all)."""
import json
import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("confirmam.ml")
MODELS = Path(__file__).resolve().parent.parent.parent / "models"


@lru_cache(maxsize=None)
def _load(name: str):
    path = MODELS / f"{name}.joblib"
    if not path.exists():
        log.warning("AI model %s not found. Run: python -m train.train_all", name)
        return None
    try:
        import joblib
        return joblib.load(path)
    except Exception as exc:  # version mismatch, corrupt file, scikit-learn missing...
        log.warning("Could not load AI model %s (%s). Run: python -m train.train_all", name, exc)
        return None


def warm_up() -> dict:
    return status()


def status() -> dict:
    out = {}
    for name in ("url_model", "message_model"):
        out[name] = _load(name) is not None
    for f in ("url_metrics.json", "message_metrics.json"):
        p = MODELS / f
        if p.exists():
            out[f.replace(".json", "")] = json.loads(p.read_text())
    return out


def url_scam_probability(host: str) -> float | None:
    model = _load("url_model")
    if model is None or not host:
        return None
    try:
        return float(model.predict_proba([host.lower()])[0][1])
    except Exception as exc:
        log.warning("URL model failed: %s", exc)
        return None


def message_scam_probability(text: str) -> float | None:
    model = _load("message_model")
    if model is None or not text.strip():
        return None
    try:
        return float(model.predict_proba([text])[0][1])
    except Exception as exc:
        log.warning("Message model failed: %s", exc)
        return None


def to_weight(p: float | None, max_weight: int, lo: float = 0.5) -> int:
    """0 below `lo`; rises linearly to max_weight at p=1.0."""
    if p is None or p < lo:
        return 0
    return round(max_weight * (p - lo) / (1 - lo))

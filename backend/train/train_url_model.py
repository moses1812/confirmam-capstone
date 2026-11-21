"""Train the URL/domain classifier (hostname-based). Run from the project root:  python -m train.train_url_model"""
import json
import random
import time
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from app.ml.features import batch_numeric

ROOT = Path(__file__).resolve().parent.parent
DATA, MODELS = ROOT / "data", ROOT / "models"
random.seed(11)
_tld = tldextract.TLDExtract(suffix_list_urls=())


def load(path):
    return [l.strip().lower() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]


def cap_per_domain(hosts, cap):
    """Mass-hosting domains (e.g. thousands of *.000webhostapp.com) must not dominate the model."""
    seen, out = defaultdict(int), []
    random.shuffle(hosts)
    for h in hosts:
        d = _tld(h).registered_domain or h
        if seen[d] < cap:
            seen[d] += 1
            out.append((h, d))
    return out


def build_pipeline():
    return Pipeline([
        ("feats", FeatureUnion([
            ("chars", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3, max_features=150000, sublinear_tf=True, dtype=np.float32)),
            ("num", Pipeline([("f", FunctionTransformer(batch_numeric, validate=False)), ("s", StandardScaler())])),
        ])),
        ("clf", LogisticRegression(C=3.0, max_iter=400, solver="liblinear", class_weight="balanced")),
    ])


SANITY = {  # hostnames the model never saw: should be 0 (legit) / 1 (scam)
    "gtbank.com": 0, "zenithbank.com": 0, "mtnonline.com": 0, "www.nairaland.com": 0, "jumia.com.ng": 0, "bbc.com": 0, "github.com": 0,
    "adebayo-schools.edu.ng": 0, "lagosfoods.com.ng": 0,
    "gtb-security-update.xyz": 1, "opay-bvn-link.top": 1, "naija-wealth-double.xyz": 1, "paypa1-secure-login.com": 1,
    "zenithbank-verify.online": 1, "mtn-promo-winner.click": 1, "cbn-grant-claim.site": 1, "secure-login.gtbank.com.verify-id.icu": 1,
}


def main():
    t0 = time.time()
    phish = cap_per_domain(load(DATA / "phishing_hosts.txt"), 25)
    benign = cap_per_domain(load(DATA / "benign_hosts.txt"), 25)
    hosts = [h for h, _ in phish] + [h for h, _ in benign]
    groups = [d for _, d in phish] + [d for _, d in benign]
    y = np.array([1] * len(phish) + [0] * len(benign))
    print(f"samples: {len(phish)} phishing / {len(benign)} benign")

    # Honest evaluation: whole registered domains are held out (no near-duplicates of training hosts).
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=5).split(hosts, y, groups))
    pipe = build_pipeline().fit([hosts[i] for i in tr], y[tr])
    p = pipe.predict_proba([hosts[i] for i in te])[:, 1]
    metrics = {"model": "url_host_logreg", "train_samples": int(len(tr)), "test_samples": int(len(te)),
               "roc_auc": round(float(roc_auc_score(y[te], p)), 4), "avg_precision": round(float(average_precision_score(y[te], p)), 4)}
    for thr in (0.5, 0.8, 0.9):
        pr, rc, f1, _ = precision_recall_fscore_support(y[te], p >= thr, average="binary", zero_division=0)
        metrics[f"thr_{thr}"] = {"precision": round(float(pr), 4), "recall": round(float(rc), 4), "f1": round(float(f1), 4)}
    print(json.dumps(metrics, indent=2))

    print("\nSanity check on unseen hostnames (P(scam)):")
    names = list(SANITY)
    ps = pipe.predict_proba(names)[:, 1]
    for n, pp in zip(names, ps):
        print(f"  {'OK ' if (pp >= 0.5) == bool(SANITY[n]) else 'MISS'} {pp:5.2f}  {n}")

    final = build_pipeline().fit(hosts, y)  # ship the model trained on everything
    MODELS.mkdir(exist_ok=True)
    joblib.dump(final, MODELS / "url_model.joblib", compress=3)
    (MODELS / "url_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nsaved models/url_model.joblib in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()

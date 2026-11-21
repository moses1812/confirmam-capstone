"""Train the scam-message classifier.  Run from the project root:  python -m train.train_message_model

Data:  data/sms_spam_collection.tsv   real SMS corpus (UCI SMS Spam Collection, Almeida & Hidalgo)
       data/ng_messages.csv           synthetic Nigerian scam / legitimate messages (train/make_ng_messages.py)
       data/extra_messages.csv        OPTIONAL: your own real labelled messages (text,label  with 1=scam, 0=legit)
"""
import csv
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline

from app.ml.features import normalize_message

ROOT = Path(__file__).resolve().parent.parent
DATA, MODELS = ROOT / "data", ROOT / "models"


def load_all():
    texts, labels, groups, source = [], [], [], []
    for i, line in enumerate((DATA / "sms_spam_collection.tsv").read_text(encoding="latin-1").splitlines()):
        if "\t" in line:
            lab, txt = line.split("\t", 1)
            texts.append(txt); labels.append(1 if lab == "spam" else 0); groups.append(f"sms-{i}"); source.append("sms")
    with open(DATA / "ng_messages.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            texts.append(r["text"]); labels.append(int(r["label"])); groups.append(r["group"]); source.append("ng")
    extra = DATA / "extra_messages.csv"
    if extra.exists():
        with open(extra, encoding="utf-8", newline="") as f:
            for i, r in enumerate(csv.DictReader(f)):
                texts.append(r["text"]); labels.append(int(r["label"])); groups.append(f"extra-{i}"); source.append("extra")
    return texts, np.array(labels), groups, np.array(source)


def build_pipeline():
    return Pipeline([
        ("feats", FeatureUnion([
            ("words", TfidfVectorizer(preprocessor=normalize_message, ngram_range=(1, 2), min_df=2, max_features=80000, sublinear_tf=True, dtype=np.float32)),
            ("chars", TfidfVectorizer(preprocessor=normalize_message, analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=80000, sublinear_tf=True, dtype=np.float32)),
        ])),
        ("clf", LogisticRegression(C=6.0, max_iter=500, solver="liblinear", class_weight="balanced")),
    ])


SANITY = [  # brand-new messages, NOT from the templates. Expected: 1 = scam, 0 = legitimate
    ("Dear customer your Opay wallet has been limited. Confirm your details at opay-verify.top within 24hrs", 1),
    ("Congrats! You have been picked to receive N500,000 from the youth fund. Send N5,000 registration to 0123456789", 1),
    ("Good day sir, I have $15M to move out of the country and need a trustworthy partner. You get 30%.", 1),
    ("Hello I am stuck at Dubai airport, my wallet was stolen. Please send $300 I will pay back tomorrow", 1),
    ("Make 50k daily on Telegram. Send 10k to start, guaranteed returns, over 200 people paid", 1),
    ("Your GTB token has expired. Send your new token to our agent on 08031234567 to avoid blockage", 1),
    ("You have won a prize! Call 09061701461 to claim your free holiday now", 1),
    ("Hi, your Bolt ride is arriving in 3 minutes", 0),
    ("Your verification code is 482913. Do not share it with anyone.", 0),
    ("Mum I have reached school safely, will call you after lectures", 0),
    ("Please send me the report before 5pm, the client is waiting", 0),
    ("Never share your PIN or OTP with anyone. Stay safe from fraud. - Access Bank", 0),
    ("Dear customer, your account has been credited with N30,000 from Ada. Balance N45,200.", 0),
    ("Abeg wetin you dey do for weekend? Make we go see that new film", 0),
]


def prf(y, p, thr):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p >= thr, average="binary", zero_division=0)
    return {"precision": round(float(pr), 4), "recall": round(float(rc), 4), "f1": round(float(f1), 4)}


def main():
    t0 = time.time()
    X, y, groups, source = load_all()
    print(f"samples: {len(X)}  (scam {int(y.sum())} / legit {int((1 - y).sum())})  sources: " + ", ".join(f"{s}={int((source == s).sum())}" for s in sorted(set(source))))

    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=3).split(X, y, groups))  # whole templates held out
    pipe = build_pipeline().fit([X[i] for i in tr], y[tr])
    p = pipe.predict_proba([X[i] for i in te])[:, 1]
    yt, st = y[te], source[te]
    metrics = {"model": "message_tfidf_logreg", "train_samples": int(len(tr)), "test_samples": int(len(te)),
               "overall": {"roc_auc": round(float(roc_auc_score(yt, p)), 4), "avg_precision": round(float(average_precision_score(yt, p)), 4), **prf(yt, p, 0.5)}}
    for s in sorted(set(st)):
        m = st == s
        if len(set(yt[m])) == 2:
            metrics[f"{s}_heldout"] = {"n": int(m.sum()), "roc_auc": round(float(roc_auc_score(yt[m], p[m])), 4), **prf(yt[m], p[m], 0.5)}
    print(json.dumps(metrics, indent=2))

    print("\nSanity check on brand-new hand-written messages (P(scam)):")
    ps = pipe.predict_proba([t for t, _ in SANITY])[:, 1]
    ok = 0
    for (t, lab), pp in zip(SANITY, ps):
        good = (pp >= 0.5) == bool(lab)
        ok += good
        print(f"  {'OK  ' if good else 'MISS'} {pp:5.2f}  {t[:95]}")
    metrics["sanity_correct"] = f"{ok}/{len(SANITY)}"

    final = build_pipeline().fit(X, y)
    MODELS.mkdir(exist_ok=True)
    joblib.dump(final, MODELS / "message_model.joblib", compress=3)
    (MODELS / "message_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nsaved models/message_model.joblib in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()

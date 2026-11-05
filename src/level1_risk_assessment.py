"""Level 1: Isolation Forest anomaly detection on encrypted-traffic flow metadata -> risk scores."""
import argparse
import json
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# Metadata-only features (no payload content) available in UNSW-NB15
METADATA_FEATURES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sinpkt", "dinpkt", "sjit", "djit",
    "tcprtt", "synack", "ackdat", "smean", "dmean", "ct_srv_src", "ct_dst_ltm",
]


def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    cols = [c for c in METADATA_FEATURES if c in df.columns]
    X = df[cols].copy()
    for c in X.select_dtypes(include=["object", "string"]).columns:
        X[c] = X[c].astype("category").cat.codes
    return X.fillna(X.median(numeric_only=True))


def to_trust_level(score: float, low: float, high: float) -> str:
    return "LOW" if score < low else ("MEDIUM" if score <= high else "HIGH")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/UNSW_NB15_training-set.csv")
    ap.add_argument("--config", default="config/policies.json")
    ap.add_argument("--sample", type=int, default=15018)
    ap.add_argument("--out", default="outputs")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    cfg = json.load(open(args.config))
    low, high = cfg["thresholds"]["low"], cfg["thresholds"]["high"]

    df = pd.read_csv(args.data)
    if args.sample and len(df) > args.sample:
        df = df.sample(args.sample, random_state=42).reset_index(drop=True)

    X = StandardScaler().fit_transform(preprocess(df))
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)

    raw = -model.score_samples(X)                         # higher = more anomalous
    risk = (raw - raw.min()) / (raw.max() - raw.min())    # scale to [0, 1]

    out = pd.DataFrame({
        "flow_id": np.arange(len(df)),
        "risk_score": risk.round(4),
        "trust_level": [to_trust_level(r, low, high) for r in risk],
    })
    for f in cfg["metadata_fields"]:
        if f in df.columns:
            out[f] = df[f].values
    if "label" in df.columns:
        out["label"] = df["label"].values
        pred = (out["trust_level"] != "LOW").astype(int)
        print(confusion_matrix(out["label"], pred))
        print(classification_report(out["label"], pred, target_names=["normal", "flagged"]))

    out.to_csv(os.path.join(args.out, "level1_risk_scores.csv"), index=False)
    print(out["trust_level"].value_counts(normalize=True).mul(100).round(1))


if __name__ == "__main__":
    main()

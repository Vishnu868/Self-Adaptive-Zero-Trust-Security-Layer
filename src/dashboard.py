"""Level-1 / Level-2 results dashboard (risk distribution, actions, timeline, cumulative actions)."""
import argparse
import os

import matplotlib.pyplot as plt
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enforcement", default="outputs/level2_enforcement.csv")
    ap.add_argument("--out", default="outputs/zero_trust_dashboard.png")
    args = ap.parse_args()
    df = pd.read_csv(args.enforcement)
    colors = {"ALLOW": "#2e7d32", "CHALLENGE": "#f9a825", "BLOCK": "#c62828"}

    fig, ax = plt.subplots(2, 2, figsize=(14, 9))
    ax[0, 0].hist(df["risk_score"], bins=60, color="#1565c0")
    for t in (0.3, 0.6):
        ax[0, 0].axvline(t, ls="--", color="k")
    ax[0, 0].set_title("Risk score distribution")

    counts = df["action"].value_counts().reindex(colors.keys(), fill_value=0)
    ax[0, 1].bar(counts.index, counts.values, color=list(colors.values()))
    for i, v in enumerate(counts.values):
        ax[0, 1].text(i, v, f"{v} ({v / len(df):.1%})", ha="center", va="bottom")
    ax[0, 1].set_title("Enforcement action distribution")

    ax[1, 0].scatter(df["flow_id"], df["risk_score"], s=2, c=df["action"].map(colors))
    for t in (0.3, 0.6):
        ax[1, 0].axhline(t, ls="--", color="k")
    ax[1, 0].set_title("Risk score timeline")

    for a, c in colors.items():
        ax[1, 1].plot((df["action"] == a).cumsum().values, color=c, label=a)
    ax[1, 1].legend(); ax[1, 1].set_title("Cumulative enforcement actions")

    fig.suptitle("Zero-Trust Enforcement Results Dashboard", fontsize=15)
    fig.tight_layout()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    fig.savefig(args.out, dpi=120)
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()

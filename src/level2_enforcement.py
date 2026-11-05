"""Level 2: Zero-Trust policy engine. Converts Level-1 risk scores into ALLOW / CHALLENGE / BLOCK."""
import argparse
import json
import os
from datetime import datetime

import pandas as pd


class ZeroTrustEnforcer:
    def __init__(self, config_path: str):
        cfg = json.load(open(config_path))
        self.policies = cfg["policies"]
        self.meta_fields = cfg["metadata_fields"]

    def decide(self, row: pd.Series) -> dict:
        level = row["trust_level"]
        policy = self.policies[level]
        reasons = {
            "LOW": "Behaviour consistent with normal traffic baseline",
            "MEDIUM": "Suspicious behaviour pattern based on risk score",
            "HIGH": "Strong deviation from baseline - likely attack behaviour",
        }
        return {
            "flow_id": int(row["flow_id"]),
            "risk_score": float(row["risk_score"]),
            "trust_level": level,
            "action": policy["action"],
            "description": policy["description"],
            "response_code": policy["response_code"],
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "reason": reasons[level],
            "metadata": {f: row[f].item() if hasattr(row[f], "item") else row[f]
                         for f in self.meta_fields if f in row},
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scores", default="outputs/level1_risk_scores.csv")
    ap.add_argument("--config", default="config/policies.json")
    ap.add_argument("--out", default="outputs")
    args = ap.parse_args()

    enforcer = ZeroTrustEnforcer(args.config)
    df = pd.read_csv(args.scores)
    decisions = [enforcer.decide(r) for _, r in df.iterrows()]

    with open(os.path.join(args.out, "level2_enforcement_log.json"), "w") as f:
        json.dump(decisions, f, indent=2)
    pd.DataFrame(decisions).drop(columns=["metadata"]).to_csv(
        os.path.join(args.out, "level2_enforcement.csv"), index=False)

    summary = pd.Series([d["action"] for d in decisions]).value_counts()
    print(pd.DataFrame({"flows": summary, "share_%": (summary / len(decisions) * 100).round(1)}))


if __name__ == "__main__":
    main()

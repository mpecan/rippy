#!/usr/bin/env python3
"""Mean answer per label from an eval.py JSONL: does a backend separate the labels at all?

    python3 scripts/jev-eval/separation.py target/jev-eval-results/rippy-kev-4b.jsonl
"""
import json
import statistics
import sys
from collections import defaultdict

KEYS = ["read_only", "exfiltration", "writes_outside_project", "reads_secrets",
        "irreversible", "runs_project_code", "self_referential"]

for path in sys.argv[1:]:
    by_label, outcomes = defaultdict(lambda: defaultdict(list)), defaultdict(lambda: defaultdict(int))
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            a = ((r["report"].get("jev") or {}).get("answers")) or {}
            outcomes[r["label"]][r["outcome"]] += 1
            if not a:
                continue
            by_label[r["label"]]["read_only"].append(a["effect"]["probabilities"]["read_only"])
            for k in KEYS[1:]:
                by_label[r["label"]][k].append(a[k]["noul"])
    print(f"\n{path.rsplit('/', 1)[-1]}")
    print("label   " + "  ".join(k[:10].rjust(10) for k in KEYS) + "  outcomes")
    for label in ("safe", "unsafe", "exfil"):
        means = [statistics.mean(by_label[label][k]) if by_label[label][k] else float("nan") for k in KEYS]
        print(f"{label:<7} " + "  ".join(f"{m:10.2f}" for m in means) + "  " + dict.__repr__(dict(outcomes[label])))

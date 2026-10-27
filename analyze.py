import json
import collections
from detector import scan

pairs = [json.loads(l) for l in open("pairs.jsonl")]

keys = ["sql", "eval", "pickle", "command", "yaml", "random",
        "hardcoded", "deserial", "xss", "path", "assert"]
count = collections.Counter()
for p in pairs:
    v = p["vulnerability"].lower()
    matched = [k for k in keys if k in v]
    for k in matched:
        count[k] += 1
    if not matched:
        count["other"] += 1
print("Vulnerability types in dataset:")
for k, n in count.most_common():
    print(f"  {k}: {n}")

false_alarms = [p for p in pairs if scan(p["fixed_code"])]
for p in false_alarms[:3]:
    print("\n===== FIXED CODE THAT WAS FLAGGED =====")
    print(p["fixed_code"])
    print("Detector said:", scan(p["fixed_code"]))

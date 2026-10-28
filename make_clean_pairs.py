import json
from behavior_check import behavior_check

pairs = [json.loads(l) for l in open("verified_pairs.jsonl")]
clean = [p for p in pairs if not behavior_check(p["vulnerable_code"], p["fixed_code"])]
with open("clean_pairs.jsonl", "w") as f:
    for p in clean:
        f.write(json.dumps(p) + "\n")
print(f"Saved {len(clean)} of {len(pairs)} pairs to clean_pairs.jsonl")

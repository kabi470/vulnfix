import collections
import json

from detector import scan

pairs = [json.loads(l) for l in open("pairs.jsonl")]
verified = []
still_vulnerable = collections.Counter()
undetected = 0

for p in pairs:
    before = scan(p["vulnerable_code"])
    after = scan(p["fixed_code"])
    if before and not after:
        p["rule"] = before[0][1].split(":")[0]
        verified.append(p)
    elif before and after:
        still_vulnerable[before[0][1].split(":")[0]] += 1
    else:
        undetected += 1

with open("verified_pairs.jsonl", "w") as f:
    for p in verified:
        f.write(json.dumps(p) + "\n")

print(f"Total pairs: {len(pairs)}")
print(f"Verified fixes (flagged before, clean after): {len(verified)}")
print(f"'Fix' still flagged: {sum(still_vulnerable.values())}", dict(still_vulnerable))
print(f"Not detected at all: {undetected}")
print("Verified by rule:", dict(collections.Counter(p["rule"] for p in verified)))

for p in verified[:1]:
    print("\n--- VERIFIED EXAMPLE:", p["rule"])
    print("VULNERABLE:\n" + p["vulnerable_code"])
    print("FIXED:\n" + p["fixed_code"])

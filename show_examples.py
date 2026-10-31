import json

pairs = [json.loads(l) for l in open("real_pairs.jsonl")]
for cwe in ("CWE-601", "CWE-79", "CWE-22"):
    group = [p for p in pairs if p["vulnerability"] == cwe]
    group.sort(key=lambda p: len(p["vulnerable_code"]) + len(p["fixed_code"]))
    for p in group[:2]:
        print("=" * 60)
        print(cwe, p["cve_id"], p["function"])
        print("--- VULNERABLE:\n" + p["vulnerable_code"])
        print("--- FIXED:\n" + p["fixed_code"])

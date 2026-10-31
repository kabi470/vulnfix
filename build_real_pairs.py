import ast
import collections
import json
import sqlite3
import textwrap

from behavior_check import behavior_check
from detector import scan

DB = "data/CVEfixes_v1.0.0/Data/CVEfixes.db"
MIN_LEN, MAX_LEN = 60, 2500


def parses(code):
    try:
        ast.parse(code)
        return True
    except Exception:
        return False


def functions(src):
    """{qualified_name: dedented source} for each function and method."""
    tree = ast.parse(src)
    lines = src.splitlines()
    out = {}

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seg = "\n".join(lines[child.lineno - 1:child.end_lineno])
                out[prefix + child.name] = textwrap.dedent(seg)
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")

    visit(tree, "")
    return out


def safe_scan(code):
    try:
        return scan(code)
    except Exception:
        return None


con = sqlite3.connect(DB)
cve_of = {}
for h, c in con.execute("SELECT hash, cve_id FROM fixes"):
    cve_of.setdefault(h, c)
cwe_of = {}
for c, w in con.execute("SELECT cve_id, cwe_id FROM cwe_classification"):
    cwe_of.setdefault(c, w)

rows = con.execute(
    "SELECT hash, filename, code_before, code_after FROM file_change "
    "WHERE programming_language='Python' AND code_before IS NOT NULL AND code_after IS NOT NULL"
)

stats = collections.Counter()
seen, pairs = set(), []
for h, fname, before, after in rows:
    stats["python file changes"] += 1
    try:
        fb, fa = functions(before), functions(after)
    except Exception:
        stats["skipped (not valid Python 3)"] += 1
        continue
    for name, old in fb.items():
        new = fa.get(name)
        if not new or new == old:
            continue
        if not (MIN_LEN <= len(old) <= MAX_LEN and len(new) <= MAX_LEN):
            continue
        if not (parses(old) and parses(new)) or (old, new) in seen:
            continue
        seen.add((old, new))
        cve = cve_of.get(h, "")
        pairs.append({
            "vulnerability": cwe_of.get(cve, ""),
            "vulnerable_code": old,
            "fixed_code": new,
            "cve_id": cve,
            "function": name,
            "file": fname,
        })

verified, rules = [], collections.Counter()
flagged = 0
for p in pairs:
    b = safe_scan(p["vulnerable_code"])
    a = safe_scan(p["fixed_code"])
    if b:
        flagged += 1
    if b and a == []:
        try:
            problems = behavior_check(p["vulnerable_code"], p["fixed_code"])
        except Exception:
            problems = ["check crashed"]
        if not problems:
            p["rule"] = b[0][1].split(":")[0]
            rules[p["rule"]] += 1
            verified.append(p)

with open("real_pairs.jsonl", "w") as f:
    for p in pairs:
        f.write(json.dumps(p) + "\n")
with open("real_verified_pairs.jsonl", "w") as f:
    for p in verified:
        f.write(json.dumps(p) + "\n")

print("Python file changes read:", stats["python file changes"])
print("Skipped (not valid Python 3):", stats["skipped (not valid Python 3)"])
print("Changed functions (all pairs):", len(pairs))
print("Detector flags the vulnerable version:", flagged)
print("Verified (flagged before, clean after, passes behavior check):", len(verified))
print("By rule:", dict(rules))
if verified:
    p = verified[0]
    print("\n--- Example:", p["cve_id"], p["vulnerability"], p["rule"])
    print("VULNERABLE:\n" + p["vulnerable_code"])
    print("FIXED:\n" + p["fixed_code"])

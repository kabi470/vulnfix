import ast
import json
import re
import sys

from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATASET = "CyberNative/Code_Vulnerability_Security_DPO"
OUT_FILE = "pairs.jsonl"


def extract_code(text):
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def parses(code):
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def build_pairs():
    ds = load_dataset(DATASET, split="train")
    print("Columns:", ds.column_names)
    pairs = []
    for row in ds:
        if str(row.get("lang", "")).lower() != "python":
            continue
        vulnerable = extract_code(row["rejected"])
        fixed = extract_code(row["chosen"])
        if parses(vulnerable) and parses(fixed) and vulnerable != fixed:
            pairs.append({
                "vulnerability": row.get("vulnerability", ""),
                "vulnerable_code": vulnerable,
                "fixed_code": fixed,
            })
    with open(OUT_FILE, "w") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"Saved {len(pairs)} clean pairs to {OUT_FILE}")
    return pairs


def find_similar(query_code, pairs, k=3):
    corpus = [p["vulnerable_code"] for p in pairs]
    vec = TfidfVectorizer(token_pattern=r"[A-Za-z_]+")
    matrix = vec.fit_transform(corpus + [query_code])
    scores = cosine_similarity(matrix[-1], matrix[:-1]).ravel()
    best = scores.argsort()[::-1][:k]
    return [pairs[i] for i in best]


if __name__ == "__main__":
    pairs = build_pairs()
    if len(sys.argv) > 1:
        for ex in find_similar(sys.argv[1], pairs):
            print("\n--- Similar:", ex["vulnerability"])
            print("VULNERABLE:\n", ex["vulnerable_code"])
            print("FIXED:\n", ex["fixed_code"])

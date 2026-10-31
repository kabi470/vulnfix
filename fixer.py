"""scan -> retrieve -> fix -> verify.

The model is passed in as a plain function ask(messages) -> text, so the same
code works with any open model (Kaggle GPU, Ollama, ...). Nothing here edits
your files: results are suggestions to review.
"""
import ast
import difflib
import json
import re
import textwrap

from behavior_check import behavior_check
from detector import scan
from name_check import add_missing_imports, new_undefined_names

SYSTEM = "You are a secure coding assistant. Make minimal edits."


def load_pool(path):
    """Verified (vulnerable -> fixed) examples used for retrieval."""
    return [json.loads(line) for line in open(path)]


def extract(text):
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def similar(code, pool, k=2):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    corpus = [p["vulnerable_code"] for p in pool]
    vec = TfidfVectorizer(token_pattern=r"[A-Za-z_]+")
    m = vec.fit_transform(corpus + [code])
    scores = cosine_similarity(m[-1], m[:-1]).ravel()
    return [pool[i] for i in scores.argsort()[::-1][:k]]


def problems_in(original, fixed):
    try:
        ast.parse(fixed)
    except SyntaxError:
        return ["fixed code is not valid Python"]
    found = [f"line {l}: {m}" for l, m in scan(fixed)]
    return found + behavior_check(original, fixed) + new_undefined_names(original, fixed)


def build_messages(code, findings, examples):
    found = "\n".join(f"line {l}: {m}" for l, m in findings)
    prompt = ""
    if examples:
        prompt += "Examples of similar fixes:\n\n"
        for ex in examples:
            prompt += f"VULNERABLE:\n{ex['vulnerable_code']}\nFIXED:\n{ex['fixed_code']}\n\n"
    prompt += (f"The scanner found this in the Python function below:\n{found}\n\nCode:\n{code}\n\n"
               "Fix only that problem with the smallest possible change. "
               "Return ONLY the fixed function in one code block: no classes, no helper functions, "
               "same name and arguments. Use only names the function already uses, Python built-ins, "
               "or standard-library modules. Use only APIs that exist in Python 3.14.")
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]


def fix_code(code, ask, pool=None, tries=3):
    """Fix one snippet. Returns a dict with status, fixed code and what is left."""
    findings = scan(code)
    if not findings:
        return {"status": "no findings", "fixed": code, "attempts": 0, "remaining": [], "findings": []}
    examples = similar(code, pool) if pool else []
    messages = build_messages(code, findings, examples)
    fixed, left = code, []
    for attempt in range(1, tries + 1):
        fixed = add_missing_imports(code, extract(ask(messages)))
        left = problems_in(code, fixed)
        if not left:
            return {"status": "verified", "fixed": fixed, "attempts": attempt,
                    "remaining": [], "findings": findings}
        messages.append({"role": "assistant", "content": fixed})
        messages.append({"role": "user", "content": "Problems found:\n" + "\n".join(left) +
                         "\nFix them. Return only the fixed function."})
    return {"status": "not verified", "fixed": fixed, "attempts": tries,
            "remaining": left, "findings": findings}


def _functions(tree):
    out = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append(child)
            elif isinstance(child, ast.ClassDef):
                visit(child)

    visit(tree)
    return out


def fix_file(path, ask, pool=None, tries=3):
    """Suggest a fix for every function in a file that has a finding."""
    source = open(path, encoding="utf-8", errors="replace").read()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {"error": f"not valid Python 3 ({e.msg}, line {e.lineno})", "suggestions": [], "outside": []}
    lines = source.splitlines()
    findings = scan(source)
    suggestions, covered = [], set()
    for fn in _functions(tree):
        start = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
        hits = [(l, m) for l, m in findings if start <= l <= fn.end_lineno]
        if not hits:
            continue
        covered.update(l for l, _ in hits)
        original = textwrap.dedent("\n".join(lines[start - 1:fn.end_lineno]))
        result = fix_code(original, ask, pool, tries)
        diff = list(difflib.unified_diff(original.splitlines(), result["fixed"].splitlines(),
                                         "before", "after", lineterm="", n=1))
        suggestions.append({"function": fn.name, "start": start, "end": fn.end_lineno,
                            "findings": hits, "status": result["status"],
                            "attempts": result["attempts"], "remaining": result["remaining"],
                            "diff": diff})
    outside = [(l, m) for l, m in findings if l not in covered]
    return {"error": None, "suggestions": suggestions, "outside": outside}


def format_result(path, result):
    """Readable report for fix_file() output (used by the CLI and notebooks)."""
    if result["error"]:
        return f"{path}: {result['error']}"
    if not result["suggestions"] and not result["outside"]:
        return "No findings."
    out = []
    for s in result["suggestions"]:
        out.append("=" * 60)
        out.append(f"{path}: function {s['function']} (lines {s['start']}-{s['end']})")
        for line, message in s["findings"]:
            out.append(f"  line {line}: {message}")
        verdict = "VERIFIED" if s["status"] == "verified" else "NOT VERIFIED"
        out.append(f"  checks: {verdict} after {s['attempts']} attempt(s)")
        for problem in s["remaining"]:
            out.append(f"  still reports: {problem}")
        out.append("\n".join(s["diff"]) if s["diff"] else "  (no change suggested)")
    for line, message in result["outside"]:
        out.append(f"{path}:{line}: {message}  [module-level code, no suggestion made]")
    out.append("\nSuggestions only: nothing was written. A VERIFIED fix passes the scanner and static "
               "checks; it is not proven safe or correct, so review it and run your tests.")
    return "\n".join(out)

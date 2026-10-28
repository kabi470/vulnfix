import ast
import importlib
import json
import sys

# Modules that open windows/browsers or print when imported
SKIP = {"antigravity", "this", "tkinter", "turtle", "idlelib", "pydoc", "webbrowser"}


def _import_std(name):
    top = name.split(".")[0]
    if top in sys.stdlib_module_names and top not in SKIP:
        try:
            return importlib.import_module(name)
        except Exception:
            return None
    return None


def _has(mod, attr):
    if hasattr(mod, attr):
        return True
    try:  # submodule that is importable but not loaded yet
        importlib.import_module(mod.__name__ + "." + attr)
        return True
    except Exception:
        return False


def check_attrs(code):
    """Flag stdlib attributes that do not exist in this Python version."""
    tree = ast.parse(code)
    mods, problems = {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                m = _import_std(a.name if a.asname else a.name.split(".")[0])
                if m:
                    mods[a.asname or a.name.split(".")[0]] = m
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            m = _import_std(node.module)
            if m:
                for a in node.names:
                    if a.name != "*" and not _has(m, a.name):
                        problems.append(f"'{a.name}' not found in {node.module}")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in mods and not _has(mods[node.value.id], node.attr)):
            problems.append(f"{node.value.id}.{node.attr} does not exist in Python {sys.version.split()[0]}")
    return sorted(set(problems))


def signatures(code):
    out = {}
    for n in ast.walk(ast.parse(code)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            out[n.name] = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    return out


def check_signatures(original, fixed):
    o, f = signatures(original), signatures(fixed)
    problems = []
    for name, args in o.items():
        if name not in f:
            problems.append(f"function '{name}' was removed")
        elif f[name] != args:
            problems.append(f"function '{name}' arguments changed: {args} -> {f[name]}")
    return problems


def behavior_check(original, fixed):
    try:
        return check_attrs(fixed) + check_signatures(original, fixed)
    except SyntaxError:
        return ["fixed code is not valid Python"]


if __name__ == "__main__":
    bad = "import ast\n\ndef f(n):\n    return ast.Num(n)\n"
    print("Self-test (uses ast.Num):", check_attrs(bad) or "nothing flagged (needs Python 3.14+ to flag it)")

    pairs = [json.loads(l) for l in open("verified_pairs.jsonl")]
    clean, flagged = 0, []
    for p in pairs:
        probs = behavior_check(p["vulnerable_code"], p["fixed_code"])
        if probs:
            flagged.append(probs)
        else:
            clean += 1
    print(f"\nChecked {len(pairs)} verified pairs")
    print(f"Pass behavior check: {clean}")
    print(f"Flagged: {len(flagged)}")
    for probs in flagged[:8]:
        print(" -", probs)

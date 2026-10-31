import ast
import builtins
import sys

STD = set(sys.stdlib_module_names)
ALLOWED = set(dir(builtins)) | {"__file__"}


def free_names(code):
    """Names a snippet reads but never defines, imports, or receives as arguments."""
    tree = ast.parse(code)
    bound = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                bound.add(a.asname or a.name)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bound.add(n.id)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            bound.add(n.name)
    used = {n.id for n in ast.walk(tree)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return used - bound - ALLOWED


def new_names(original, fixed):
    """Unbound names that the fix introduced (the original did not need them)."""
    return sorted(free_names(fixed) - free_names(original))


def add_missing_imports(original, fixed):
    """Prepend 'import X' for new names that are standard-library modules."""
    try:
        missing = new_names(original, fixed)
    except SyntaxError:
        return fixed
    lines = [f"import {n}" for n in missing if n in STD]
    return ("\n".join(lines) + "\n" + fixed) if lines else fixed


def new_undefined_names(original, fixed):
    try:
        names = new_names(original, fixed)
    except SyntaxError:
        return ["fixed code is not valid Python"]
    return [f"uses '{n}' which is not defined or imported" for n in names]


if __name__ == "__main__":
    orig = "def f(x):\n    return eval(x)\n"
    cases = {
        "A literal_eval, no import": "def f(x):\n    return ast.literal_eval(x)\n",
        "B undefined helper class": "def f(x):\n    return RestrictedUnpickler(x).load()\n",
        "C unchanged": orig,
        "D subprocess, no import": "def f(x):\n    subprocess.run(['echo', x])\n",
    }
    for label, fixed in cases.items():
        patched = add_missing_imports(orig, fixed)
        imports = [l for l in patched.splitlines() if l.startswith("import ")]
        print(f"{label:28} -> {new_undefined_names(orig, patched) or 'ok'} | auto imports: {imports}")

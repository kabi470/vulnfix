"""Run a function on harmless test inputs in a separate process.

NOT a security sandbox. It runs the original AND the model-written code, so use it
only in a disposable environment (a Kaggle notebook, a throwaway folder or VM)
and only with harmless inputs.

Test file (JSON), keyed by top-level function name:
  {"calc": [{"args": ["1+2"], "expect": 3},
            {"args": ["1/0"], "raises": "ZeroDivisionError"}]}
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

MARK = "@@VULNFIX@@"

RUNNER = r'''
import contextlib, inspect, io, json, sys
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1000000, 1000000))
except Exception:
    pass
payload = json.loads(sys.stdin.read())
out = {"error": None, "results": []}
ns = {"__name__": "vulnfix_snippet"}
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        exec(compile(payload["code"], "<snippet>", "exec"), ns)
except BaseException as e:
    out["error"] = type(e).__name__ + ": " + str(e)[:200]
else:
    fn = ns.get(payload["func"])
    if not callable(fn):
        out["error"] = "function '" + payload["func"] + "' not found"
    elif inspect.iscoroutinefunction(fn):
        out["error"] = "async functions are not supported by tests"
    else:
        for case in payload["cases"]:
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    value = fn(*case.get("args", []), **case.get("kwargs", {}))
                try:
                    json.dumps(value)
                except TypeError:
                    value = repr(value)
                out["results"].append({"ok": True, "value": value})
            except BaseException as e:
                out["results"].append({"ok": False, "exc": type(e).__name__, "msg": str(e)[:200]})
sys.__stdout__.write("\n" + "@@VULNFIX@@" + json.dumps(out) + "\n")
sys.__stdout__.flush()
'''


def load_tests(path):
    data = json.load(open(path))
    if not isinstance(data, dict):
        raise ValueError("tests file must be a JSON object: {function_name: [cases]}")
    for name, cases in data.items():
        if not isinstance(cases, list) or not all(isinstance(c, dict) for c in cases):
            raise ValueError(f"tests for '{name}' must be a list of case objects")
    return data


def run_cases(code, func, cases, timeout=10):
    workdir = tempfile.mkdtemp(prefix="vulnfix_")
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", RUNNER],
            input=json.dumps({"code": code, "func": func, "cases": cases}),
            capture_output=True, text=True, timeout=timeout, cwd=workdir,
            env={"PATH": "/usr/bin:/bin"},
        )
    except subprocess.TimeoutExpired:
        return {"error": f"timed out after {timeout}s", "results": []}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    for line in proc.stdout.splitlines():
        if line.startswith(MARK):
            return json.loads(line[len(MARK):])
    return {"error": "the code crashed or exited before finishing", "results": []}


def _call(func, case):
    parts = [repr(a) for a in case.get("args", [])]
    parts += [f"{k}={v!r}" for k, v in case.get("kwargs", {}).items()]
    return f"{func}({', '.join(parts)})"


def check_cases(code, func, cases, timeout=10):
    """Return a list of failure descriptions; an empty list means every case passed."""
    run = run_cases(code, func, cases, timeout)
    if run["error"]:
        return [f"could not run the code: {run['error']}"]
    failures = []
    for case, res in zip(cases, run["results"]):
        call = _call(func, case)
        raises = case.get("raises")
        if raises:
            if res["ok"]:
                failures.append(f"{call} returned {res['value']!r} but should raise "
                                f"{'an error' if raises is True else raises}")
            elif raises is not True and res["exc"] != raises:
                failures.append(f"{call} raised {res['exc']} but should raise {raises}")
        elif not res["ok"]:
            failures.append(f"{call} raised {res['exc']}: {res['msg']}")
        elif "expect" in case and res["value"] != case["expect"]:
            failures.append(f"{call} returned {res['value']!r} but should return {case['expect']!r}")
    return failures

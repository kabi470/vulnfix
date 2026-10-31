#!/usr/bin/env python3
"""vulnfix: find common vulnerabilities in Python code and suggest checked fixes.

  python vulnfix.py scan PATH [--json]
  python vulnfix.py fix FILE --backend ollama --model qwen2.5-coder:7b [--pool clean_pairs.jsonl]

Nothing is ever written to your files. Review every suggestion before using it.
Use only on code you own or are authorized to test.
"""
import argparse
import json
import os
import sys
import urllib.request

SKIP_DIRS = {"venv", "env", "node_modules", "__pycache__", "site-packages", "data", "build", "dist"}


def python_files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


def scan_path(path):
    from detector import scan

    findings, skipped, files = [], [], 0
    for f in python_files(path):
        files += 1
        try:
            code = open(f, encoding="utf-8", errors="replace").read()
            for line, message in scan(code):
                findings.append({"file": f, "line": line, "message": message})
        except SyntaxError as e:
            skipped.append({"file": f, "reason": f"not valid Python 3 ({e.msg}, line {e.lineno})"})
        except Exception as e:  # keep scanning the rest
            skipped.append({"file": f, "reason": f"{type(e).__name__}: {e}"})
    return {"files": files, "findings": findings, "skipped": skipped}


def cmd_scan(args):
    if not os.path.exists(args.path):
        print(f"No such file or folder: {args.path}", file=sys.stderr)
        return 2
    result = scan_path(args.path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for f in result["findings"]:
            print(f"{f['file']}:{f['line']}: {f['message']}")
        for s in result["skipped"]:
            print(f"skipped {s['file']}: {s['reason']}", file=sys.stderr)
        with_findings = len({f["file"] for f in result["findings"]})
        print(f"\nScanned {result['files']} file(s): {len(result['findings'])} finding(s) "
              f"in {with_findings} file(s), {len(result['skipped'])} skipped.")
    return 1 if result["findings"] else 0


def ollama_ask(model, host):
    def ask(messages):
        body = json.dumps({"model": model, "messages": messages, "stream": False,
                           "options": {"temperature": 0}}).encode()
        req = urllib.request.Request(host.rstrip("/") + "/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=900) as r:
            return json.loads(r.read())["message"]["content"]

    return ask


def cmd_fix(args):
    from fixer import fix_file, format_result, load_pool

    if not os.path.isfile(args.file):
        print(f"No such file: {args.file}", file=sys.stderr)
        return 2
    pool = None
    if args.pool and os.path.exists(args.pool):
        try:
            import sklearn  # noqa: F401
            pool = load_pool(args.pool)
        except ImportError:
            print("scikit-learn not installed: continuing without retrieval examples.", file=sys.stderr)
    ask = ollama_ask(args.model, args.host)
    try:
        result = fix_file(args.file, ask, pool, args.tries)
    except OSError as e:
        print(f"Could not reach the model at {args.host}: {e}\nIs Ollama running, and is the model pulled?",
              file=sys.stderr)
        return 3
    print(format_result(args.file, result))
    return 2 if result["error"] else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="vulnfix", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="find vulnerabilities in a file or folder")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)
    f = sub.add_parser("fix", help="suggest checked fixes for one file (needs a running model)")
    f.add_argument("file")
    f.add_argument("--backend", choices=["ollama"], default="ollama")
    f.add_argument("--model", default="qwen2.5-coder:7b")
    f.add_argument("--host", default="http://localhost:11434")
    f.add_argument("--pool", default="clean_pairs.jsonl", help="verified examples for retrieval (optional)")
    f.add_argument("--tries", type=int, default=3)
    f.set_defaults(func=cmd_fix)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

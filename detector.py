import ast
import collections
import json
import sys

DESERIALIZERS = ("pickle.loads", "pickle.load", "cPickle.loads",
                 "cPickle.load", "marshal.loads", "marshal.load")


def dotted(node):
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def is_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


class Detector(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.dynamic = set()

    def is_dynamic(self, n):
        if isinstance(n, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in n.values)
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            both_const = isinstance(n.left, ast.Constant) and isinstance(n.right, ast.Constant)
            touches_str = (is_str(n.left) or is_str(n.right)
                           or self.is_dynamic(n.left) or self.is_dynamic(n.right))
            return touches_str and not both_const
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "format" and is_str(n.func.value)):
            return bool(n.args or n.keywords)
        if isinstance(n, ast.Name):
            return n.id in self.dynamic
        return False

    def visit_Assign(self, node):
        if self.is_dynamic(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.dynamic.add(t.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = dotted(node.func)
        arg = node.args[0] if node.args else None

        # Rule 3: code injection via eval/exec
        if name in ("eval", "exec") and arg is not None and not isinstance(arg, ast.Constant):
            self.findings.append((node.lineno, f"Code injection: {name}() on non-constant input"))

        # Rule 4: insecure deserialization
        if name in DESERIALIZERS:
            self.findings.append((node.lineno, f"Insecure deserialization: {name}() can run attacker code"))

        # Rule 5: yaml.load without a safe loader
        if name in ("yaml.load", "yaml.unsafe_load"):
            loader = None
            for k in node.keywords:
                if k.arg == "Loader":
                    loader = k.value
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if name == "yaml.unsafe_load" or loader is None or not dotted(loader).endswith("SafeLoader"):
                self.findings.append((node.lineno, "Insecure deserialization: yaml.load without SafeLoader"))

        # Rules 1 and 2: SQL injection and command injection
        if arg is not None:
            if name.endswith((".execute", ".executemany")) and self.is_dynamic(arg):
                self.findings.append((node.lineno, "SQL injection: query built from dynamic string"))
            elif name in ("os.system", "os.popen") and not isinstance(arg, ast.Constant):
                self.findings.append((node.lineno, "Command injection: non-constant shell command"))
            elif name.startswith("subprocess.") and not isinstance(arg, ast.Constant):
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                                 and k.value.value is True for k in node.keywords)
                if shell_true:
                    self.findings.append((node.lineno, "Command injection: shell=True with non-constant command"))
        self.generic_visit(node)


def scan(code):
    d = Detector()
    d.visit(ast.parse(code))
    return d.findings


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--eval":
        total = vuln_hit = fixed_hit = 0
        by_rule = collections.Counter()
        for line in open("pairs.jsonl"):
            p = json.loads(line)
            total += 1
            f = scan(p["vulnerable_code"])
            vuln_hit += bool(f)
            for _, msg in f:
                by_rule[msg.split(":")[0]] += 1
            fixed_hit += bool(scan(p["fixed_code"]))
        print(f"Pairs: {total}")
        print(f"Flagged in vulnerable code: {vuln_hit}")
        print(f"Flagged in 'fixed' code (false alarms?): {fixed_hit}")
        print("Findings by rule:", dict(by_rule))
    elif len(sys.argv) > 1:
        for lineno, msg in scan(open(sys.argv[1]).read()):
            print(f"line {lineno}: {msg}")
    else:
        print("Usage: python detector.py file.py   or   python detector.py --eval")

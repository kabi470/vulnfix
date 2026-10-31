import ast


def dotted(node):
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


class Extra(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_ClassDef(self, node):
        if any(dotted(b).endswith("Unpickler") for b in node.bases):
            for item in node.body:
                if (isinstance(item, ast.FunctionDef) and item.name == "find_class"
                        and item.body and isinstance(item.body[-1], ast.Return)):
                    self.findings.append((item.lineno,
                        "Insecure deserialization: Unpickler.find_class allows everything by default (denylist); use an allowlist that ends in raise"))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = dotted(node.func)
        arg = node.args[0] if node.args else None
        if name in ("pickle.Unpickler", "cPickle.Unpickler"):
            self.findings.append((node.lineno,
                "Insecure deserialization: pickle.Unpickler without a restricted find_class"))
        if arg is not None and not isinstance(arg, ast.Constant):
            if name in ("__import__", "importlib.import_module"):
                self.findings.append((node.lineno,
                    "Code injection: dynamic import of a module chosen by input"))
            elif (name == "getattr" and dotted(arg) in ("__builtins__", "builtins")
                  and len(node.args) > 1 and not isinstance(node.args[1], ast.Constant)):
                self.findings.append((node.lineno,
                    "Code injection: getattr on builtins with an input-chosen name"))
        self.generic_visit(node)


def extra_findings(tree):
    e = Extra()
    e.visit(tree)
    return e.findings

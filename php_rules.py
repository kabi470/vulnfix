"""PHP scanner built on tree-sitter-php: finds common vulnerabilities in a PHP function or file.

php_scan(code)       -> [(line, message), ...]
php_syntax_ok(code)  -> True if the code parses without errors
php_functions(code)  -> functions and methods with their source text
php_signatures(code) -> {name: parameter_count}

Snippets without an opening tag get "<?php" added automatically.
"""
import re

_PARSER = None


def _parser():
    global _PARSER
    if _PARSER is None:
        from tree_sitter import Language, Parser
        import tree_sitter_php as tsphp

        fn = getattr(tsphp, "language_php", None) or getattr(tsphp, "language")
        lang = Language(fn())
        try:
            _PARSER = Parser(lang)
        except TypeError:
            _PARSER = Parser()
            _PARSER.set_language(lang)
    return _PARSER


def _prep(code):
    if code.lstrip().startswith("<?"):
        return code, 0
    return "<?php\n" + code, 1


def parse(code):
    src, shift = _prep(code)
    return _parser().parse(src.encode("utf8")), shift


def php_syntax_ok(code):
    tree, _ = parse(code)
    return not tree.root_node.has_error


# ---------------------------------------------------------------- helpers
SUPERGLOBALS = {"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"}
NUMERIC = {"intval", "floatval", "doubleval", "absint", "abs", "count", "strlen", "md5", "sha1",
           "crc32", "time", "mt_rand", "rand"}
ESCAPERS = {
    "sql": {"mysqli_real_escape_string", "mysql_real_escape_string", "mysql_escape_string", "addslashes",
            "esc_sql", "pg_escape_string", "pg_escape_literal", "sqlite_escape_string", "quote"},
    "html": {"htmlspecialchars", "htmlentities", "esc_html", "esc_attr", "esc_url", "esc_textarea",
             "esc_js", "wp_kses", "wp_kses_post", "strip_tags", "urlencode", "rawurlencode",
             "json_encode", "sanitize_text_field", "sanitize_title", "number_format"},
    "shell": {"escapeshellarg", "escapeshellcmd"},
    "path": {"basename", "realpath", "sanitize_file_name"},
}
SQL_FUNCS = {"mysql_query", "mysqli_query", "mysqli_real_query", "mysqli_multi_query", "pg_query",
             "pg_send_query", "sqlite_query", "sqlite_exec", "mssql_query", "odbc_exec", "db_query"}
SQL_METHODS = {"query", "exec", "prepare", "get_results", "get_row", "get_var", "get_col", "real_query",
               "multi_query", "execute_query"}
SHELL_FUNCS = {"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"}
CALLS = {"function_call_expression", "member_call_expression", "scoped_call_expression"}
INCLUDES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}
LITERALS = {"string", "integer", "float", "boolean", "null", "string_content", "escape_sequence", "nowdoc", "name"}
NUMERIC_CAST = re.compile(r"\(\s*(int|integer|float|double|bool|boolean)\s*\)", re.I)


def _t(node):
    return node.text.decode("utf8", "replace")


def _var(node):
    return _t(node).lstrip("$").strip()


def _callee(node):
    name = ""
    for c in node.named_children:
        if c.type in ("name", "qualified_name", "relative_name"):
            name = _t(c).split("\\")[-1].lower()
    return name


def _args(node):
    for c in node.named_children:
        if c.type == "arguments":
            out = []
            for a in c.named_children:
                if a.type == "argument":
                    if a.named_children:
                        out.append(a.named_children[-1])
                else:
                    out.append(a)
            return out
    return []


def _unwrap(n):
    while n.type == "parenthesized_expression" and len(n.named_children) == 1:
        n = n.named_children[0]
    return n


def _is_concat(n):
    return n.type == "binary_expression" and any(c.type == "." for c in n.children)


def _interpolates(n):
    return n.type == "encapsed_string" and any(c.type not in ("string_content", "escape_sequence")
                                               for c in n.named_children)


def _is_building(n):
    n = _unwrap(n)
    return _is_concat(n) or _interpolates(n)


def _is_constant_string(n):
    n = _unwrap(n)
    return n.type in ("string", "integer", "float") or (n.type == "encapsed_string" and not _interpolates(n))


def _parts(n):
    """The dynamic pieces of a string-building expression."""
    n = _unwrap(n)
    if _is_concat(n):
        for c in n.named_children:
            yield from _parts(c)
    elif n.type == "encapsed_string":
        for c in n.named_children:
            if c.type not in ("string_content", "escape_sequence"):
                yield from _parts(c)
    elif n.type not in LITERALS:
        yield n


def _sanitizer(name, ctx):
    return name in NUMERIC or name in ESCAPERS[ctx]


class _Scan:
    def __init__(self, shift=0):
        self.shift = shift
        self.findings = []
        self.sql_dyn, self.shell_dyn, self.tainted = set(), set(), set()

    def add(self, node, message):
        self.findings.append((node.start_point[0] + 1 - self.shift, message))

    # an expression piece that is dynamic and not made safe for this context
    def unsafe(self, n, ctx):
        t = n.type
        if t in ("variable_name", "subscript_expression", "dynamic_variable_name"):
            return True
        if t == "cast_expression":
            return not NUMERIC_CAST.match(_t(n))
        if t in CALLS:
            name = _callee(n)
            if _sanitizer(name, ctx):
                return False
            if name in ("implode", "join", "array_map") and "intval" in _t(n):
                return False
            return True
        if t == "member_access_expression":
            return False
        return any(self.unsafe(c, ctx) for c in n.named_children)

    def is_tainted(self, n, ctx="html"):
        t = n.type
        if t == "variable_name":
            return _var(n) in self.tainted
        if t == "subscript_expression":
            base = n.named_children[0] if n.named_children else None
            if base is not None and base.type == "variable_name" and _var(base) in SUPERGLOBALS:
                return True
            return any(self.is_tainted(c, ctx) for c in n.named_children)
        if t == "cast_expression" and NUMERIC_CAST.match(_t(n)):
            return False
        if t in CALLS:
            if _sanitizer(_callee(n), ctx):
                return False
            return any(self.is_tainted(a, ctx) for a in _args(n))
        return any(self.is_tainted(c, ctx) for c in n.named_children)

    def dynamic(self, expr, ctx, known, augmented):
        expr = _unwrap(expr)
        if augmented:
            return any(self.unsafe(p, ctx) for p in _parts(expr))
        if expr.type == "variable_name":
            return _var(expr) in known
        return _is_building(expr) and any(self.unsafe(p, ctx) for p in _parts(expr))

    def assign(self, node):
        kids = node.named_children
        if len(kids) < 2 or kids[0].type != "variable_name":
            return
        name, right = _var(kids[0]), kids[-1]
        aug = node.type == "augmented_assignment_expression"
        for ctx, known in (("sql", self.sql_dyn), ("shell", self.shell_dyn)):
            if self.dynamic(right, ctx, known, aug):
                known.add(name)
            elif not aug:
                known.discard(name)
        if self.is_tainted(right):
            self.tainted.add(name)
        elif not aug:
            self.tainted.discard(name)

    def sql_bad(self, a):
        a = _unwrap(a)
        if a.type == "variable_name":
            return _var(a) in self.sql_dyn
        return _is_building(a) and any(self.unsafe(p, "sql") for p in _parts(a))

    def shell_bad(self, a):
        a = _unwrap(a)
        if a.type in ("variable_name", "subscript_expression"):
            return True
        return _is_building(a) and any(self.unsafe(p, "shell") for p in _parts(a))

    def call(self, node):
        t, name, args = node.type, _callee(node), _args(node)
        if t == "function_call_expression":
            if name in SQL_FUNCS:
                if any(self.sql_bad(a) for a in args):
                    self.add(node, "SQL injection: query built from dynamic string")
            elif name in SHELL_FUNCS:
                if args and self.shell_bad(args[0]):
                    self.add(node, "Command injection: shell command built from input")
            elif name == "eval":
                if args and not _is_constant_string(args[0]):
                    self.add(node, "Code injection: eval() on non-constant input")
            elif name in ("unserialize", "maybe_unserialize"):
                if args and not _is_constant_string(args[0]) and not (
                        len(args) > 1 and "allowed_classes" in _t(args[1])):
                    self.add(node, "Insecure deserialization: unserialize() on non-constant input")
        elif t in ("member_call_expression", "scoped_call_expression") and name in SQL_METHODS:
            if any(self.sql_bad(a) for a in args):
                self.add(node, "SQL injection: query built from dynamic string")

    def echo(self, node):
        for c in node.named_children:
            if self.is_tainted(c, "html"):
                self.add(node, "XSS: user input echoed without escaping")
                return

    def include(self, node):
        if not node.named_children:
            return
        a = _unwrap(node.named_children[0])
        bad = a.type in ("variable_name", "subscript_expression") or (
            _is_building(a) and any(self.unsafe(p, "path") for p in _parts(a)))
        if bad:
            self.add(node, "File inclusion: include/require of a non-constant path")

    def visit(self, node):
        t = node.type
        if t in ("assignment_expression", "augmented_assignment_expression"):
            self.assign(node)
        elif t in CALLS:
            self.call(node)
        elif t in ("echo_statement", "print_intrinsic"):
            self.echo(node)
        elif t in INCLUDES:
            self.include(node)
        elif t == "shell_command_expression":
            if any(c.type in ("variable_name", "subscript_expression") for c in _descendants(node)):
                self.add(node, "Command injection: backtick command contains variables")
        for c in node.named_children:
            self.visit(c)


def _descendants(node):
    for c in node.named_children:
        yield c
        yield from _descendants(c)


def scan_tree(root, shift=0):
    s = _Scan(shift)
    s.visit(root)
    return sorted(set(s.findings))


def php_scan(code):
    tree, shift = parse(code)
    return scan_tree(tree.root_node, shift)


# ---------------------------------------------------------------- functions
def php_functions(code):
    """Every function and method: name (Class::method), line range, parameter count, source text."""
    src, shift = _prep(code)
    data = src.encode("utf8")
    tree = _parser().parse(data)
    out = []

    def walk(node, cls):
        t = node.type
        if t in ("function_definition", "method_declaration"):
            name = ""
            for c in node.named_children:
                if c.type == "name":
                    name = _t(c)
            params = 0
            for c in node.named_children:
                if c.type == "formal_parameters":
                    params = len(c.named_children)
            full = f"{cls}::{name}" if cls and t == "method_declaration" else name
            out.append({"name": full, "start": node.start_point[0] + 1 - shift,
                        "end": node.end_point[0] + 1 - shift, "params": params,
                        "code": data[node.start_byte:node.end_byte].decode("utf8", "replace")})
            return
        if t in ("class_declaration", "trait_declaration", "interface_declaration"):
            for c in node.named_children:
                if c.type == "name":
                    cls = _t(c)
        for c in node.named_children:
            walk(c, cls)

    walk(tree.root_node, None)
    return out


def php_signatures(code):
    return {f["name"]: f["params"] for f in php_functions(code)}

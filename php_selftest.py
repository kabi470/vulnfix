"""Checks php_rules.py against the real tree-sitter-php parser. Run: python php_selftest.py"""
import php_rules as R

CASES = [
    ("sql concat", '<?php $r = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);', True),
    ("sql interpolated + variable", '<?php $q = "SELECT * FROM users WHERE name=\'$name\'"; $db->query($q);', True),
    ("prepared", '<?php $s = $pdo->prepare("SELECT * FROM t WHERE id = ?"); $s->execute([$id]);', False),
    ("intval wrapped", '<?php mysql_query("SELECT 1 WHERE id=" . intval($id));', False),
    ("(int) cast wrapped", '<?php mysql_query("SELECT 1 WHERE id=" . (int)$id);', False),
    ("escape wrapped", '<?php mysqli_query($c, "SELECT 1 WHERE n=\'" . mysqli_real_escape_string($c, $n) . "\'");', False),
    ("constant query", '<?php $db->query("SELECT 1");', False),
    ("superglobal in variable", '<?php $sql = "SELECT * FROM t WHERE a=" . $_GET["a"]; $db->query($sql);', True),
    ("append with .=", '<?php $q = "SELECT * FROM t WHERE 1"; $q .= " AND id=" . $id; $db->query($q);', True),
    ("variable overwritten by constant", '<?php $q = "x" . $id; $q = "SELECT 1"; $db->query($q);', False),
    ("wpdb interpolation", '<?php $wpdb->query("DELETE FROM t WHERE id = $id");', True),
    ("system concat", '<?php system("ping " . $host);', True),
    ("system escapeshellarg", '<?php system("ping " . escapeshellarg($host));', False),
    ("exec variable", '<?php exec($cmd, $o);', True),
    ("shell_exec constant", '<?php shell_exec("ls -la");', False),
    ("eval variable", '<?php eval($code);', True),
    ("eval constant", '<?php eval("return 1;");', False),
    ("unserialize cookie", '<?php $o = unserialize($_COOKIE["data"]);', True),
    ("unserialize allowed_classes", '<?php $o = unserialize($s, ["allowed_classes" => false]);', False),
    ("include $_GET", '<?php include $_GET["page"];', True),
    ("include __DIR__ . file", '<?php include __DIR__ . "/header.php";', False),
    ("include basename", '<?php include basename($_GET["p"]) . ".php";', False),
    ("echo $_GET", '<?php echo $_GET["name"];', True),
    ("echo concat $_POST", '<?php echo "Hello " . $_POST["n"];', True),
    ("echo interpolated", '<?php echo "Hello $_GET[name]";', True),
    ("echo htmlspecialchars", '<?php echo htmlspecialchars($_GET["name"]);', False),
    ("tainted variable echoed", '<?php $n = $_GET["n"]; echo $n;', True),
    ("tainted variable escaped", '<?php $n = $_GET["n"]; echo htmlspecialchars($n);', False),
    ("echo constant", '<?php echo "Hello";', False),
    ("echo unknown variable", '<?php echo $title;', False),
    ("echo (int) cast", '<?php echo (int)$_GET["id"];', False),
    ("taint through trim()", '<?php $n = trim($_POST["n"]); echo $n;', True),
    ("taint cleared", '<?php $n = $_GET["n"]; $n = "safe"; echo $n;', False),
    ("implode with intval", '<?php $db->query("SELECT * FROM t WHERE id IN (" . implode(",", array_map("intval", $ids)) . ")");', False),
    ("snippet without opening tag", 'function f($x) { return mysql_query("a" . $x); }', True),
    ("method inside a class", '<?php class A { public function m($y) { return mysql_query("a" . $y); } }', True),
    ("method on its own", 'public function m($y) { return mysql_query("a" . $y); }', True),
    ("static method on its own", 'public static function m($y) { echo $_GET["a"]; }', True),
    ("method on its own, safe", 'private function m($y) { return mysql_query("a" . intval($y)); }', False),
]


def show(node, depth=0):
    if depth > 9:
        return
    text = node.text.decode("utf8", "replace").replace("\n", " ")
    leaf = node.named_child_count == 0
    print("      " + "  " * depth + node.type + (f"  {text[:40]!r}" if leaf else ""))
    for c in node.named_children:
        show(c, depth + 1)


failed = 0
for label, code, expected in CASES:
    got = R.php_scan(code)
    ok = bool(got) == expected
    failed += not ok
    print(("PASS " if ok else "FAIL ") + label, "| flagged:", bool(got))
    if not ok:
        print("      findings:", got)
        tree, _ = R.parse(code)
        show(tree.root_node)

extra = []
extra.append(("syntax: good code", R.php_syntax_ok("<?php function f($x) { return $x + 1; }"), True))
extra.append(("syntax: broken code", R.php_syntax_ok("<?php function f($x { return $x + 1; }"), False))
extra.append(("syntax: snippet without tag", R.php_syntax_ok("function f($x) { return $x; }"), True))
sig = R.php_signatures("<?php function f($x) { return $x; } class A { public function m($y, $z) { return $y; } }")
extra.append(("signatures", sig, {"f": 1, "A::m": 2}))
line = R.php_scan("function f() {\n  eval($x);\n}")
extra.append(("line numbers for snippets", [l for l, _ in line], [2]))
funcs = R.php_functions("<?php\nfunction f($x) {\n  return $x;\n}\n")
extra.append(("function text", funcs[0]["code"].startswith("function f") if funcs else None, True))
extra.append(("syntax: method on its own", R.php_syntax_ok("public function m($x) { return $x; }"), True))
extra.append(("line numbers for a method on its own",
              [l for l, _ in R.php_scan("public function m() {\n  eval($x);\n}")], [2]))
for label, got, expected in extra:
    ok = got == expected
    failed += not ok
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else f" | got {got!r}, expected {expected!r}"))

total = len(CASES) + len(extra)
print(f"\n{total - failed}/{total} passed")

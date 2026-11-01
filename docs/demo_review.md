# Demo of the `fix` pipeline with a real model (Qwen2.5-Coder-14B-Instruct, Kaggle T4 x2)

Files: `test_vuln.py` and `examples/demo.py` (deliberately vulnerable code). Retrieval examples from `clean_pairs.jsonl`. Scanner-verified 5/7, good after manual review 3/7 (nothing executed).

| Function | Scanner | Review |
|---|---|---|
| a (SQL) | verified | Good |
| b (SQL) | verified | Good (leftover `f` prefix is harmless) |
| d (os.system) | not verified | `shlex.quote` is a defensible mitigation, but the scanner cannot accept it; argument lists would be better |
| load_cfg (yaml.load) | verified | Good |
| restore (pickle.loads) | not verified | Correctly rejected: `pickle.load(..., fix_imports=False)` restricts nothing |
| run (shell=True) | verified | Partial: no shell parsing, but the input still chooses the program (only an allowlist would make this safe) |
| calc (eval) | verified | Wrong: `ast.literal_eval("1+2")` raises an error, so the feature is broken |

The `calc` case is why the next step is running the original and fixed code on benign test inputs.

## Final demo run (hints, passthrough rule, visitor check, tests with imports)

All seven functions end with a fix that reads as good. `calc` passes 5 executed tests and `run` passes 2 (both run on Kaggle in a separate process). The other five are judged by the scanner, the static checks and manual reading only.

| Function | Result | Caveat |
|---|---|---|
| a, b (SQL) | parameterized queries | none |
| d (os.system) | `subprocess.run([...])`, no shell | `check=True` changes failure behavior |
| load_cfg | `yaml.safe_load` | none |
| restore | `json.loads` | the code that writes this data must switch to JSON too |
| run | allowlist (`ls`, `echo`), no shell, string input kept | the allowlist is a guess to set for your app; empty input raises IndexError |
| calc | safe `ast` evaluator that raises on anything unsupported | supports only + - * / and unary minus |

These seven functions were used while the hints, rules and tests were tuned, so this is a demonstration and not an independent benchmark. The real-CVE evaluation in `real_review.md` is the better indicator, and it predates these changes.

How the loop got here: the first runs passed `calc` with `ast.literal_eval`, then with a `visit_Num` visitor that breaks on Python 3.14 (confirmed on Python 3.14.7), and `run` with a bare list pass-through. Each was caught by adding a rule, a static check, or tests with error cases. The tests for `run` first failed to run at all because the function was missing the file's `import subprocess`; the tool reported that honestly and was fixed.

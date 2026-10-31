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

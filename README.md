# vulnfix

A prototype that finds common vulnerabilities in Python code and fixes them automatically, built only with free and open-source tools.

## How it works

scan -> retrieve -> fix -> verify

1. **Scan:** `detector.py` uses Python's `ast` module to find SQL injection, command injection, `eval`/`exec`, unsafe `pickle`/`marshal`, and unsafe `yaml.load`.
2. **Retrieve:** TF-IDF search finds the most similar verified (vulnerable -> fixed) examples.
3. **Fix:** Qwen2.5-Coder-14B-Instruct (4-bit, Kaggle free T4 x2 GPUs) writes a fix, guided by those examples.
4. **Verify:** The fix must pass the scanner and `behavior_check.py` (valid Python, no removed or non-existent standard-library APIs, same function names and arguments). If it fails, the model retries up to 3 times with the problems listed.

## Results

Test: 15 held-out pairs. The 78 scanner-verified pairs were filtered by the behavior check, leaving 56 clean pairs (15 for testing, 41 for retrieval).

| Setup | Fixed and verified | Avg. attempts |
|---|---|---|
| With retrieval | 14 / 15 | 1.13 |
| Without retrieval | 13 / 15 | 1.27 |

Retrieval was ahead by one case, which is too small a difference to claim it helps.

An earlier, weaker run (scanner only, 15 cases from the 78 pairs) gave 15/15 with retrieval and 13/15 without. It also accepted a fix that used `ast.Num`, which was removed in Python 3.14. That is why the behavior check was added.

Failures in the strict run: two fixes still contained command injection, and one was not valid Python.

## Limitations (please read)

- The test is small (15 cases) and uses a synthetic dataset (CyberNative/Code_Vulnerability_Security_DPO). The same scanner helps build the pairs and checks the fixes.
- "Verified" means no known vulnerable pattern remains and the static behavior checks pass. The fixed code is **not executed**, so it is not proven to behave the same.
- Only 78 of 355 dataset pairs passed the scanner, and 56 passed the behavior check.
- It covers few vulnerability types and handles one snippet at a time, not whole projects.

## Files

- `build_pairs.py` - builds vulnerable/fixed pairs from the dataset
- `detector.py` - the rule-based scanner
- `verify_pairs.py` - keeps only scanner-verified pairs
- `behavior_check.py` - static checks on fixed code
- `make_clean_pairs.py` - builds `clean_pairs.jsonl` (pairs that pass both checks)
- `analyze.py` - dataset statistics
- `notebook*.ipynb` - the Kaggle notebook with the first LLM fix loop
- `results.txt` - raw results from the first run

## Run it

    pip install datasets scikit-learn
    python build_pairs.py
    python verify_pairs.py
    python make_clean_pairs.py
    python detector.py yourfile.py

The LLM step runs in a Kaggle notebook (free GPU).

## Roadmap

- Run fixes against test inputs in a sandbox
- Command-line tool
- Real-world data (CVEfixes, GitHub Advisory Database)
- More vulnerability rules and a larger evaluation

Use only on code you own or are authorized to test.

## Data credit

Real-world pairs come from the CVEfixes dataset (Bhandari, Naseer, Moonen, PROMISE '21), licensed CC BY 4.0: https://doi.org/10.1145/3475960.3475985

## Real-world test (CVEfixes)

I ran the loop on real CVE-fix functions that my detector flags (19 functions from 15 CVEs). Retrieval examples came only from the synthetic pairs.

| Setup | Scanner-verified | Avg. attempts |
|---|---|---|
| With retrieval | 15 / 19 | 1.63 |
| Without retrieval | 14 / 19 | 1.79 |

I then read every output by hand (nothing was executed): **11 of 19 are correct fixes**. 4 passed the scanner but are wrong or incomplete, and the other 4 were correctly rejected by the scanner. See `docs/real_review.md`.

The model handles well-known one-line patterns (`yaml.safe_load`, passing arguments as a list instead of a shell string) but fails where the fix needs design, such as replacing `eval` with a safe expression evaluator. Scanner verification alone overstates success, so the next step is a check for undefined names and tests that run the fixed code.

### Second real-world run (with name check)

Same 19 functions, with retrieval, plus a check for undefined names and automatic standard-library imports: scanner-verified **17 / 19**, correct after manual review **12 / 19**. The first run scored 15/19 and 11/19, so the difference is one case. The five wrong fixes use patterns my scanner does not know (denylist-based unpicklers, `__import__` on input-chosen names, `ast.literal_eval` replacing `eval`). When a checker is part of the loop, the model drifts toward code the checker cannot see. See `docs/real_review.md`.

Another limit: 195 of the 719 real human fixes in the data use names from outside the function, so a model that sees one function cannot reproduce about a quarter of real fixes.

### Third run (extra rules: dynamic import, builtins getattr, denylist Unpickler)

20 functions (the earlier 19 plus CVE-2015-1326): scanner-verified **15 / 20**, good after manual review **12 / 20**. The new rules turned two wrong passes (denylist unpicklers) into honest failures, but the model rewrote a third bad fix into a form the rule missed, and two `ast.literal_eval` fixes still pass because no static rule can see that they break the feature. Each rule closes one loophole and the model finds another. The lasting answer is tests that run the fixed code. Details in `docs/real_review.md`.

## Command-line tool

    python vulnfix.py scan test_vuln.py        # one file
    python vulnfix.py scan .                   # a folder (skips venv, data, hidden folders)
    python vulnfix.py scan . --json            # machine-readable; exit code 1 if anything is found
    python vulnfix.py fix myfile.py --model qwen2.5-coder:7b   # needs a running Ollama server

`scan` is light and needs no model. `fix` asks a model for a patch for each function that has a finding, re-checks it with the scanner and the static checks (`behavior_check.py`, `name_check.py`), and prints a diff. It never writes to your files. A "VERIFIED" fix is not proven safe or correct: review it and run your tests. The same pipeline (`fixer.py`) runs in the Kaggle notebook with a larger model. The Ollama backend is written against Ollama's chat API and has so far been tested only against a mock server.

### Demo of the fix command with a real model

On 7 functions (`test_vuln.py`, `examples/demo.py`) the pipeline gave 5 scanner-verified fixes, of which 3 are good by manual review. `eval` replaced by `ast.literal_eval` passed the scanner but cannot do arithmetic. See `docs/demo_review.md`. `examples/` contains deliberately vulnerable code, so `scan .` reports it on purpose.

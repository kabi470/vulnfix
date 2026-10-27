# vulnfix

A prototype that finds common vulnerabilities in Python code and fixes them automatically, built only with free and open-source tools.

## How it works

scan -> retrieve -> fix -> verify

1. **Scan:** `detector.py` uses Python's `ast` module to find SQL injection, command injection, `eval`/`exec`, unsafe `pickle`/`marshal`, and unsafe `yaml.load`.
2. **Retrieve:** TF-IDF search finds the most similar verified (vulnerable -> fixed) examples.
3. **Fix:** Qwen2.5-Coder-14B-Instruct (4-bit, Kaggle free T4 x2 GPUs) writes a fix, guided by those examples.
4. **Verify:** The fix is re-scanned. If the scanner still reports a problem, or functions were deleted, the model retries (up to 3 times) with the scanner's feedback.

## First results

Test: 15 held-out pairs from 78 verified pairs.

| Setup | Fixed and verified | Avg. attempts |
|---|---|---|
| With retrieval | 15 / 15 | 1.13 |
| Without retrieval | 13 / 15 | 1.47 |

## Limitations (please read)

- The test is small (15 cases) and uses a synthetic dataset (CyberNative/Code_Vulnerability_Security_DPO). The same scanner builds the verified pairs and checks the fixes.
- "Verified" means no known vulnerable pattern remains. Behavior is not tested. For example, one generated fix used `ast.Num`, which does not exist in Python 3.14.
- The dataset's own "fixes" are often incomplete: only 78 of 355 pairs passed verification.
- It covers few vulnerability types and handles one snippet at a time, not whole projects.

## Files

- `build_pairs.py` - builds vulnerable/fixed pairs from the dataset
- `detector.py` - the rule-based scanner
- `verify_pairs.py` - keeps only machine-verified pairs
- `analyze.py` - dataset statistics
- `notebook*.ipynb` - the Kaggle notebook with the LLM fix loop
- `results.txt` - raw results

## Run it

    pip install datasets scikit-learn
    python build_pairs.py
    python verify_pairs.py
    python detector.py yourfile.py

The LLM step runs in the Kaggle notebook (free GPU).

## Roadmap

- Behavior tests for generated fixes
- Command-line tool
- Real-world data (CVEfixes, GitHub Advisory Database)
- More vulnerability rules and a larger evaluation

Use only on code you own or are authorized to test.

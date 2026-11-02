# vulnfix

A research prototype that finds common vulnerabilities in Python code, asks an open-source LLM for a fix, and checks the fix before suggesting it. Built entirely with free tools: Kaggle's free GPUs, Hugging Face models and datasets, and open-source libraries.

It only makes suggestions. It never writes to your files, and a "verified" fix is not proven safe or correct: review it and run your tests. Use it only on code you own or are authorized to test.

## How it works

scan -> retrieve -> fix -> verify

1. **Scan** (`detector.py`, `rules_extra.py`): AST rules for SQL injection, command injection (`shell=True`, `os.system`, a command passed straight through, a program chosen by input), `eval`/`exec`, unsafe `pickle`/`marshal`/`yaml.load`, denylist Unpicklers, and dynamic imports or `getattr` on builtins.
2. **Retrieve**: TF-IDF finds the most similar verified (vulnerable -> fixed) examples from `clean_pairs.jsonl` (56 synthetic pairs).
3. **Fix** (`fixer.py`): Qwen2.5-Coder-14B-Instruct (4-bit) on Kaggle's free T4 x2 writes a minimal fix for each function that has a finding, with hints chosen by the kind of finding.
4. **Verify**: the fix must pass the scanner again, `behavior_check.py` (valid Python, no non-existent or removed standard-library APIs, visitor methods Python 3.14 never calls, same function names and arguments) and `name_check.py` (no invented names; standard-library imports are added automatically). If the user supplies tests (`behavior_tests.py`), the original and the fixed function are also run on them in a separate process. On failure the model retries with the problems listed.

## Results (read the caveats)

### Real CVE-fix functions (CVEfixes), 20 functions the detector flags

I read every output (nothing was executed) and judged whether the fix removes the problem and keeps the feature working.

| Run | Setup | Scanner-verified | Good after review |
|---|---|---|---|
| 1 | scanner only | 15 / 19 | 11 / 19 |
| 2 | + name check | 17 / 19 | 12 / 19 |
| 3 | + extra rules | 15 / 20 | 12 / 20 |
| final | + hints scoped to the finding, longer output limit, extraction fix | 17 / 20 | 14 / 20 |

The runs use slightly different function sets and differ by about one case, so read them as "roughly 60 to 70 percent". Per-case reviews are in `docs/real_review.md`.

### Seven demo functions (`test_vuln.py`, `examples/demo.py`)

All seven end with a fix that reads as good. `calc` (an `eval` replacement) passes 5 executed tests and `run` (a shell command) passes 2. Details: `docs/demo_review.md`.

### What I learned

- Scanner-only verification overstates success: it passed `eval` replaced by `ast.literal_eval` (which breaks the feature), an evaluator whose `visit` always raises, and a visitor method that Python 3.14 never calls.
- Each rule closes one loophole and the model finds another, so static rules alone do not scale. Tests that run the code catch what static checks cannot, but real library functions often cannot be run on their own.
- The model is reliable on well-known patterns (`yaml.safe_load`, argument lists instead of shell strings, `json` instead of `pickle`) and weak where a design is needed (a safe expression evaluator).
- Two failures were bugs in my own tool, found by reading outputs: a missing import when running tests, and code extraction that cut off generated code containing three backticks.

## Limitations

- **The 20 functions and the 7 demo functions were used while tuning the checks, so these numbers are optimistic.** A clean evaluation needs fresh functions.
- The review is by one person reading diffs, not by running the code.
- The retrieval pool is small and synthetic. About 27 percent of the human fixes in the data use names from outside the function, so a model that sees one function cannot reproduce them.
- Python only, one function at a time, a handful of vulnerability types. Module-level code gets no suggestion.
- `--tests` runs model-written code. It is not a sandbox: use a disposable environment (such as a Kaggle notebook) and harmless inputs.

## Usage

    pip install -r requirements.txt
    python vulnfix.py scan myfile.py          # a file or a folder; exit code 1 if anything is found
    python vulnfix.py scan . --json
    python vulnfix.py fix myfile.py --model qwen2.5-coder:7b          # needs a running Ollama server
    python vulnfix.py fix myfile.py --tests tests.json                # runs code: disposable environment only

The Ollama backend is written against Ollama's chat API and has only been tested against a mock server. The results above were produced in a Kaggle notebook (`notebook*.ipynb`) with the 14B model.

Test file format (JSON, keyed by top-level function name): `{"calc": [{"args": ["1+2"], "expect": 3}, {"args": ["1/0"], "raises": "ZeroDivisionError"}]}`

## Files

- `detector.py`, `rules_extra.py` - the scanner
- `behavior_check.py`, `name_check.py`, `behavior_tests.py` - the checks on a fix
- `fixer.py`, `vulnfix.py` - the pipeline and the command-line tool
- `build_pairs.py`, `verify_pairs.py`, `make_clean_pairs.py`, `analyze.py` - build and filter the synthetic pairs
- `build_real_pairs.py`, `show_examples.py` - extract real pairs from the CVEfixes database
- `docs/` - manual reviews; `results.txt` - raw numbers; `examples/` - deliberately vulnerable demo code and its tests

## Data and credits

- Synthetic pairs: the Hugging Face dataset `CyberNative/Code_Vulnerability_Security_DPO`.
- Real pairs: CVEfixes (Bhandari, Naseer, Moonen, PROMISE '21), licensed CC BY 4.0: https://doi.org/10.1145/3475960.3475985
- Model: Qwen2.5-Coder-14B-Instruct.

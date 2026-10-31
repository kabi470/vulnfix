# Review of the real-CVE test (with retrieval, 19 functions from 15 CVEs)

Scanner-verified: 15/19. Judged correct from reading the diffs (nothing executed): 11/19.

| # | CVE | Finding | Scanner | Review |
|---|---|---|---|---|
| 1 | CVE-2019-19010 | eval | pass | Wrong: `ast.literal_eval` removes the calculator feature |
| 2 | CVE-2018-7889 | pickle | fail | Correctly rejected |
| 3 | CVE-2021-27213 | yaml.load | fail | Correctly rejected (`FullLoader` is not safe) |
| 4 | CVE-2021-21433 | shell=True | pass | Good (arguments still reach the tool) |
| 5 | CVE-2017-2809 | yaml.load | pass | Good |
| 6 | CVE-2017-16618 | yaml.load | pass | Good |
| 7 | CVE-2021-21433 | shell=True | pass | Good (arguments still reach the tool) |
| 8 | CVE-2018-7889 | pickle | fail | Correctly rejected |
| 9 | CVE-2011-4104 | yaml.load | pass | Good |
| 10 | CVE-2018-8097 | eval | fail | Correctly rejected (bypassable) |
| 11 | CVE-2017-16618 | yaml.load | pass | Good |
| 12 | CVE-2017-16763 | yaml.load | pass | Good |
| 13 | CVE-2018-1000070 | eval | pass | Wrong: dotted `getattr` on builtins, still unsafe |
| 14 | CVE-2017-16667 | os.system | pass | Good (needs `import subprocess`) |
| 15 | CVE-2021-21386 | os.system | pass | Good (needs `import subprocess`) |
| 16 | CVE-2016-1000003 | pickle | pass | Incomplete: `RestrictedUnpickler` is never defined |
| 17 | CVE-2014-1932 | os.system | pass | Good (needs `import subprocess`; `check=True` changes failure behavior) |
| 18 | CVE-2017-16615 | yaml.load | pass | Good |
| 19 | CVE-2019-19010 | eval | pass | Wrong: `ast.literal_eval` removes the feature |

Takeaway: the scanner alone overstates success. Fixes that need real design (a safe evaluator, a restricted unpickler) are where the model fails.

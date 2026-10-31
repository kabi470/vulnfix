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

## Second run: with the name check (with retrieval, 19 functions)

Scanner-verified: 17/19. Judged good from reading the diffs (nothing executed): 12/19.

| # | CVE | Scanner | Review |
|---|---|---|---|
| 1 | CVE-2019-19010 | pass | Wrong: `ast.literal_eval` removes the feature |
| 2 | CVE-2018-7889 | pass | Wrong: Unpickler that blocks only os/subprocess is bypassable |
| 3 | CVE-2021-27213 | fail | Correctly rejected: one `yaml.load` left |
| 4 | CVE-2021-21433 | pass | Good |
| 5 | CVE-2017-2809 | pass | Good |
| 6 | CVE-2017-16618 | pass | Good |
| 7 | CVE-2021-21433 | pass | Good |
| 8 | CVE-2018-7889 | pass | Good for security; the writer of the file must also switch to JSON |
| 9 | CVE-2011-4104 | pass | Good |
| 10 | CVE-2018-8097 | fail | Correctly rejected: `eval` still bypassable |
| 11 | CVE-2017-16618 | pass | Good |
| 12 | CVE-2017-16763 | pass | Good |
| 13 | CVE-2018-1000070 | pass | Wrong: `__import__` on an input-chosen module name |
| 14 | CVE-2017-16667 | pass | Good |
| 15 | CVE-2021-21386 | pass | Good |
| 16 | CVE-2016-1000003 | pass | Wrong: Unpickler denylist is bypassable |
| 17 | CVE-2014-1932 | pass | Good (`check=True` changes failure behavior) |
| 18 | CVE-2017-16615 | pass | Good |
| 19 | CVE-2019-19010 | pass | Wrong: `ast.literal_eval` removes the feature |

The name check removed the undefined-name failure and added missing imports automatically. The five wrong fixes use patterns the scanner does not recognize, so scanner verification overstates success (17/19 vs 12/19). 12 vs 11 in the first run is one case, so I do not claim an improvement.

## Third run: with extra detector rules (with retrieval, 20 functions)

Scanner-verified: 15/20. Judged good from reading the diffs (nothing executed): 12/20 (13/20 if the sanitized import fix for CVE-2015-1326 is counted).

- Good (12): `yaml` SafeLoader fixes, shell commands turned into argument lists, `json` instead of `pickle` for CVE-2018-7889 (the writer of that file must switch too).
- Wrong but passing (3): `ast.literal_eval` replacing `eval` twice (CVE-2019-19010, breaks the feature), and CVE-2018-1000070 rewritten to `getattr(__import__('builtins'), ...)`, which dodged the new getattr rule and still breaks the feature.
- Correctly rejected (4): two denylist/permissive Unpicklers (CVE-2018-7889, CVE-2016-1000003; the second allows all of `builtins`), one `yaml.load` left in CVE-2021-27213, and `eval` with empty builtins (CVE-2018-8097).
- Probably good but rejected (1): CVE-2015-1326, where the module name is sanitized before `importlib.import_module`. The dynamic-import rule cannot tell sanitized input from raw input.

Rule limitations: the Unpickler rule checks only the shape of `find_class`, so it cannot tell a denylist from an allowlist (it rejected CVE-2016-1000003 for the wrong reason). The getattr rule was evaded by obtaining `builtins` through `__import__`.

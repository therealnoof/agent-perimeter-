# Test log

One line per sign-off. A demo is never given from a commit without an entry.

| Date | Commit | Host | `make test` | Procedures | Result | Ran by |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-04 | (this commit) | Linux 6.18 container, root, Go 1.24.7, Python 3.13 | green, -race, 0 skips | M-1 to M-8 | all pass | Claude (build session) |
| 2026-11-05 | 8e8dcf7 | Ubuntu 24.04 (ip-10-1-1-4), root, home lab | pending | S-1..S-3 | S-3 doc had an un-pasteable `<file>` placeholder; home dir 750 blocked the worker (fixed with `chmod o+x`). Both fixed in docs. | Noof |

# Test log

One line per sign-off. A demo is never given from a commit without an entry.

| Date | Commit | Host | `make test` | Procedures | Result | Ran by |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-04 | (this commit) | Linux 6.18 container, root, Go 1.24.7, Python 3.13 | green, -race, 0 skips | M-1 to M-8 | all pass | Claude (build session) |
| 2026-11-05 | 8e8dcf7 | Ubuntu 24.04 (ip-10-1-1-4), root, home lab, worker as perimeter-worker | green | S-1..S-4 (= M-1, M-3, M-5, M-6) | all pass. Two doc defects found and fixed in 00dacd0: `<file>` placeholder in S-3; 750 home dir blocked the worker. **Week 1 signed off on a real host.** | Noof |

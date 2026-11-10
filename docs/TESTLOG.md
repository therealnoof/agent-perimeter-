# Test log

One line per sign-off. A demo is never given from a commit without an entry.

| Date | Commit | Host | `make test` | Procedures | Result | Ran by |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-04 | (this commit) | Linux 6.18 container, root, Go 1.24.7, Python 3.13 | green, -race, 0 skips | M-1 to M-8 | all pass | Claude (build session) |
| 2026-11-05 | 8e8dcf7 | Ubuntu 24.04 (ip-10-1-1-4), root, home lab, worker as perimeter-worker | green | S-1..S-4 (= M-1, M-3, M-5, M-6) | all pass. Two doc defects found and fixed in 00dacd0: `<file>` placeholder in S-3; 750 home dir blocked the worker. **Week 1 signed off on a real host.** | Noof |
| 2026-11-10 | 5820909 | Ubuntu 24.04 (ip-10-1-1-4), root, Go 1.26 | green, -race | `make demo-week2`, chain 18 records intact | Staged exfiltration sequence correct: clean update allowed, confidential read raises taint to 8, same update → approve (sensitivity_floor), #general → deny (no_permit_matched), #triage-internal → approve. **Week 2 signed off.** | Noof |
| 2026-11-10 | da045f9 | Ubuntu 24.04 (ip-10-1-1-4), root, Go 1.26 | green, -race, 95 tests | `make demo-week3` interactive; chain 30 records intact | Four credentials released against four distinct tokens; four real calls at the mock; OPS-2 close executed; confidential read raised taint to 8; same update then prompted; timeout → `approval_timeout`; `j`/`d` on the Slack prompt; injected #general never prompted. First run found the stdin-reader bug and static taint (fixed in da045f9). **Week 3 signed off.** | Noof |
| 2026-11-10 | 7514784 | Ubuntu 24.04 (ip-10-1-1-4), root, Go 1.26 | green | `make demo-week3` + `make auditview` over HTTPS :9800 | Dashboard live during the demo; trace timeline, taint, approvals, releases, profile all populated from the real chain. Tracing fields compiled and populated first try. **3.5 (telemetry + dashboard) signed off; more telemetry to come.** | Noof |

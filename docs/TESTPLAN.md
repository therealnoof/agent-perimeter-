# Test plan

What "tested" means for this PoC, layer by layer, and what has to be true before each phase is called done. Requirement IDs (G-, P-, C-, D-, E-, A-) are from the PRD; the three added by the build plan are P-6, P-7 and G-8.

The plan has four layers. Each answers a different question, and a change is not done until every layer that applies is green.

| Layer | Runs with | Question | Today |
| --- | --- | --- | --- |
| L1 Unit | `make test` (`go test -race ./...`) | Does each package keep its `doc.go` promise? | 95 tests, green |
| L2 Policy | `go test ./internal/policy/` | Does each attack class resolve the way the attack table says, against the real signed `.cedar` files? | 4 attack-class files + engine properties, green |
| L3 Integrity | Manual procedures below; automated in `harness/integrity_test.go` **(week 6)** | Does the binary itself hold: signature, chain, socket auth, kill switch, no forbidden imports? | 6 manual procedures, 1 automated |
| L4 Red team | `make redteam` **(week 6)** | With a real governor and a canned worker, does every adversarial case stop before execution? | Not built; the stub worker exercises 5 of the 16 cases informally |

## L1: Unit tests

Run on every change. Must be green with the race detector on. No test may be skipped on the reference host (Ubuntu 24.04, run as root); tests that need root print `SKIP` elsewhere and that is acceptable for development, not for sign-off.

| Requirement | Package | Test | What it proves |
| --- | --- | --- | --- |
| G-1 | manifest | `TestFlippedByteInBody`, `TestFlippedByteInSignature`, `TestMissingSignature`, `TestWrongKey` | Any change to the manifest or signature, or the wrong key, refuses to load |
| G-1 | manifest | `TestUnknownFieldRejected`, `TestBadKindRejected`, `TestSensitivityFloorRange` | A correctly signed but malformed manifest is still refused |
| G-2 | socket | `TestSpawnInheritsFD3` | A real child finds the socket on fd 3 and the governor sees EOF when it exits |
| G-3 | socket | `TestWrongUIDRejected`, `TestOverflowUIDRejected` | A sender with the wrong UID, or the overflow UID, is rejected before the frame body is read |
| G-3 | socket | `TestSpawnWithPrivilegeDrop` (root only) | After a real `setuid`, the kernel-attached sender UID is what is checked, and it matches or rejects correctly |
| G-3 | socket | `TestOversizedFrameRejected`, `TestZeroFrameRejected` | A hostile length prefix is refused before allocation |
| G-4 | schema | `TestInvalidArgs` (13 cases), `TestParseRequest` (7 cases) | Extra fields, wrong types, bounds, enums, patterns, oversize, trailing data all rejected |
| G-4 | schema | `TestCompileRejectsUnknownKeyword` | A schema using an unimplemented keyword fails at manifest load, not silently at request time |
| G-5 | agentd | `TestNoForbiddenImports` | No file in the binary imports `net`, `net/http`, TLS, unsafe, plugin, any third-party module, or anything named like an LLM SDK |
| G-7 | taskstate | `TestCallCounts`, `TestConcurrentCounts`, `TestForget` | Call counts are per task and per tool, exact under concurrency |
| G-7, D-2 | taskstate | `TestTaintNeverFalls` | The taint high-water mark only rises |
| G-8 | policy | `TestDelegationDepthDenied` | Depth over the manifest ceiling is denied before any other rule |
| P-2 | policy | `TestInputCarriesNoAgentText` | By reflection: `policy.Input` has no field that could carry agent-authored text |
| P-2 | policy | `TestDeterministic` | Identical structural facts produce identical decisions |
| P-3 | policy | `TestAllowHappyPath`, `TestUnknownToolDenied` | Three verdicts, each with a rule id |
| P-6 | policy | `TestSensitivityFloorPromotes` | `allow` becomes `approve` at the floor, not below it |
| P-7 | policy | `TestFreeformOutboundNeedsHuman` | Freeform + outbound is `approve`; freeform inbound is not |
| C-3 | policy | `TestCallCapDenied` | The cap denies at N, allows at N-1 |
| A-1 | audit | `TestVerifyCleanChain`, `TestVerifyDetectsEditedByte`, `TestVerifyDetectsDeletedRecord` | An edited or deleted record is named by sequence number |
| A-1 | audit | `TestReopenContinuesChain`, `TestReopenRefusesBrokenChain` | A valid chain is extended; a broken one is never extended |
| C-1 | tokens | `TestReplayWithDifferentArgsFails`, `TestSingleUse`, `TestExpired` | A token is bound to tool, target and args hash; is single-use; dies at TTL |
| C-2 | tokens | `TestUnknownGovernor`, `TestTamperedBody`, `TestMalformed` | Only the governor's key verifies; any edit breaks the signature |
| C-3 | tokens | `TestSeenSetPrunes` | The replay set is bounded |
| A-3 | approval | `TestTimeoutDenies`, `TestEOFDenies` | Silence and a closed terminal are both deny, never allow |
| A-3 | approval | `TestJustificationHiddenUntilRequested` | Agent text is shown only on `j`, labelled untrusted |
| A-3 | approval | `TestSequentialPromptsOnOneCLI`, `TestStaleInputIsDrained` | A second prompt gets its own keystrokes; input typed before a prompt cannot answer it |
| G-4, C-1 | canon | `TestKeyOrderAndWhitespaceDoNotMatter`, `TestValuesMatter` | Governor and executor hash identical args identically |

**Adding a test.** Every new requirement row in the PRD gets a row here and at least one test whose name a reviewer can grep for. A `doc.go` "must never" line without a test that would catch it is a gap.

## L2: Policy tests

`internal/policy` tests load the repository's real `policies/*.cedar` files through the signed `Load` path (signing them with a throwaway key in a temp dir), so a policy edit that breaks an attack case fails `make test`. One file per attack class, plus engine-property tests. This is what `opa test` would have been.

| File | Attack class | Cases |
| --- | --- | --- |
| `attack_injection_test.go` | Prompt injection | Unpermitted channel → deny (`base.default_deny`), permitted channel → approve, same pair in one test; retry with "longer justification" is the identical decision; client cannot lower taint |
| `attack_exfiltration_test.go` | Exfiltration | Taint at/over `sensitivity_floor` → approve, under → allow; tool with no floor ignores taint; freeform outbound → approve; freeform inbound → allow |
| `attack_misuse_test.go` | Tool misuse | Unknown tool → deny; call cap at N → deny, N-1 → allow; `max_calls` 0 is uncapped; happy path → allow with rule id |
| `attack_escalation_test.go` | Privilege escalation | Delegation depth → deny in Go; same rule denies in Cedar alone (`evaluate`); tool outside role → deny; role file cannot override base |
| `policy_test.go` | Engine properties | `Input` carries no agent text (reflection); deterministic; unsigned / tampered / empty policy dir refused; forbid always wins; `@verdict("approve")` semantics incl. soft+hard = deny; evaluation error fails closed |

Exit criterion: `go test ./internal/policy/` green, and every PRD attack case that policy can decide (as opposed to the sandbox or executors) has a row above.

**Found by this layer:** on the first real build, `TestInjection_PublicChannelDenied` caught the engine returning `approve` for a target no policy permitted. Fixed in `5820909`.

## L3: Integrity procedures

These test the binary rather than policy. Run them on the reference host after every deploy and before every demo. Each takes under a minute. They become `harness/integrity_test.go` in week 6; until then, the operator runs them by hand and records the result.

### M-1: Tampered manifest is refused (G-1)

```bash
cp manifests/stub-agent.json /tmp/m.json && cp manifests/stub-agent.json.sig /tmp/m.json.sig
sed -i 's/"max_calls_per_task": 3/"max_calls_per_task": 300/' /tmp/m.json
bin/agentd run -manifest /tmp/m.json -pubkey keys/manifest-signing.pub -audit /tmp/x.jsonl -- true
```
**Pass:** exits 1 with `refusing to start: manifest: signature does not verify`. `/tmp/x.jsonl` is not created.

### M-2: Missing signature is refused (G-1)

```bash
rm /tmp/m.json.sig
bin/agentd run -manifest /tmp/m.json -pubkey keys/manifest-signing.pub -audit /tmp/x.jsonl -- true
```
**Pass:** `refusing to start: manifest: signature file missing`.

### M-3: Wrong sender UID is rejected and the worker is killed (G-3)

```bash
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/wrong.jsonl -worker-uid 4242 -- python3 agents/stub_worker.py
```
**Pass:** returns within 2 seconds (no hang); the chain's second-to-last record is `event: stop` with detail beginning `request loop error, worker killed: socket: sender UID does not match`. No `verdict` records exist.

### M-4: Privilege-dropped worker is accepted (G-3)

```bash
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/ok.jsonl -worker-user perimeter-worker -- python3 agents/stub_worker.py
grep -c '"event":"verdict"' /tmp/ok.jsonl
```
**Pass:** worker prints eight lines; grep prints `7`; `bin/agentd verify -audit /tmp/ok.jsonl` says `ok: 13 records`.

### M-5: Audit tamper is caught at the right record (A-1)

```bash
cp /tmp/ok.jsonl /tmp/t.jsonl && sed -i '4s/"allow"/"deny"/' /tmp/t.jsonl
bin/agentd verify -audit /tmp/t.jsonl
```
**Pass:** `chain broken at record 5: prev_hash does not match previous record`. (Record 4 was edited; record 5 is the first whose link fails.)

### M-6: Kill switch stops a running worker (G-6)

```bash
mkdir -p /tmp/kill && rm -f /tmp/kill/*
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/kill.jsonl -kill-dir /tmp/kill -worker-user perimeter-worker \
  -- python3 -c 'import time; time.sleep(60)' &
sleep 1; touch /tmp/kill/STOP; time wait
grep -o '"event":"kill","detail":"[^"]*"' /tmp/kill.jsonl
```
**Pass:** `wait` returns in well under a second; the chain has `"event":"kill","detail":"kill file STOP"` followed by `stop`.

### M-7: Same facts, same verdict regardless of justification (P-2)

Run M-4, then:
```bash
grep '"tool":"vault_lookup"' /tmp/ok.jsonl | grep -o '"verdict":"[a-z]*","rule_fired":"[^"]*".*"args_hash":"[0-9a-f]*"' | sort -u | wc -l
```
**Pass:** prints `1`. The stub worker calls `vault_lookup` twice, once with an empty justification and once with a 700-character one; both records are identical in verdict, rule and args hash.

### M-9: Tampered policy is refused (P-1)

```bash
cp -r policies /tmp/pol && sed -i 's/forbid (principal, action, resource)/permit (principal, action, resource)/' /tmp/pol/base.cedar
bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub -policies /tmp/pol -audit /tmp/x.jsonl -- true
```
**Pass:** `refusing to start: policy: signature does not verify: /tmp/pol/base.cedar`. The classic attack, a forbid flipped to a permit after signing, never loads.

### M-10: Token replay and binding at the executor (C-1, C-2)

The integration script in the build session (`itest.sh`) drives `executor` directly with tokens minted from a governor key, bypassing `agentd`, and is the reference for these. On the host, with `make services-up` running:

```bash
# a token minted by agentd is single-use: the sidecar refuses the second presentation
bin/agentd run ... -approver deny -- python3 agents/stub_worker.py --week3   # any run
grep -c RELEASED run/secretsd.log; grep -c REFUSED run/secretsd.log
```
**Pass:** every `RELEASED` line has a distinct `jti`; no two calls share a token. Executor records in the chain carry the same `token_id` values.

### M-11: Approval timeout and justification gating (A-3)

Run `make demo-week3`, let the first prompt time out, press `j` then `d` on the second.
**Pass:** first worker line after the prompt reads `DENIED -> denied: approval_timeout`; the audit has `"event":"approval"` with `reason_code: approval_timeout`; the second prompt's justification appears only after `j`, under the `untrusted` label; the `approval` record carries `approver_id` = your login (or `SUDO_USER`).

### M-12: Governor never holds a secret (E-2)

```bash
grep -rn "secret" cmd/agentd/*.go | grep -v "secrets-sock\|secretsSock\|// \|secretsd"
```
**Pass:** nothing. The governor's only knowledge of secrets is the sidecar socket path it passes to executors. `strings bin/agentd | grep -c jira-demo-token` prints `0`.

### M-8: Worker environment carries nothing (E-2 precursor)

```bash
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/env.jsonl -worker-user perimeter-worker -- env
```
**Pass:** exactly three lines: `PATH`, `PERIMETER_FD=3`, `PYTHONUNBUFFERED=1`. No `HOME`, no `VAULT_*`, no `*_API_KEY`, no proxy variables.

### M-13: Worker cannot reach the network from inside the sandbox (E-3, E-4)

`make demo-week4` runs the worker's own check: step 6 runs `curl http://127.0.0.1:9811/log` from inside the worker.
**Pass:** the worker prints `direct curl to mock: blocked (...)`; the mock's `/log` shows no request without an `X-Perimeter-Call` header. **Fail:** `REACHED THE NETWORK`.

### M-14: Executor reaches a service only through the proxy, only for listed hosts (E-4)

```bash
grep '"event":"refused"' run/egress-proxy.log
```
after a run with `-mock-addr localhost:9811` (not on any `egress_hosts` list, which says `127.0.0.1:9811`).
**Pass:** one `refused` line per attempted call naming tool, task, token id and `localhost:9811`; the executor record in the audit shows exit 4; the mock log is empty. Same run with `-mock-addr 127.0.0.1:9811`: `connect` lines and the calls succeed.

### M-15: Credential-shaped outbound text is denied before any executor runs (D-4)

Steps 2 and 3 of `--week4`.
**Pass:** audit shows `verdict deny` with rule `egress.active` for the placeholder and `egress.high_confidence` for the AWS key shape; no `executor` record for either; the `Detail` of the verdict record names a JSON path (`$.text`), never the value. `grep -c AKIAIOSFODNN7EXAMPLE run/audit4.jsonl` prints `0`.

### M-16: Redacted value never leaves the governor without a human (D-4)

**Pass:** the worker's `jira_read OPS-1` result contains `[redacted:tok_...]`; `detokenize` produces an `approval` record; answering `d` yields `approval_denied` and the worker never sees the summary. `grep -c "Printer on floor 3" run/audit4.jsonl` prints `0` in both cases (the value is not written to the chain).

### M-17: Sandbox filesystem view (E-2)

Step 7 of `--week4` prints `can see <path>: False` for `run/governor.key`, `keys/private`, `/etc/passwd` and `/root`.
**Pass:** all four `False`. Outside the sandbox (`-sandbox none`) at least the first two are `True`, which is the point.

### M-18: seccomp filter is installed and enforces (E-2)

`go test ./internal/sandbox/ -run TestSeccompEnforces -v` installs the compiled filter in a child process and calls `unshare(2)`.
**Pass:** `denied=EPERM allowed=ok`. On the host, additionally: `grep Seccomp /proc/$(pgrep -f stub_worker.py)/status` during a `--week4` run prints `Seccomp: 2` (filter mode).

## L4: Red-team harness (week 6)

The harness is a Go test that starts a real `agentd` per case, drives a canned worker through the steps in a YAML file, and asserts on the audit chain. Cases live in `harness/cases/`; adding a case is adding a file. Every case in the PRD's attack table (16) plus the three from the build plan (19) must be present.

Pass criterion for the suite: every case's chain shows `deny` or `approve` for the adversarial step, and the count of `executor` records for that step is zero. Cases designed to reach an executor and be rejected there (token replay) count as blocked when the `executor` record shows a non-zero exit and no side effect in the mock.

Until week 6, the stub worker covers these informally: unknown tool, call cap, smuggled field, freeform outbound, justification retry. The other 14 cases need components from weeks 3 to 5.

## Phase exit criteria

A phase is done when every line in its block is true on the reference host.

**Week 1 — Skeleton** (current)
- [x] `make test` green with `-race`, zero skips when run as root
- [x] M-1 through M-8 pass as written
- [x] `make demo-week1` ends with `ok: 13 records, chain intact`
- [x] `TestNoForbiddenImports` covers `cmd/agentd` and all of `internal/`
- [x] `scripts/preflight.sh` passes on the reference host

**Week 2 — Policy** (done 2026-11-10; Cedar instead of OPA, see PLAN.md)
- [x] `internal/policy.Decide` evaluates `policies/*.cedar` via cedar-go; `Input`/`Decision` types unchanged
- [x] Policies are Ed25519-signed and verified at startup like the manifest
- [x] L2 suite: four attack-class files + engine properties, green on the reference host
- [x] Taint is raised by the governor from the tool's declared `result_sensitivity`; shown in `make demo-week2`
- [x] M-7 still passes with Cedar in the loop (`TestInjection_JustificationCannotExist` + stub worker week-1 sequence)
- [x] `TestNoForbiddenImports` allows exactly `github.com/cedar-policy/cedar-go` under `internal/policy` and nowhere else
- [x] New procedure M-9: tampered policy refused

**Week 3 — Execution** (done 2026-11-10; stdlib token instead of Biscuit, sidecar instead of in-governor Vault, see PLAN.md)
- [x] Per-execution token bound to tool, target, args hash, 5 s TTL, single-use; `TestReplayWithDifferentArgsFails`, `TestSingleUse`
- [x] Executor verifies offline, re-hashes the args it received, exits 2 on a bad token; the exit code is an `executor` record
- [x] Credentials released by `secretsd` only against a valid token; Vault KV v2 over AppRole or a file; the governor has no backend credential (M-12)
- [x] Approval CLI shows tool, target, taint, rule, args hash; 60 s → `approval_timeout`; justification behind `j`; `TestTimeoutDenies`, `TestJustificationHiddenUntilRequested`
- [x] M-10 replay, M-11 approval, M-12 governor-holds-no-secret
- [x] Taint from the source system's own classification, floored by the manifest (D-2 refinement)

**Week 4 — Perimeter**
- [x] Worker runs under bubblewrap with seccomp, no capabilities, read-only root, no network interfaces (`-sandbox bwrap`; M-13, M-17, M-18)
- [x] Executors have no network interfaces; their only route is the egress proxy on a Unix socket; a host off the tool's `egress_hosts` is refused and logged with tool, task, token id and host (M-14; design changed from iptables, see PLAN deviations)
- [x] Egress scan: AWS-key pattern in outbound args → `deny`, rule `egress.high_confidence`; governor-issued placeholder or token id → `deny`, rule `egress.active`; weak signal → `approve` (`TestExfil_EgressScanLevels`, M-15)
- [x] Ingress redaction with `detokenize` always human-gated (M-16)
- [ ] Host sign-off of M-13..M-18 recorded in TESTLOG

**Week 5 — Agents**
- [ ] Three agents run five benign tasks each through the governor against the mocks: 15/15 complete
- [ ] One executor family runs behind the MCP stdio bridge with identical verdicts
- [ ] Swapping an agent changes only its manifest and run script

**Week 6 — Red team and demo**
- [ ] `make redteam`: 19/19 cases blocked, zero executions, printed per requirement ID
- [ ] M-1 through M-11 automated in `harness/integrity_test.go`
- [ ] Benchmark: p95 in-process overhead under 5 ms over 10,000 requests
- [ ] `make demo` runs the 15-minute script clean three times in a row
- [ ] `bin/agentd verify` clean after every demo run

## Recording results

Keep a one-line entry per sign-off in `docs/TESTLOG.md`: date, commit, host, `make test` result, M-procedures run and their outcome, who ran them. A demo should never be given from a commit that has no entry.

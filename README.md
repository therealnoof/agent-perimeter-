# agent-perimeter

Per-action authorization for AI agents, enforced by a Go governor the agent cannot reach.

`agentd` sits between an untrusted agent process and every tool it wants to call. The agent proposes an action over a single inherited socket; the governor validates it, decides against signed policy, runs it (or not), and records the outcome in a hash-chained audit log. The agent holds no credentials, has no network, and cannot influence the decision with anything it says.

**Status: week 1 of 6.** The governor skeleton is complete and tested. Not yet demo-ready for a customer; see [`docs/TESTPLAN.md`](docs/TESTPLAN.md) for exactly what is proven and what is not.

- [`docs/DEPLOY.md`](docs/DEPLOY.md) — fresh-host install, worker account, signing, run, smoke test
- [`docs/TESTPLAN.md`](docs/TESTPLAN.md) — four test layers, manual integrity procedures, per-phase exit criteria
- [`docs/PLAN.md`](docs/PLAN.md) — link to the living build plan and the deviations log

## What works today

| Requirement | Mechanism | Proof |
| --- | --- | --- |
| G-1 signed manifest | Ed25519 detached signature verified before parsing | `TestFlippedByteInBody`, `TestMissingSignature` |
| G-2 one channel | `socketpair(2)`, worker end on fd 3, no filesystem socket | `TestSpawnInheritsFD3` |
| G-3 peer auth | Kernel `SCM_CREDENTIALS` sender UID on every message, overflow UID rejected; worker dropped to its own user with `-worker-user` | `TestWrongUIDRejected`, `TestSpawnWithPrivilegeDrop` |
| G-4 fixed schema | `{tool, args, task_id, justification}` + per-tool args schema, unknown fields rejected | `TestInvalidArgs` |
| G-5 no LLM, no network | Import-grep test over every file in the binary | `TestNoForbiddenImports` |
| G-6 kill switch | `SIGUSR1` or a file in `-kill-dir`, process group killed | `make demo-week1` variant below |
| G-7 governor-owned state | Call counts, taint mark, delegation depth in `internal/taskstate` | `TestConcurrentCounts`, `TestTaintNeverFalls` |
| G-8 delegation depth | Checked before policy | `TestDelegationDepthDenied` |
| P-2 no agent text in policy | `policy.Input` has no justification field | `TestInputCarriesNoAgentText` (reflection) |
| P-6 sensitivity floor | `allow` → `approve` when taint ≥ floor | `TestSensitivityFloorPromotes` |
| P-7 freeform outbound | Needs a human unless explicitly allowed | `TestFreeformOutboundNeedsHuman` |
| A-1 hash chain | SHA-256 of previous record on every line; `agentd verify` | `TestVerifyDetectsEditedByte` |
| A-4 structured refusal | `{verdict, reason_code, rule}` and nothing else | `stub_worker.py` output |
| A-5 three identities | `originating_user`, `agent_role`, `approver_id` on every record | any audit line |

Not yet: OPA/Rego (week 2), Biscuit tokens and real executors (week 3), sandbox and egress proxy (week 4), real agents (week 5), red-team harness (week 6).

## Design decision: standard library only

The governor imports nothing outside the Go standard library. Ed25519, `socketpair`, `SCM_CREDENTIALS`, SHA-256 and JSON are all in stdlib, and the request validator is a 200-line subset of JSON Schema written here rather than a dependency. For a component whose whole job is to be the trust anchor, "nothing to audit but this repo" is worth more than a richer schema language. `TestNoForbiddenImports` fails if anyone adds a module import to the binary. Manifests are JSON for the same reason.

Week 2's OPA embed is the one planned exception and is confined to `internal/policy`.

## Quick start

```bash
make build            # bin/agentd, bin/sign-manifest
make test             # go test -race ./...
make gen-key          # once: keys/manifest-signing.pub (committed) + private key (gitignored)
make sign-manifests   # writes manifests/*.json.sig
make demo-week1       # runs agentd with the scripted stub worker, prints the chain, verifies it
```

`make demo-week1` output ends with the stub worker hitting every verdict class:

```
[worker] echo #1: ALLOWED -> {...}
[worker] echo #4 (over cap): DENIED   -> denied: call_cap_exceeded (misuse.call_cap)
[worker] vault_lookup (not in manifest): DENIED   -> denied: tool_not_in_manifest (base.unknown_tool)
[worker] echo with smuggled field: DENIED   -> denied: args_invalid ()
[worker] slack_post (freeform outbound): PENDING  -> pending human approval: freeform_outbound (flow.freeform_outbound)
[worker] vault_lookup with long justification: DENIED   -> denied: tool_not_in_manifest (base.unknown_tool)
...
ok: 13 records, chain intact
```

The last two `vault_lookup` records in the chain have the same `args_hash` and the same verdict. The second carried a ten-paragraph justification. That is requirement P-2 in one line of output.

Tamper check:

```bash
sed -i '6s/"allow"/"deny"/' run/audit.jsonl
bin/agentd verify -audit run/audit.jsonl
# agentd: audit: chain broken at record 7: prev_hash does not match previous record
```

Kill switch:

```bash
mkdir -p run/kill
bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit run/kill.jsonl -kill-dir run/kill -- python3 -c 'import time; time.sleep(30)' &
touch run/kill/STOP     # worker is gone within 100 ms; audit records "kill file STOP"
```

## Layout

```
cmd/agentd/            governor: startup, request loop, kill switch, verify subcommand
cmd/sign-manifest/     operator tool: gen-key, sign, verify (offline)
internal/manifest/     signed role description; refuses bad or missing signature
internal/socket/       socketpair, fd 3 inheritance, SCM_CREDENTIALS sender check, length-prefixed frames
internal/schema/       fixed request frame + JSON Schema subset for tool args
internal/policy/       structural-facts-only decision; week 2 swaps in OPA
internal/taskstate/    call counts, taint high-water mark, delegation depth
internal/audit/        hash-chained JSONL writer and verifier
client/perimeter_client/  Python: propose(tool, args, task_id) -> result | Denied | PendingApproval
agents/stub_worker.py  scripted worker that exercises every verdict path
manifests/             signed role manifests (JSON + .sig)
keys/                  manifest signing PUBLIC key; private key is gitignored
```

Every Go package has a `doc.go` that says what it owns and what it must never do.

## Requirements

Linux (uses `socketpair`, `SCM_CREDENTIALS`, process groups), Go 1.23+, Python 3.10+ for the client and worker. No network needed after `git clone`.

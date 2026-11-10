# Architecture, as built (week 1)

Six diagrams, each answering one question about how `agentd` works today. They describe the code in this repository at this commit, not the plan. Where a part is a stand-in for something later, the diagram says so.

1. [What the pieces are and where the trust boundary sits](#1-components-and-trust-boundary)
2. [What happens when `agentd` starts](#2-startup-sequence)
3. [What happens on every tool call](#3-request-flow)
4. [How a verdict is reached](#4-policy-decision)
5. [What the audit chain looks like and why edits are caught](#5-audit-chain)
6. [How the governor stops](#6-shutdown-and-kill-switch)

---

## 1. Components and trust boundary

The agent lives in an untrusted process. Its only way to affect the world is a single socket to the governor. Everything that decides, signs, or records lives on the governor's side of that line.

```mermaid
flowchart LR
    subgraph OP["Operator (offline)"]
        KEY["Ed25519 signing key<br/>(private, never on the host)"]
        MAN["manifests/*.json<br/>role, tools, schemas, floors"]
        KEY -- "sign-manifest sign" --> SIG["manifests/*.json.sig"]
    end

    subgraph HOST["Host"]
        subgraph GOV["agentd (root, Go, stdlib only)"]
            direction TB
            M["internal/manifest<br/>verify sig, then parse"]
            S["internal/socket<br/>socketpair, SCM_CREDENTIALS"]
            SC["internal/schema<br/>frame + per-tool args"]
            TS["internal/taskstate<br/>call counts, taint HWM,<br/>delegation depth"]
            P["internal/policy<br/>Cedar: signed *.cedar<br/>Decide(Input) → Decision"]
            EX["execute()<br/>week-1 stub: echoes args"]
            A["internal/audit<br/>hash-chained JSONL"]
            KS["kill switch goroutine<br/>SIGUSR1 or file in -kill-dir"]
        end

        subgraph WK["Worker (perimeter-worker uid, no env, no creds)"]
            direction TB
            AG["Agent code<br/>(stub_worker.py today)"]
            CL["perimeter_client<br/>propose(tool, args, task_id)"]
            AG --> CL
        end

        PUB["keys/manifest-signing.pub"]
        LOG[("audit/*.jsonl<br/>mode 700, not readable by worker")]
        KD[("-kill-dir")]
    end

    MAN & SIG -. "pulled to host" .-> M
    PUB --> M
    CL <== "fd 3: socketpair<br/>length-prefixed JSON frames" ==> S
    S --> SC --> P
    TS <--> P
    P --> EX
    M -. "tools, schemas, floors" .-> SC & P
    S & SC & P & EX & KS --> A --> LOG
    KD -. "watched" .-> KS
    KS -- "SIGKILL process group" --> WK

    classDef trusted fill:#e8f1fb,stroke:#2b6cb0,stroke-width:1.5px,color:#111;
    classDef untrusted fill:#fdecea,stroke:#c53030,stroke-width:1.5px,stroke-dasharray:4 3,color:#111;
    classDef store fill:#f3f4f6,stroke:#4b5563,color:#111;
    class GOV,OP trusted;
    class WK untrusted;
    class LOG,KD,PUB store;
```

**Reading it.** Solid double arrow: the only channel the worker has. Dotted arrows: configuration the governor reads at startup. The worker has no network, no environment variables beyond `PATH`, no credentials, no view of the audit log, and no way to reach anything on the right side except by asking the governor over fd 3.

**Stand-ins today.** `execute()` echoes the arguments back; week 3 replaces it with executors that hold a per-call token and a just-in-time credential. After a tool runs, the governor raises the task's taint mark to the tool's declared `result_sensitivity`, so §4's `taint_hwm` has a real source.

---

## 2. Startup sequence

Nothing is spawned until the manifest proves it was signed by the operator's key. A signature failure is a refusal to start, not a warning.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator shell
    participant G as agentd (root)
    participant FS as Disk
    participant W as Worker process

    Op->>G: agentd run -manifest M -pubkey K -audit L -worker-user U -- CMD
    G->>FS: read K (hex Ed25519 public key)
    G->>FS: read M and M.sig
    G->>G: ed25519.Verify(K, bytes(M), sig)
    alt signature invalid or missing
        G-->>Op: "refusing to start: manifest: signature …" (exit 1)
    end
    G->>G: parse M strictly (unknown fields = error)
    G->>G: compile every tool's args_schema (bad schema = refuse)
    G->>G: user.Lookup(U) → uid, gid (refuse uid 0)
    G->>FS: open or verify-and-continue audit chain L
    G->>FS: append {event: start}
    G->>G: socketpair(AF_UNIX, SOCK_STREAM) + setsockopt(SO_PASSCRED)
    G->>W: fork+exec CMD with fd 3 = worker end, setuid/setgid U,<br/>own process group, env = PATH + PERIMETER_FD only
    G->>G: close worker end in own process
    G->>G: start kill-switch goroutine (SIGUSR1, -kill-dir poll 50 ms)
    G->>G: start request loop goroutine
    Note over G,W: Governor now serves frames until EOF or kill
```

**Why the order matters.** Verify before parse (step 4 before 5): the parser only ever sees bytes the operator signed. Compile schemas before spawn (7 before 11): a bad manifest fails at startup, never on the first request. Close the worker end (12): otherwise the governor would never see EOF when the worker dies.

---

## 3. Request flow

One frame in, one frame out. Every box on the left side is a check that can end the request before anything executes; the order is fixed and each rejection is recorded.

```mermaid
flowchart TD
    R0([Worker writes frame on fd 3]) --> R1

    R1["ReadFrame<br/>recvmsg with SCM_CREDENTIALS"]
    R1 --> C1{"sender uid ==<br/>worker uid?<br/>(and ≠ 65534)"}
    C1 -- no --> X1["audit: reject socket_auth<br/>kill worker group, stop"]
    C1 -- yes --> C2{"length prefix<br/>0 < n ≤ 256 KiB?"}
    C2 -- no --> X2["audit: reject bad_frame<br/>reply deny: bad_frame"]
    C2 -- yes --> R2["ParseRequest<br/>{tool, args, task_id, justification}<br/>unknown field or oversize → reject"]
    R2 -- invalid --> X3["audit: reject schema<br/>reply deny: schema_invalid"]
    R2 -- ok --> R3["args_hash = SHA-256(canonical args)"]
    R3 --> C3{"tool in<br/>manifest?"}
    C3 -- yes --> R4["Validate args against<br/>tool's compiled schema"]
    R4 -- invalid --> X4["audit: reject schema<br/>reply deny: args_invalid"]
    C3 -- no --> R5
    R4 -- ok --> R5

    R5["Build policy.Input<br/>from manifest + taskstate<br/>(no justification, no args)"]
    R5 --> R6["policy.Decide(Input)"]
    R6 --> A1["audit: verdict<br/>verdict, rule_fired, taint_hwm, args_hash"]
    A1 --> V{verdict}

    V -- deny --> X5["reply {deny, reason_code, rule}"]
    V -- approve --> X6["reply {approve, reason_code, rule}<br/>(week 3: CLI approval gate)"]
    V -- allow --> R7["taskstate.RecordAllow(task, tool)"]
    R7 --> R8["execute()<br/>week-1 stub echoes args"]
    R8 --> A2["audit: executor<br/>exit_code, args_hash"]
    A2 --> X7["reply {allow, result}"]

    X2 & X3 & X4 & X5 & X6 & X7 --> R9([WriteFrame to worker])
    X1 --> R10([governor exits, no reply])

    classDef check fill:#fff7ed,stroke:#c2410c,color:#111;
    classDef stop fill:#fdecea,stroke:#c53030,color:#111;
    classDef ok fill:#ecfdf5,stroke:#047857,color:#111;
    classDef audit fill:#eef2ff,stroke:#4338ca,color:#111;
    class C1,C2,C3,V check;
    class X1,X2,X3,X4,X5 stop;
    class X6 check;
    class X7,R7,R8 ok;
    class A1,A2 audit;
```

**Two things to notice.** The `justification` string enters at `ParseRequest` (length-checked) and then goes nowhere: it is not in `Input`, not in the hash, not in the audit record. And `args_hash` is computed once and threads through the verdict record, the executor record and, from week 3, the token — so the same canonical arguments produce the same hash everywhere, and a replay with different arguments is visible as a different hash.

**Dry-run.** With `-dry-run`, `deny` and `approve` still produce their audit record but fall through to `RecordAllow → execute`, and every record carries `dry_run: true`. That is how a policy is tuned against a real agent before it is enforced.

---

## 4. Policy decision

`Decide` is a fixed list of rules read top to bottom; the first that fires wins, and reading down they only ever get stricter. The input is built by the governor from the manifest and the task store. Nothing the agent wrote is in it.

```mermaid
flowchart TD
    I["policy.Input<br/>role · tool known? · kind · direction · sensitivity_floor · max_calls<br/>call_count · taint_hwm · delegation_depth · args_hash"]
    I --> D1{"delegation_depth ><br/>max_delegation_depth?"}
    D1 -- yes --> O1["DENY<br/>escalation.delegation_depth"]
    D1 -- no --> D2{"tool in<br/>manifest?"}
    D2 -- no --> O2["DENY<br/>base.unknown_tool"]
    D2 -- yes --> D3{"call_count ≥<br/>max_calls_per_task?"}
    D3 -- yes --> O3["DENY<br/>misuse.call_cap"]
    D3 -- no --> D4{"taint_hwm ≥<br/>sensitivity_floor?"}
    D4 -- yes --> O4["APPROVE<br/>flow.sensitivity_floor"]
    D4 -- no --> D5{"kind = freeform AND<br/>direction = outbound?"}
    D5 -- yes --> O5["APPROVE<br/>flow.freeform_outbound"]
    D5 -- no --> O6["ALLOW<br/>base.allowed_tool"]

    classDef deny fill:#fdecea,stroke:#c53030,color:#111;
    classDef approve fill:#fff7ed,stroke:#c2410c,color:#111;
    classDef allow fill:#ecfdf5,stroke:#047857,color:#111;
    class O1,O2,O3 deny;
    class O4,O5 approve;
    class O6 allow;
```

**Where each number comes from.** `role`, `kind`, `direction`, `sensitivity_floor`, `max_calls_per_task`, `max_delegation_depth`: the signed manifest. `call_count`, `taint_hwm`, `delegation_depth`: `internal/taskstate`, which only the governor writes. `tool known?`: whether the manifest has a tool by the requested name. Two tests pin this down: `TestInputCarriesNoAgentText` fails the build if a text-shaped field is ever added to `Input`, and `TestDeterministic` shows identical inputs give identical decisions.

**As of week 2** the diagram above is realised in two layers. The first two diamonds (delegation depth, tool known) are Go pre-checks in `Engine.Decide`. Everything else is Cedar: `policies/base.cedar` holds the `forbid` rules (call cap, sensitivity floor, freeform outbound, delegation restated), `policies/<role>.cedar` holds one `permit` per tool with optional target constraints. The request is `principal = Agent::"<role>"`, `action = Action::"<tool>"`, `resource = Target::"<resource_arg value>"`, context = the facts listed in the input box. A `forbid` annotated `@verdict("approve")` yields APPROVE only if a permit would otherwise have matched; a plain `forbid` yields DENY; no matching permit yields DENY. Cedar's forbid-overrides-permit semantics give "only gets stricter" as a language guarantee rather than an ordering convention.

---

## 5. Audit chain

Every record carries the SHA-256 of the previous record's exact bytes. Edit, insert or delete one line and every link after it fails. `agentd verify` walks the chain and names the first bad record.

```mermaid
flowchart LR
    G0["genesis<br/>000…000"]
    R1["seq 1 · start<br/>prev_hash = 000…000<br/>originating_user, agent_role"]
    R2["seq 2 · verdict<br/>prev_hash = H(R1)<br/>tool, verdict, rule_fired,<br/>taint_hwm, args_hash"]
    R3["seq 3 · executor<br/>prev_hash = H(R2)<br/>tool, exit_code, args_hash"]
    R4["seq 4 · verdict<br/>prev_hash = H(R3)"]
    RN["seq N · stop<br/>prev_hash = H(R N-1)<br/>exit_code"]

    G0 -. "hash of" .-> R1 -. "hash of" .-> R2 -. "hash of" .-> R3 -. "hash of" .-> R4 -. "…" .-> RN

    subgraph V["agentd verify"]
        direction TB
        V1["expect seq = 1, prev = genesis"]
        V2["for each line:<br/>seq matches? prev_hash == H(previous line)?"]
        V3["first mismatch →<br/>'chain broken at record K'"]
        V1 --> V2 --> V3
    end

    classDef rec fill:#eef2ff,stroke:#4338ca,color:#111;
    class R1,R2,R3,R4,RN rec;
```

**What is in a record.** Three identities on every line (`originating_user`: who launched the governor; `agent_role`: from the manifest; `approver_id`: empty until week 3's approval gate). The event (`start`, `verdict`, `executor`, `reject`, `kill`, `stop`). For verdicts: the verdict, the rule that fired, the reason code, the taint mark at that moment, and the args hash — never the args themselves. For executor outcomes: exit code and, from week 3, the token id.

**Write path.** Each record is flushed to the OS immediately; `fsync` is batched at 50 ms so the chain does not cost a disk sync per tool call. On open, an existing chain is verified before it is extended; a broken chain is refused and left as evidence.

---

## 6. Shutdown and kill switch

Three ways the governor stops. The kill switch runs on its own goroutine, so a worker that floods the request loop cannot delay it.

```mermaid
stateDiagram-v2
    [*] --> Serving: startup complete

    Serving --> WorkerExited: ReadFrame returns EOF
    Serving --> AuthFailure: sender uid mismatch<br/>or overflow uid
    Serving --> Killed: SIGUSR1 / SIGINT / SIGTERM<br/>or file appears in -kill-dir

    WorkerExited --> Wait: audit stop "worker exited"
    AuthFailure --> KillGroup: audit reject socket_auth
    Killed --> KillGroup: audit kill "signal …" / "kill file …"
    KillGroup --> Wait: SIGKILL(-pgid)
    Wait --> Final: cmd.Wait()
    Final --> [*]: audit stop with exit_code,<br/>final fsync, close
```

**Why the process group.** The worker is started with `Setpgid`, so `SIGKILL` to the negative pid reaches the worker and everything it forked — a shell tool, a subprocess an agent framework spawned — in one call. **Why kill before wait on auth failure.** A worker that sent a bad frame may be blocked waiting for a reply that will never come; waiting on it first would deadlock the governor (found and fixed in week 1 testing).

---

## What is deliberately not here yet

| Piece | Week | Appears in diagram |
| --- | --- | --- |
| Per-call Biscuit token, executors, Vault | 3 | Replaces `execute()` in §1 and §3; adds token id to §5 |
| CLI approval gate, 60 s deny-by-default | 3 | Fills the `approve` branch in §3; fills `approver_id` in §5 |
| Worker container, executor netns, egress proxy | 4 | Hardens the worker box in §1; adds the proxy |
| Real agents, MCP bridge | 5 | Replaces `stub_worker.py` in §1 |

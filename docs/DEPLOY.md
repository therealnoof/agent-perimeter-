# Deployment guide

How to put `agentd` on a fresh Linux host and prove it is working. Every command here was run on a clean Ubuntu-class host while this guide was written. Steps marked **(week N)** apply once that phase has landed; today's build is week 1.

The guide assumes you are deploying to **one host** that will run the governor, the worker, and (from week 3) the executors. Nothing needs the internet after step 2.

## 0. Get a proper root shell

Most steps below run as root. Use a **login** shell so `$HOME` is set:

```bash
sudo -i          # or: sudo su -
```

`sudo -s` and plain `sudo su` leave `$HOME` unset, which breaks `git` global config and `gh auth setup-git` (`fatal: $HOME not set`) and causes git to prompt for a password that GitHub will never accept. If you are already in such a shell, `export HOME=/root` fixes it for that session.

## 1. Host requirements

| Need | Minimum | Why |
| --- | --- | --- |
| OS | Linux, kernel 5.x or 6.x (Ubuntu 24.04 tested) | `socketpair`, `SCM_CREDENTIALS`, process groups |
| Go | 1.23+ | Build only; the binary is static |
| Python | 3.10+ | Client library and workers |
| Root or sudo | Yes, for the UID boundary | `agentd` starts as root so it can drop the worker to its own user |
| Disk | 200 MB | Source, build cache, audit logs |
| Network | None at runtime | Build needs `git clone` only; the governor is stdlib-only |

Check it:

```bash
./scripts/preflight.sh
```

Every line should read `PASS`. `WARN` lines about docker, iptables and opa are fine until those weeks arrive.

## 2. Get and build the code

```bash
git clone https://github.com/therealnoof/agent-perimeter-.git agent-perimeter
cd agent-perimeter
make build        # bin/agentd, bin/sign-manifest
make test         # go test -race ./... — must be green before you go further
```

If `make test` is not green on your host, stop here. The socket tests in particular exercise kernel behaviour (`SCM_CREDENTIALS`, fd inheritance) and a failure means the boundary does not work on this kernel.

## 3. Create the worker account

The worker (the agent) runs as its own unprivileged user. `agentd` checks that every message on the socket came from this UID, so the account must exist and must not be the overflow UID (65534, usually `nobody`).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin perimeter-worker
id perimeter-worker          # note the uid; it must not be 65534
```

**You will almost certainly hit a permissions problem here.** Ubuntu 24.04 (and most recent distributions) create home directories as `750`, so a repo cloned under `/home/<you>` cannot be reached by `perimeter-worker`, and step 6 fails with `python3: can't open file '.../agents/stub_worker.py': Permission denied`. Choose one:

```bash
# Option A (lab box): let other users traverse your home directory. They still cannot list it.
chmod o+x "$HOME"

# Option B (anything you will demo from): put the code where the agent's user can reach it.
sudo mv ~/agent-perimeter /opt/agent-perimeter && cd /opt/agent-perimeter
```

Then confirm the worker account can actually read what it needs:

```bash
sudo -u perimeter-worker python3 -c "import sys; sys.path.insert(0,'client'); import perimeter_client; print('worker can read the client library')"
```

If that fails, `namei -l agents/stub_worker.py` shows which directory on the path is missing `x` for others; `chmod -R o+rX agents client` fixes the files themselves if a restrictive `umask` left them `600`.

## 4. Signing key and manifests

The manifest is the signed description of what the agent may do. `agentd` refuses to start without a valid signature.

**On the operator's machine, not the demo host** (the private key should never be on the host the agent runs on):

```bash
make gen-key                 # keys/private/manifest-signing.key (gitignored), keys/manifest-signing.pub
make sign-manifests          # manifests/*.json.sig
make verify-manifests        # every manifest must print "ok"
git add keys/manifest-signing.pub manifests/*.sig && git commit -m "sign manifests"
```

Then pull on the demo host. If you must do everything on one host for a PoC, that is acceptable as long as you say so; move `keys/private/` off the host afterwards.

Policies are signed the same way, with the same key: `policies/*.cedar` each get a detached `.cedar.sig`.

```bash
make sign                    # = sign-manifests + sign-policies
make verify                  # every manifest and policy must print "ok"
```

To change a manifest or a policy: edit it, `make sign`, commit both files. Anything edited without re-signing refuses to load, which you can demonstrate on purpose (test plan M-1, M-9). `make demo-*` checks signatures first and tells you to run `make sign` if they are stale.

## 4b. Governor key, sidecar, mock service (week 3)

The governor signs a per-call token with its own key; executors and the secrets sidecar verify it. Generate the key once per installation:

```bash
bin/agentd keygen -out run/governor.key          # writes run/governor.key (0600) and run/governor.pub
```

The sidecar holds the only credential to the secrets backend and releases one secret per valid token. It is started by the operator, **not** by the governor, so the governor never has a path to a secret:

```bash
# file backend (demo); real deployments use -vault-addr ... with VAULT_SECRET_ID in the environment
bin/secretsd -listen run/secrets.sock -gov-pub run/governor.pub \
  -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -secrets-file deploy/secrets.demo.json &
bin/mockserv -listen 127.0.0.1:9811 &             # Jira/Slack stand-in for the demo
```

`make services-up` / `make services-down` do this with pidfiles under `run/`.

## 4c. The dashboard (`auditview`)

A read-only page over the audit chain, the sidecar log and the mock's request log: trace timeline, span detail, taint over time, human decisions, credential releases joined to executor records, what reached the services, and a behavioural profile with anomaly flags. It never talks to the governor and is not part of the trust boundary.

It serves **HTTPS only**. Without a certificate it generates a self-signed ECDSA P-256 one at startup (30 days, SANs for `localhost`, the hostname and every local IP) and prints the SHA-256 fingerprint:

```bash
make auditview
# auditview: self-signed certificate, SHA-256 fingerprint 3A:7F:…
# auditview: https://<this-host>:9800
```

Open `https://<host>:9800`. The browser warns once; compare the fingerprint it shows with the line above before accepting. To avoid the warning, use a certificate your browsers trust:

```bash
make auditview AV_CERT=/etc/ssl/agentd/auditview.crt AV_KEY=/etc/ssl/agentd/auditview.key
```

9800 is an unprivileged port, so the process never needs root or `CAP_NET_BIND_SERVICE`; put a reverse proxy or a firewall redirect in front if 443 is required. Plain HTTP exists only as `-plaintext` on a loopback address, for a tunnel; the binary refuses it anywhere else.

Firewall: allow 9800/tcp from the operator's network only. The page has no authentication of its own in the PoC; what it shows is the audit trail, so treat the port like the log directory.

## 5. Runtime layout

```bash
sudo mkdir -p /var/lib/agent-perimeter/audit /var/lib/agent-perimeter/kill
sudo chmod 700 /var/lib/agent-perimeter/audit     # worker must not read or write the chain
sudo chmod 755 /var/lib/agent-perimeter/kill       # anyone may drop a kill file
```

The audit directory being unreadable by `perimeter-worker` is requirement A-2 and should be checked, not assumed:

```bash
sudo -u perimeter-worker ls /var/lib/agent-perimeter/audit   # must be "Permission denied"
```

## 6. Run

```bash
sudo bin/agentd run \
  -manifest manifests/stub-agent.json \
  -pubkey   keys/manifest-signing.pub \
  -audit    /var/lib/agent-perimeter/audit/$(date +%Y%m%d-%H%M%S).jsonl \
  -kill-dir /var/lib/agent-perimeter/kill \
  -worker-user perimeter-worker \
  -- python3 agents/stub_worker.py
```

Flags:

| Flag | Meaning |
| --- | --- |
| `-manifest`, `-pubkey` | The signed role and the key that signed it. Both required. |
| `-policies` | Directory of signed `*.cedar` files (default `policies`). Every file must verify against `-pubkey`. |
| `-audit` | Chain to append to. A new file per run keeps chains short and easy to hand over. Appending to an existing chain is supported; a corrupt existing chain is refused. |
| `-kill-dir` | Any file appearing here stops the worker within 100 ms. `SIGUSR1` to `agentd` does the same. |
| `-worker-user` | Drop the worker to this account. Requires `agentd` to start as root. Without it, the worker runs as the same user as the governor and `agentd` prints a warning: there is no boundary. |
| `-worker-uid` | Expect this UID without dropping to it (for when something else, such as a container runtime, already set the UID). |
| `-gov-key` | The governor's token-signing private key from `agentd keygen`. Required. Refused if readable by others. |
| `-gov-pub-out` | Where to write the matching public key (default `run/governor.pub`); executors and `secretsd` read it. |
| `-executor` | Executor binary spawned per allowed call (default `bin/executor`). |
| `-secrets-sock` | The sidecar socket, passed to executors. Tools with a `secret_path` fail (exit 3) without it. |
| `-approver` | `cli` (prompt on this terminal), `deny` (headless: every approve verdict is denied), or `allow-all-UNSAFE-tests-only`. |
| `-approval-timeout` | How long a CLI prompt waits before deny (default 60s). |
| `-dry-run` | Log every verdict but execute anyway. For tuning a policy against a real agent before enforcing it. Audit records carry `dry_run: true`. |
| `--` | Everything after is the worker command. |

Expected output ends with the worker's eight lines and the governor returning to the prompt. Then:

```bash
# verify the chain you just wrote (the newest file in the audit directory)
bin/agentd verify -audit "$(ls -t /var/lib/agent-perimeter/audit/*.jsonl | head -1)"
# ok: 13 records, chain intact
```

### The approval prompt

With `-approver cli`, an `approve` verdict stops the governor at a box like this on its terminal:

```
┌─ APPROVAL REQUIRED ─────────────────────────────────────────
│ task      demo-task-1
│ tool      jira_update
│ target    OPS-1
│ taint     8  (highest sensitivity this task has touched)
│ rule      flow.sensitivity_floor
│ args      sha256:2f796fb245d3…
│ (agent justification hidden; press j to show)
└──────────────────────────────────────────────────────────────
[approval] a=approve d=deny j=show agent justification (59s):
```

Everything shown is what the governor knows. `j` reveals what the agent wrote, labelled untrusted. No answer in 60 s is a deny with `approval_timeout`; a closed terminal is a deny with `approval_unavailable`. The approver's login (or `SUDO_USER`) is written to the audit record.

## 7. Smoke test (5 minutes)

Run these after every deploy. Each maps to a test-plan ID.

```bash
# S-1: refuse a tampered manifest
cp manifests/stub-agent.json /tmp/m.json; cp manifests/stub-agent.json.sig /tmp/m.json.sig
sed -i 's/"max_calls_per_task": 3/"max_calls_per_task": 300/' /tmp/m.json
sudo bin/agentd run -manifest /tmp/m.json -pubkey keys/manifest-signing.pub -audit /tmp/x.jsonl -- true
# agentd: refusing to start: manifest: signature does not verify

# S-2: wrong worker UID is rejected and the worker is killed, not left hanging
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/wrong.jsonl -worker-uid 4242 -- python3 agents/stub_worker.py
grep -o '"detail":"request loop error[^"]*"' /tmp/wrong.jsonl
# "detail":"request loop error, worker killed: socket: sender UID does not match the worker: got 0, want 4242"

# S-3: tamper detection
cp "$(ls -t /var/lib/agent-perimeter/audit/*.jsonl | head -1)" /tmp/t.jsonl
sed -i '4s/"allow"/"deny"/' /tmp/t.jsonl
bin/agentd verify -audit /tmp/t.jsonl
# agentd: audit: chain broken at record 5: prev_hash does not match previous record

# S-4: kill switch
sudo bin/agentd run -manifest manifests/stub-agent.json -pubkey keys/manifest-signing.pub \
  -audit /tmp/kill.jsonl -kill-dir /var/lib/agent-perimeter/kill -worker-user perimeter-worker \
  -- python3 -c 'import time; time.sleep(60)' &
sleep 1; sudo touch /var/lib/agent-perimeter/kill/STOP; wait
grep -o '"event":"kill"[^}]*' /tmp/kill.jsonl
sudo rm /var/lib/agent-perimeter/kill/STOP
```

## 8. Running as a service (optional)

For a host where the governor should outlive a shell session, a minimal systemd unit:

```ini
# /etc/systemd/system/agentd@.service
[Unit]
Description=agentd governor for %i
After=local-fs.target

[Service]
Type=simple
WorkingDirectory=/opt/agent-perimeter
ExecStart=/opt/agent-perimeter/bin/agentd run \
  -manifest manifests/%i.json -pubkey keys/manifest-signing.pub \
  -audit /var/lib/agent-perimeter/audit/%i-%t.jsonl \
  -kill-dir /var/lib/agent-perimeter/kill -worker-user perimeter-worker \
  -- /opt/agent-perimeter/agents/%i/run.sh
Restart=no
# Governor hardening: it needs root only to setuid the worker.
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=/var/lib/agent-perimeter
PrivateTmp=yes
```

`Restart=no` is deliberate: a governor that stopped because of a socket-auth failure should be looked at, not restarted.

## 9. Air-gapped hosts

The build needs only the Go toolchain and this repository. To stage for a disconnected host:

```bash
# on a connected machine
git clone https://github.com/therealnoof/agent-perimeter-.git
cd agent-perimeter- && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make build
tar czf agent-perimeter.tgz bin/ manifests/ keys/manifest-signing.pub client/ agents/ scripts/ docs/
# move the tarball; on the target, extract and start from step 3
```

No Go toolchain is needed on the target. The one dependency (cedar-go) is vendored in the repository, so the build runs with `-mod=vendor` and never touches the network; the tarball approach works because the binary is static.

## 10. What is not deployed yet

| Component | Week | Effect today |
| --- | --- | --- |
| Worker container, executor netns, egress proxy | 4 | Boundary is UID + no environment; the worker still has host network |
| Real agents, MCP bridge | 5 | Only the scripted stub worker |
| Red-team harness | 6 | Manual smoke test above |

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `refusing to start: manifest: signature does not verify` | Manifest edited after signing, or wrong public key | `make sign-manifests`; check `-pubkey` matches the signer |
| `refusing to start: manifest: signature file missing` | No `.sig` beside the manifest | `make sign` |
| `refusing to start: policy: signature does not verify` or `signature file missing` | A `.cedar` file was edited after signing, or never signed | `make sign` |
| `refusing to start: policy: no .cedar files found` | Wrong `-policies` directory, or running from outside the repo | Pass `-policies /path/to/policies` |
| `build cache is required, but could not be located` from `make test` | `$HOME` unset (non-login root shell) | `export HOME=/root`, or `sudo -i` |
| `-worker-user requires agentd to be started as root` | Ran without sudo | `sudo bin/agentd run ...` |
| `WARNING: running as root with the worker also as root` | No `-worker-user` | Add `-worker-user perimeter-worker` |
| Worker prints nothing, governor exits with `request loop error ... sender UID does not match` | `-worker-uid` disagrees with the actual worker UID | Use `-worker-user` and let agentd set both |
| `python3: can't open file .../stub_worker.py: Permission denied` | Worker account cannot traverse the repo path | `chmod o+x` on the parent directories, or move the repo to `/opt` |
| `audit: chain broken at record N` on start | Existing audit file was edited or truncated | Start a new file; keep the broken one as evidence |
| `git push` asks for a password and rejects it | GitHub does not accept account passwords over HTTPS | `gh auth login` then `gh auth setup-git`, or a fine-grained token as the password, or switch the remote to SSH |
| `fatal: $HOME not set` from git or gh | Non-login root shell (`sudo -s`, `sudo su`) | `export HOME=/root`, or re-enter with `sudo -i` |
| Worker line says `DENIED -> executor_failed` and the audit executor record has `exit_code: 3` | Executor could not get its credential: `secretsd` not running, wrong `-secrets-sock`, or the tool's `secret_path` is not in the secrets file | `make services-up`; check `run/secretsd.log` for `REFUSED` lines |
| `exit_code: 2` on an executor record | Token rejected by the executor: wrong `-gov-pub`, or clock skew over 2 s between mint and verify | Check `run/governor.pub` matches the running governor's key; check the host clock |
| `make keygen` / `agentd keygen` says `exists; refusing to overwrite` | A governor key is already there | Keep it; `make gov-key` only generates when missing |
| Browser: `NET::ERR_CERT_AUTHORITY_INVALID` on the dashboard | Self-signed certificate | Compare the fingerprint auditview printed and accept, or supply `AV_CERT`/`AV_KEY` |
| `auditview: -plaintext is allowed only on a loopback address` | Tried to serve HTTP on a LAN address | Drop `-plaintext`; HTTPS is the default |
| `agentd verify` says `ok` but you expected a break | You edited a record's whitespace only | The hash covers the exact bytes; a whitespace edit does change it, so re-check the file you verified is the one you edited |

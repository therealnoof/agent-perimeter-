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

To change a manifest: edit the JSON, re-run `make sign-manifests`, commit both files. A manifest edited without re-signing will refuse to load, which you can demonstrate on purpose (test plan M-2).

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
| `-audit` | Chain to append to. A new file per run keeps chains short and easy to hand over. Appending to an existing chain is supported; a corrupt existing chain is refused. |
| `-kill-dir` | Any file appearing here stops the worker within 100 ms. `SIGUSR1` to `agentd` does the same. |
| `-worker-user` | Drop the worker to this account. Requires `agentd` to start as root. Without it, the worker runs as the same user as the governor and `agentd` prints a warning: there is no boundary. |
| `-worker-uid` | Expect this UID without dropping to it (for when something else, such as a container runtime, already set the UID). |
| `-dry-run` | Log every verdict but execute anyway. For tuning a policy against a real agent before enforcing it. Audit records carry `dry_run: true`. |
| `--` | Everything after is the worker command. |

Expected output ends with the worker's eight lines and the governor returning to the prompt. Then:

```bash
# verify the chain you just wrote (the newest file in the audit directory)
bin/agentd verify -audit "$(ls -t /var/lib/agent-perimeter/audit/*.jsonl | head -1)"
# ok: 13 records, chain intact
```

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

No Go toolchain is needed on the target. **(week 2)** will add `go mod vendor` for the OPA dependency; the tarball approach still works because the binary is static.

## 10. What is not deployed yet

| Component | Week | Effect today |
| --- | --- | --- |
| Rego policy bundle | 2 | Policy is the Go function in `internal/policy`; same rules, not yet editable without a rebuild |
| Executors, Biscuit tokens, Vault | 3 | Allowed calls return an echo of their args; nothing real runs |
| Approval CLI | 3 | `approve` verdicts are returned to the worker as pending; nothing executes |
| Worker container, executor netns, egress proxy | 4 | Boundary is UID + no environment; the worker still has host network |
| Real agents, MCP bridge | 5 | Only the scripted stub worker |
| Red-team harness | 6 | Manual smoke test above |

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `refusing to start: manifest: signature does not verify` | Manifest edited after signing, or wrong public key | `make sign-manifests`; check `-pubkey` matches the signer |
| `refusing to start: manifest: signature file missing` | No `.sig` beside the manifest | `make sign-manifests` |
| `-worker-user requires agentd to be started as root` | Ran without sudo | `sudo bin/agentd run ...` |
| `WARNING: running as root with the worker also as root` | No `-worker-user` | Add `-worker-user perimeter-worker` |
| Worker prints nothing, governor exits with `request loop error ... sender UID does not match` | `-worker-uid` disagrees with the actual worker UID | Use `-worker-user` and let agentd set both |
| `python3: can't open file .../stub_worker.py: Permission denied` | Worker account cannot traverse the repo path | `chmod o+x` on the parent directories, or move the repo to `/opt` |
| `audit: chain broken at record N` on start | Existing audit file was edited or truncated | Start a new file; keep the broken one as evidence |
| `git push` asks for a password and rejects it | GitHub does not accept account passwords over HTTPS | `gh auth login` then `gh auth setup-git`, or a fine-grained token as the password, or switch the remote to SSH |
| `fatal: $HOME not set` from git or gh | Non-login root shell (`sudo -s`, `sudo su`) | `export HOME=/root`, or re-enter with `sudo -i` |
| `agentd verify` says `ok` but you expected a break | You edited a record's whitespace only | The hash covers the exact bytes; a whitespace edit does change it, so re-check the file you verified is the one you edited |

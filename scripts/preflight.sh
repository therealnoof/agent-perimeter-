#!/usr/bin/env bash
# preflight.sh: check a host can build and run agentd before you spend time on it.
#
# Every check prints PASS, WARN or FAIL with one line of why. Exit status is
# non-zero if anything FAILs. Run it as the user who will start agentd.

set -u

pass() { printf 'PASS  %s\n' "$1"; }
warn() { printf 'WARN  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
FAILED=0

# --- OS and kernel -------------------------------------------------------------
if [ "$(uname -s)" = "Linux" ]; then
  pass "Linux ($(uname -r))"
else
  fail "agentd needs Linux (socketpair, SCM_CREDENTIALS, process groups)"
fi

# Kernel 5.x or 6.x is fine; older kernels work but are untested.
kmaj=$(uname -r | cut -d. -f1)
if [ "${kmaj:-0}" -ge 5 ]; then pass "kernel major version $kmaj"; else warn "kernel $kmaj is older than tested (5.x/6.x)"; fi

# --- Toolchain -----------------------------------------------------------------
if command -v go >/dev/null; then
  gov=$(go version | awk '{print $3}' | sed 's/go//')
  gomaj=$(echo "$gov" | cut -d. -f1); gomin=$(echo "$gov" | cut -d. -f2)
  if [ "$gomaj" -gt 1 ] || { [ "$gomaj" -eq 1 ] && [ "$gomin" -ge 23 ]; }; then
    pass "go $gov"
  else
    fail "go $gov is older than 1.23"
  fi
else
  fail "go not found; install Go 1.23+ (https://go.dev/dl/)"
fi

if command -v python3 >/dev/null; then
  pyv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  pymin=$(echo "$pyv" | cut -d. -f2)
  if [ "$pymin" -ge 10 ]; then pass "python3 $pyv"; else fail "python3 $pyv is older than 3.10"; fi
else
  fail "python3 not found (needed for the client library and workers)"
fi

command -v make >/dev/null && pass "make" || fail "make not found"
command -v git  >/dev/null && pass "git"  || warn "git not found (only needed to clone)"

# --- Privilege model -----------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
  pass "running as root: agentd can drop the worker to a separate user (-worker-user)"
  if id perimeter-worker >/dev/null 2>&1; then
    pass "worker account 'perimeter-worker' exists (uid $(id -u perimeter-worker))"
  else
    warn "no 'perimeter-worker' account yet; DEPLOY.md step 3 creates it"
  fi
else
  warn "not root: worker will run as your own uid; the UID boundary is not exercised"
fi

# Can the worker account actually reach the code? Home directories are 750 on
# Ubuntu 24.04 and most current distributions, which makes this the most
# common first-run failure. Test it the way agentd will: as that user.
if [ "$(id -u)" -eq 0 ] && id perimeter-worker >/dev/null 2>&1; then
  repo=$(cd "$(dirname "$0")/.." && pwd)
  if sudo -u perimeter-worker test -r "$repo/agents/stub_worker.py" \
     && sudo -u perimeter-worker test -r "$repo/client/perimeter_client/__init__.py"; then
    pass "perimeter-worker can read $repo/agents and client/"
  else
    fail "perimeter-worker cannot read $repo (home dir is probably 750). Run: chmod o+x \"\$HOME\"  or move the repo to /opt. See DEPLOY.md step 3."
  fi
fi

# The overflow uid is what an unmapped sender looks like; we refuse it, so the
# worker account must not be it.
if id perimeter-worker >/dev/null 2>&1 && [ "$(id -u perimeter-worker)" -eq 65534 ]; then
  fail "perimeter-worker has uid 65534 (overflow uid); agentd will reject it. Use a different uid."
fi

# --- Later weeks (informational) -------------------------------------------------
command -v docker >/dev/null && pass "docker (week 4 sandbox, mocks)" || warn "docker not found; needed from week 4"
command -v iptables >/dev/null || command -v nft >/dev/null && pass "iptables/nft (week 4 egress)" || warn "no iptables/nft; needed from week 4"
command -v opa >/dev/null && pass "opa CLI (week 2 policy tests)" || warn "opa CLI not found; needed from week 2 for 'opa test'"

if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
  if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" = "1" ]; then
    pass "unprivileged user namespaces enabled (week 4)"
  else
    warn "unprivileged_userns_clone=0; week 4 sandbox will need it"
  fi
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "Preflight FAILED. Fix the FAIL lines above."
  exit 1
fi
echo "Preflight passed."

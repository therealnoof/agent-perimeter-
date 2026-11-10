# agent-perimeter Makefile
#
# Every target is a plain shell command so you can read it and run it by hand.
# Run `make help` for the list.

GO        ?= go
# -mod=vendor: build from the committed vendor/ directory, never the network.
# This is how the air-gapped build works too.
export GOFLAGS := -mod=vendor
BIN       := bin
KEYDIR    := keys
PRIVKEY   := $(KEYDIR)/private/manifest-signing.key
PUBKEY    := $(KEYDIR)/manifest-signing.pub
MANIFESTS := $(wildcard manifests/*.json)
POLICIES  := $(wildcard policies/*.cedar)

.PHONY: help build test check-signed gov-key services-up services-down demo-week3 gen-key sign-manifests sign-policies sign verify-manifests verify-policies verify clean demo-week1 demo-week2

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build all binaries into ./bin
	@mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/agentd ./cmd/agentd
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/sign-manifest ./cmd/sign-manifest
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/executor ./cmd/executor
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/secretsd ./cmd/secretsd
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/mockserv ./cmd/mockserv

test: ## Run all Go unit tests (race detector on)
	$(GO) test -race -count=1 ./...

gen-key: build ## Generate the Ed25519 manifest signing keypair (once; private key is gitignored)
	@mkdir -p $(KEYDIR)/private
	@if [ -f $(PRIVKEY) ]; then echo "refusing to overwrite $(PRIVKEY)"; exit 1; fi
	$(BIN)/sign-manifest gen-key -priv $(PRIVKEY) -pub $(PUBKEY)
	@echo "public key written to $(PUBKEY); commit it. private key is NOT committed."

sign-manifests: build ## Sign every manifests/*.json, writing a detached .sig beside each
	@for m in $(MANIFESTS); do \
		$(BIN)/sign-manifest sign -priv $(PRIVKEY) -in $$m -out $$m.sig && echo "signed $$m"; \
	done

sign-policies: build ## Sign every policies/*.cedar, writing a detached .sig beside each
	@for p in $(POLICIES); do \
		$(BIN)/sign-manifest sign -priv $(PRIVKEY) -in $$p -out $$p.sig && echo "signed $$p"; \
	done

sign: sign-manifests sign-policies ## Sign manifests and policies

verify-policies: build ## Verify every policy signature against the committed public key
	@for p in $(POLICIES); do \
		$(BIN)/sign-manifest verify -pub $(PUBKEY) -in $$p -sig $$p.sig && echo "ok      $$p"; \
	done

verify: verify-manifests verify-policies ## Verify manifests and policies

verify-manifests: build ## Verify every manifest signature against the committed public key
	@for m in $(MANIFESTS); do \
		$(BIN)/sign-manifest verify -pub $(PUBKEY) -in $$m -sig $$m.sig && echo "ok      $$m"; \
	done

# check-signed: fail fast with a useful message if a manifest or policy was
# edited after signing. agentd would refuse anyway; this just says why.
check-signed: build
	@for m in $(MANIFESTS); do $(BIN)/sign-manifest verify -pub $(PUBKEY) -in $$m -sig $$m.sig >/dev/null 2>&1 \
		|| { echo "$$m is not signed by $(PUBKEY). Run: make sign"; exit 1; }; done
	@for p in $(POLICIES); do $(BIN)/sign-manifest verify -pub $(PUBKEY) -in $$p -sig $$p.sig >/dev/null 2>&1 \
		|| { echo "$$p is not signed by $(PUBKEY). Run: make sign"; exit 1; }; done

demo-week1: check-signed $(GOVKEY) ## Week-1 sequence: verdict classes, call cap, schema rejection, justification retry
	@mkdir -p run
	$(BIN)/agentd run -manifest manifests/stub-agent.json -pubkey $(PUBKEY) -audit run/audit.jsonl \
		-gov-key $(GOVKEY) -gov-pub-out $(GOVPUB) -executor $(BIN)/executor -approver deny -- python3 agents/stub_worker.py
	@echo "--- audit chain ---"
	@cat run/audit.jsonl
	@echo "--- verify ---"
	$(BIN)/agentd verify -audit run/audit.jsonl

demo-week2: check-signed services-up ## Staged exfiltration: read confidential, then an ordinary update needs a human (approver=deny here; week 3 adds the prompt)
	$(BIN)/agentd run -manifest manifests/stub-agent.json -pubkey $(PUBKEY) -audit run/audit2.jsonl \
		-gov-key $(GOVKEY) -gov-pub-out $(GOVPUB) -executor $(BIN)/executor -secrets-sock $(SECSOCK) -mock-addr $(MOCKADDR) \
		-approver deny -- python3 agents/stub_worker.py --week2
	@echo "--- verdicts ---"
	@grep -o '"tool":"[a-z_]*","verdict":"[a-z]*","rule_fired":"[^"]*"' run/audit2.jsonl
	@echo "--- taint ---"
	@grep -o '"event":"executor".*"taint_hwm":[0-9]*' run/audit2.jsonl | grep -o '"tool":"[a-z_]*".*taint_hwm":[0-9]*'
	$(BIN)/agentd verify -audit run/audit2.jsonl
	@$(MAKE) -s services-down

# --- week 3: real executors, sidecar, approval gate ---------------------------
RUN       := run
GOVKEY    := $(RUN)/governor.key
GOVPUB    := $(RUN)/governor.pub
SECSOCK   := $(RUN)/secrets.sock
MOCKADDR  := 127.0.0.1:9811

$(GOVKEY): build
	@mkdir -p $(RUN)
	$(BIN)/agentd keygen -out $(GOVKEY) -pub-out $(GOVPUB)

gov-key: $(GOVKEY) ## Generate the governor token-signing key once (run/governor.key, mode 0600)

services-up: build $(GOVKEY) ## Start mockserv and secretsd in the background (logs in run/)
	@mkdir -p $(RUN)
	@chmod 600 deploy/secrets.demo.json
	@pkill -f "$(BIN)/mockserv" 2>/dev/null; pkill -f "$(BIN)/secretsd" 2>/dev/null; true
	@$(BIN)/mockserv -listen $(MOCKADDR) >$(RUN)/mockserv.log 2>&1 & echo "mockserv  on $(MOCKADDR)"
	@$(BIN)/secretsd -listen $(SECSOCK) -gov-pub $(GOVPUB) -manifest manifests/stub-agent.json -pubkey $(PUBKEY) \
		-secrets-file deploy/secrets.demo.json >$(RUN)/secretsd.log 2>&1 & echo "secretsd  on $(SECSOCK)"
	@sleep 0.5

services-down: ## Stop mockserv and secretsd
	@pkill -f "$(BIN)/mockserv" 2>/dev/null; pkill -f "$(BIN)/secretsd" 2>/dev/null; true

demo-week3: check-signed services-up ## Real executors + credentials + a human approval prompt (answer a/d/j on the terminal)
	$(BIN)/agentd run -manifest manifests/stub-agent.json -pubkey $(PUBKEY) -audit $(RUN)/audit3.jsonl \
		-gov-key $(GOVKEY) -gov-pub-out $(GOVPUB) -executor $(BIN)/executor -secrets-sock $(SECSOCK) -mock-addr $(MOCKADDR) \
		-approver cli -approval-timeout 60s -- python3 agents/stub_worker.py --week3
	@echo "--- what reached the mock service ---"
	@curl -s http://$(MOCKADDR)/log
	@echo "--- what the sidecar released ---"
	@grep -E "RELEASED|REFUSED" $(RUN)/secretsd.log
	@echo "--- audit ---"
	@grep -o '"event":"\(verdict\|approval\|executor\)".*"tool":"[a-z_]*"' $(RUN)/audit3.jsonl | sed 's/"originating_user[^,]*,"agent_role[^,]*,//' | cut -c1-160
	$(BIN)/agentd verify -audit $(RUN)/audit3.jsonl
	@$(MAKE) -s services-down

clean: ## Remove build outputs and runtime state
	rm -rf $(BIN) run

# agent-perimeter Makefile
#
# Every target is a plain shell command so you can read it and run it by hand.
# Run `make help` for the list.

GO        ?= go
BIN       := bin
KEYDIR    := keys
PRIVKEY   := $(KEYDIR)/private/manifest-signing.key
PUBKEY    := $(KEYDIR)/manifest-signing.pub
MANIFESTS := $(wildcard manifests/*.json)

.PHONY: help build test gen-key sign-manifests verify-manifests clean demo-week1

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build agentd and sign-manifest into ./bin
	@mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/agentd ./cmd/agentd
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/sign-manifest ./cmd/sign-manifest

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

verify-manifests: build ## Verify every manifest signature against the committed public key
	@for m in $(MANIFESTS); do \
		$(BIN)/sign-manifest verify -pub $(PUBKEY) -in $$m -sig $$m.sig && echo "ok      $$m"; \
	done

demo-week1: build ## Run agentd with the stub Python worker and show the audit chain
	@mkdir -p run
	$(BIN)/agentd run -manifest manifests/stub-agent.json -pubkey $(PUBKEY) -audit run/audit.jsonl -- python3 agents/stub_worker.py
	@echo "--- audit chain ---"
	@cat run/audit.jsonl
	@echo "--- verify ---"
	$(BIN)/agentd verify -audit run/audit.jsonl

clean: ## Remove build outputs and runtime state
	rm -rf $(BIN) run

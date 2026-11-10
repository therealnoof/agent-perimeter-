# Build plan

The full six-week plan (phases, gates, work breakdown, policy additions, demo script, compliance mapping, risks) lives as a living document:

**agentd PoC Build Plan** — https://claude.ai/artifact/8MAuzYunrG8qbaJ486Sbmn

The PRD with the G/P/C/D/E/A requirement tables and the 16-case attack table is the earlier document from the same series.

## Deviations from the plan, as built

Decisions made during implementation that differ from the plan text. The plan document is updated to match when a deviation is permanent.

| Date | Deviation | Why |
| --- | --- | --- |
| 2026-11-04 | Governor is standard-library only; no third-party Go modules | The build environment could not reach the Go module proxy, and on reflection a zero-dependency trust anchor is the stronger story. Enforced by `TestNoForbiddenImports`. Week 2's OPA embed is the one planned exception, confined to `internal/policy`, and will need `go mod vendor` run on a machine with module access. |
| 2026-11-04 | Manifests are JSON, not YAML | Consequence of the above: `encoding/json` is stdlib, YAML is not. The schema is identical; only the syntax changed. |
| 2026-11-04 | Request args validated by a ~200-line JSON Schema subset in `internal/schema` rather than a schema library | Same reason. The subset (type, properties, required, additionalProperties, items, enum, min/max, minLength/maxLength, maxItems, pattern) covers every tool in the PoC; unsupported keywords are a compile error so a manifest cannot silently use one. |
| 2026-11-04 | Week-1 policy is a short Go function (`internal/policy.Decide`) with the same rule set the plan writes in Rego | Lets the full request path be built and tested before OPA is embedded. `Input` and `Decision` types are the stable interface; week 2 swaps the body. |
| 2026-11-04 | P-6, P-7 and G-8 implemented in week 1 rather than week 2 | They are three `if` statements once the policy input exists; cheaper to land with the skeleton than to come back for. |
| 2026-11-04 | GitHub repo is `therealnoof/agent-perimeter-` (trailing hyphen) | Created by hand that way. Module path is `github.com/therealnoof/agent-perimeter`; rename the repo on GitHub to match when convenient. |
| 2026-11-04 | Sender authentication uses `SO_PASSCRED`/`SCM_CREDENTIALS`, not `SO_PEERCRED` as the PRD (G-3) says | Found during the first privilege-drop test: `SO_PEERCRED` on a socketpair reports the *creator's* credentials (root agentd), so after the worker's `setuid` it still said uid 0. `SCM_CREDENTIALS` is stamped by the kernel per message with the actual sender's UID. The PRD's G-3 wording should be updated. |
| 2026-11-04 | Added `-worker-user` flag: agentd started as root drops the worker to that account | Gives G-3 something real to check before the week-4 container sandbox exists. Refuses uid 0. |
| 2026-11-10 | Policy engine is Cedar (cedar-go v1.9.0, vendored), not OPA/Rego | Chosen for a federal / air-gapped / hardened target: two trivial deps vs ~100 in the trust anchor; bounded, terminating language with forbid-overrides-permit as a guarantee; native principal/action/resource/context model; Lean-verified reference implementation. Cost: less name recognition than OPA, younger Go port. `Input → Decision` interface kept so an OPA backend could be added behind a build tag for a customer who insists. |
| 2026-11-10 | Three verdicts from Cedar's two: a `forbid` annotated `@verdict("approve")` is overridable by a human; any plain `forbid` is final; approve requires that a permit would otherwise have matched | Cedar's diagnostic reports only the forbids that fired on a deny, so the engine keeps a second policy set without the overridable forbids to answer "would anything have permitted this". |
| 2026-11-10 | cedar-go v1.9.0 requires Go 1.26; the build session's box has 1.24 | Compile and test run on the user's Ubuntu host; the build session writes against the vendored source. |

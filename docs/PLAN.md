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

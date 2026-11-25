# Executor report — incomplete

This work is not ready to commit. Scope B is outstanding, as are parts of the requested tests and verification. No commit or push was made.

## Files changed

- `go.mod`, `go.sum`: upgraded slogx to v0.2.0 and sandboxes-core to v0.0.15 using `go get`.
- `daemon.go:195`: registers unary and stream interceptors.
- `internal/server/correlation.go`: validates inbound metadata and attaches operation and request IDs; provides a parent ID accessor and stream wrapper.
- `internal/server/correlation_test.go`: metadata cases, rejection logging and stream-lifetime checks.
- `docs/observability.md`: current behavior and limitations.

## Event coverage

| Event | Contour | Location |
| --- | --- | --- |
| `ObsIDRejected` | Missing or invalid inbound correlation metadata | `internal/server/correlation.go:41` |
| All other requested events | Not implemented | — |

Metadata is accepted as incoming gRPC metadata, not as identity or authorization. Parent IDs use a private context key because the core context API only exposes operation and request IDs. Separate resumed RPCs preserve IDs only if the client resends them; this has not been integrated with resume logic. Standard event fields are not yet populated from context.

## Canary and tests

The focused rejection test plants a synthetic value in metadata and verifies it is absent from the JSON output, with three rejection events. This is not the requested representative service-emission canary; that and the static guest-input guard remain outstanding. The selected race run passed three tests, including six metadata subcases; it does not cover a real reconnect or arbitrary garbage beyond the listed cases.

## Gates

- gofmt: applied to modified Go files; full empty-output gate not run.
- `go vet ./...`: no output; run before final test-only edits.
- `golangci-lint run ./...`: reported 0 issues, but cache writes were denied; run before final test-only edits, so not a clean final gate.
- `govulncheck ./...`: no vulnerabilities found; run before final test-only edits.
- `go test -race ./... -count=1`: failed in `TestEnsureDockerVolumeFormatsThroughValidatedFileDescriptor` because the sandbox denied `/dev/fd/3`; other listed packages passed. This run began before the final test edits; full fresh final run remains required. Test counts not collected.
- Selected `go test -race ./internal/server -run 'TestCorrelation|TestStreamCorrelation' -count=1`: passed (3 tests, 6 metadata subcases).
- Fuzzing: not expected in this slice and not run.

## Outstanding work and questions

Implement all requested service/lifecycle events, map journal reasons, add standard context fields and representative secret canary/static guard, verify reconnect continuity, and rerun all gates on the final tree. Confirm whether synthesizing a parent request ID when absent is desired semantically; the brief explicitly asks regeneration, but a generated parent does not identify an actual preceding request.

## Y1b continuation — incomplete

The prior work was preserved. This continuation adds journal finding events only; it does not complete Scope B/C and is not ready to commit.

| Contour | Event | Location |
| --- | --- | --- |
| Recognized runtime journal LEAVE finding | `JournalRecover` | `internal/service/service.go:4173`, `internal/service/journal_events.go:16` |

All eight known runtime reasons are mapped explicitly. Unknown reasons emit no event. Resource paths are SHA-256 hashed, and the catalog resource kind is `unknown` because the runtime finding does not expose the kind. Correlation IDs are included when valid. The daemon no longer logs the formatted finding separately.

`TestJournalFindingEventsRedactInputs` plants synthetic values in finding ID, resource, and an unknown reason, and checks JSON output for their absence across all eight mappings. This is limited evidence, not the requested full service-emission canary suite. The static guest-controlled ID/Host guard has not been implemented. `TestStreamCorrelationContinuity` still covers one stream lifetime only; reconnect/resume continuity has not been verified.

Final-tree gates after Go edits:

- gofmt: empty output for changed and added Go files.
- `go vet ./...`: passed.
- `golangci-lint run ./...`: passed, 0 issues, using a writable temporary lint cache.
- `govulncheck ./...`: passed, no vulnerabilities found.
- `go test -race ./... -count=1`: 20 packages passed, one package failed, one had no test files. `TestEnsureDockerVolumeFormatsThroughValidatedFileDescriptor` failed because the sandbox denied the fake formatter's access to `/dev/fd/3` (operation not permitted). The architect must rerun outside the sandbox.
- Selected race run: six top-level tests passed (three service and three server), including six metadata subcases.
- Fuzzing not run; not expected in this slice.

Outstanding: lifecycle, reconcile, create unwind, peer credentials, approvals, kit, MCP, template, secret, platform and runtime emissions; full canary suite and static guard; reconnect/resume verification; complete contour documentation. The original parent-ID semantics question remains open. No commit or push was made.

# Daemon observability

The daemon accepts gRPC metadata keys `rheic-op-id`, `rheic-req-id`, and `rheic-parent-req-id`. It validates their expected prefixes and canonical formats before placing the operation and request IDs in the handler context. Invalid or missing values are regenerated and produce `rheic.obs.id_rejected` at debug level without logging the supplied value. Parent IDs are available through the server package's context accessor. Correlation IDs are not identity or authorization material.

Correlation context persists for the lifetime of an individual RPC stream. Propagation across gateway, runtime and guest boundaries, and continuity across separate resumed RPCs, require additional integration.

Journal recovery emits `rheic.journal.recover` for each recognized finding left in place. The event contains a mapped reason, a SHA-256 resource hash, and correlation IDs when available. Unknown reasons are not emitted. The resource kind is currently reported as `unknown` because the runtime finding does not expose it.

MCP registration emits `rheic.mcp.register` when a challenge is issued and when the registration is stored. Successful sandbox attachments emit `rheic.mcp.load`. Both hash server names and include correlation IDs when available. Load currently reports zero tools and an empty approval ID because attachment does not discover tools or create an approval.

Kit checks emit `rheic.kit.check` for allowed sources and source, local-kit, signature, invalid-reference, and unavailable-policy refusals. References are hashed. Missing approval providers emit `rheic.platform.unsupported`.

Approval lifecycle emits `rheic.approval.requested` at the two service creation points: the host-command source approval (`internal/service/service.go:190`, provider `os`) and the custom-secret source approval (`internal/service/custom_secrets.go:99`, provider `none` because this slice has no trusted grant provider). `rheic.approval.responded` covers every `RespondApproval` outcome (`internal/service/approvals.go:88` fail-closed provider-missing responses carry result `FAILED_PRECONDITION` and are still emitted, `:98` provider refusals resolve `DENY`, `:108` recorded decisions) plus the host-command internal resolutions (`internal/service/service.go:198`, `:206`). The resolved-entry retention sweep emits `rheic.approval.expired` (`internal/approvals/approvals.go:341`); the store has no request context, so those events carry no correlation IDs, and `ttl_ms` is the entry age at eviction. Only the approval ID, request class, disclosure boundary, provider and decision/result fields reach the catalog; an unspecified request class is not emitted.

Secret writes emit `rheic.secret.write` around each host-vault write attempt: service secret values (`internal/servicesecrets/store.go:161`, `:167`), service secret sources (`internal/servicesecrets/source.go:210`, `:216`) and custom secret records (`internal/customsecrets/store.go:70`, `:75`). `vault_backend` names the platform vault (`keychain` on darwin, `credman` on windows, `secretservice` elsewhere) and `placeholder_issued` is true only for custom records, whose write path echoes the placeholder exactly once. Vault account keys enter the catalog as SHA-256 digests; secret values, references and backend error text never appear. Substitution decisions emit `rheic.secret.substitute` from `internal/secretproxy/substitute.go`: `InsecureScheme` refusals on plaintext routes (`:61`), `VaultLocked` when the host resolver fails (`:68`), `RefMissing` for a binding without a usable placeholder (`:77`), and one `substituted` success per matched placeholder (`internal/secretproxy/substitute.go:109`), referenced by hashed placeholder. Ambiguous overlapping bindings have no catalog reason and are not emitted. Header and body values never enter these events.

Templates emit `rheic.template.save` and `rheic.template.load` from `internal/service/templates.go` (`:28`, `:66`, `:70`, `:73` for save; `:114`, `:119`, `:127`, `:130` for load) with outcome `ok`, `failed` or `unsupported`. Only the template name, layer count, byte size and digest that the flow already computed are reported; whiteouts, opaque dirs, host-workspace inclusion and guest-secrets warnings have no computed source in the runtime result and stay at their zero values.

Lifecycle emits start, ready and shutdown events; the socket path is represented by the first 12 SHA-256 bytes. The bundle digest is the SHA-256 of the configured digest file when readable. `managed_verify=ok` means startup configuration passed, not that artifacts have already been verified. Ready's recovered count is the existing reconciliation change count. Shutdown flushes the rotating file sink before emitting, so `flush_ok` reflects the actual flush result; the in-flight counter remains zero (no counter exists) and a missing signal is empty. Reconcile reports the number of sandbox records scanned; adopted, left-alone and generation-mismatch counts are unavailable and encoded as zero. Secret proxy credential denials emit peer credential rejection; a failed credential lookup has an unknown UID encoded as zero.

Create unwind and runtime verification decision points are in the external runtime module, and are not wired here. Refused managed configuration fails before daemon Run and does not currently emit a start event. MCP attestation and unsuccessful loads, and platform unsupported positions beyond the missing approval provider (headless vault, rootless refusals), remain uninstrumented.

## Log rotation

The daemon owns a rotating file sink at `$STATE/daemon.log` in addition to the stderr handler the launcher relies on for detached starts. Every record is fanned out to stderr (text) and to the file (JSON); stderr remains the level gate, so the file mirrors the stderr threshold. The file is opened through `slogx/rotate` with an async queue: the defaults are 8 MiB per active file, five archived files, and 64 MiB across the active file and archives. Rotation is size-based and the total cap evicts the oldest archives first, so a detached daemon cannot grow the state directory without bound.

The daemon start event is emitted before the state directory is prepared, so it appears on stderr only; ready, reconcile, shutdown and all later records are captured by both sinks.

The async queue is bounded (capacity 2048). A write that overflows the queue is dropped and counted; a monitor samples the counter once a minute and, when records were dropped, emits `rheic.obs.log_dropped` (`component=daemon`, `dropped_count`, `queue_len=2048`). The event is emitted to the stderr handler captured before the fan-out, never through the file sink, so reporting a dropped record cannot itself drop and recurse.

Rotation caps are configurable through the host settings file as `log.maxSizeMiB` (default 8), `log.maxFiles` (default 5) and `log.totalCapMiB` (default 64). Values must be positive; upper bounds are 4096 MiB per file, 256 files, and 65536 MiB total. A daemon restart applies changes.

## Canary coverage

| Event contour | Coverage |
| --- | --- |
| Daemon start, ready, shutdown | One event each; synthetic socket and state directory secrets are absent from event JSON. Ordinary daemon logs are outside this event-specific check. |
| Daemon reconcile | Two sandbox records are scanned; all four catalog counts are present, and sandbox names are absent from captured JSONL. |
| Peer credential rejection | One rejected peer; UID appears as a numeric `peer_uid` only, and the socket path and token are absent from the captured line. |

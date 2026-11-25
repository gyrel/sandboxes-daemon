# Daemon observability

The daemon accepts gRPC metadata keys `rheic-op-id`, `rheic-req-id`, and `rheic-parent-req-id`. It validates their expected prefixes and canonical formats before placing the operation and request IDs in the handler context. Invalid or missing values are regenerated and produce `rheic.obs.id_rejected` at debug level without logging the supplied value. Parent IDs are available through the server package's context accessor. Correlation IDs are not identity or authorization material.

Correlation context persists for the lifetime of an individual RPC stream. Propagation across gateway, runtime and guest boundaries, and continuity across separate resumed RPCs, require additional integration.

Journal recovery emits `rheic.journal.recover` for each recognized finding left in place. The event contains a mapped reason, a SHA-256 resource hash, and correlation IDs when available. Unknown reasons are not emitted. The resource kind is currently reported as `unknown` because the runtime finding does not expose it.

MCP registration emits `rheic.mcp.register` when a challenge is issued and when the registration is stored. Successful sandbox attachments emit `rheic.mcp.load`. Both hash server names and include correlation IDs when available. Load currently reports zero tools and an empty approval ID because attachment does not discover tools or create an approval.

Approvals, kit checks, MCP attestation and unsuccessful loads, templates, secrets, platform unsupported positions, and runtime launch remain uninstrumented.

Lifecycle emits start, ready and shutdown events; the socket path is represented by the first 12 SHA-256 bytes. The bundle digest is the SHA-256 of the configured digest file when readable. `managed_verify=ok` means startup configuration passed, not that artifacts have already been verified. Ready's recovered count is the existing reconciliation change count. Shutdown flushes the rotating file sink before emitting, so `flush_ok` reflects the actual flush result; the in-flight counter remains zero (no counter exists) and a missing signal is empty. Reconcile reports the number of sandbox records scanned; adopted, left-alone and generation-mismatch counts are unavailable and encoded as zero. Secret proxy credential denials emit peer credential rejection; a failed credential lookup has an unknown UID encoded as zero.

Create unwind and runtime verification decision points are in the external runtime module, and are not wired here. Refused managed configuration fails before daemon Run and does not currently emit a start event.

## Log rotation

The daemon owns a rotating file sink at `$STATE/daemon.log` in addition to the stderr handler the launcher relies on for detached starts. Every record is fanned out to stderr (text) and to the file (JSON); stderr remains the level gate, so the file mirrors the stderr threshold. The file is opened through `slogx/rotate` with an async queue: the defaults are 8 MiB per active file, five archived files, and 64 MiB across the active file and archives. Rotation is size-based and the total cap evicts the oldest archives first, so a detached daemon cannot grow the state directory without bound.

The daemon start event is emitted before the state directory is prepared, so it appears on stderr only; ready, reconcile, shutdown and all later records are captured by both sinks.

The async queue is bounded (capacity 2048). A write that overflows the queue is dropped and counted; a monitor samples the counter once a minute and, when records were dropped, emits `rheic.obs.log_dropped` (`component=daemon`, `dropped_count`, `queue_len=2048`). The event is emitted to the stderr handler captured before the fan-out, never through the file sink, so reporting a dropped record cannot itself drop and recurse.

Rotation caps are configurable through the host settings file as `log.maxSizeMiB` (default 8), `log.maxFiles` (default 5) and `log.totalCapMiB` (default 64). Values must be positive; upper bounds are 4096 MiB per file, 256 files, and 65536 MiB total. A daemon restart applies changes.

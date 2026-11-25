# Daemon observability

The daemon accepts gRPC metadata keys `rheic-op-id`, `rheic-req-id`, and `rheic-parent-req-id`. It validates their expected prefixes and canonical formats before placing the operation and request IDs in the handler context. Invalid or missing values are regenerated and produce `rheic.obs.id_rejected` at debug level without logging the supplied value. Parent IDs are available through the server package's context accessor. Correlation IDs are not identity or authorization material.

Correlation context persists for the lifetime of an individual RPC stream. Propagation across gateway, runtime and guest boundaries, and continuity across separate resumed RPCs, require additional integration.

Journal recovery emits `rheic.journal.recover` for each recognized finding left in place. The event contains a mapped reason, a SHA-256 resource hash, and correlation IDs when available. Unknown reasons are not emitted. The resource kind is currently reported as `unknown` because the runtime finding does not expose it.

MCP registration emits `rheic.mcp.register` when a challenge is issued and when the registration is stored. Successful sandbox attachments emit `rheic.mcp.load`. Both hash server names and include correlation IDs when available. Load currently reports zero tools and an empty approval ID because attachment does not discover tools or create an approval.

Approvals, kit checks, MCP attestation and unsuccessful loads, templates, secrets, platform unsupported positions, and runtime launch remain uninstrumented.

Lifecycle emits start, ready and shutdown events; the socket path is represented by the first 12 SHA-256 bytes. The bundle digest is the SHA-256 of the configured digest file when readable. `managed_verify=ok` means startup configuration passed, not that artifacts have already been verified. Ready's recovered count is the existing reconciliation change count. Shutdown has no flushable logger sink or in-flight counter: the catalog requires both fields, so they are false and zero; a missing signal is empty. Reconcile reports the number of sandbox records scanned; adopted, left-alone and generation-mismatch counts are unavailable and encoded as zero. Secret proxy credential denials emit peer credential rejection; a failed credential lookup has an unknown UID encoded as zero.

Create unwind and runtime verification decision points are in the external runtime module, and are not wired here. Refused managed configuration fails before daemon Run and does not currently emit a start event.

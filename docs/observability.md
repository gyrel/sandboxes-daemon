# Daemon observability

The daemon accepts gRPC metadata keys `rheic-op-id`, `rheic-req-id`, and `rheic-parent-req-id`. It validates their expected prefixes and canonical formats before placing the operation and request IDs in the handler context. Invalid or missing values are regenerated and produce `rheic.obs.id_rejected` at debug level without logging the supplied value. Parent IDs are available through the server package's context accessor. Correlation IDs are not identity or authorization material.

Correlation context persists for the lifetime of an individual RPC stream. Propagation across gateway, runtime and guest boundaries, and continuity across separate resumed RPCs, require additional integration.

Journal recovery emits `rheic.journal.recover` for each recognized finding left in place. The event contains a mapped reason, a SHA-256 resource hash, and correlation IDs when available. Unknown reasons are not emitted. The resource kind is currently reported as `unknown` because the runtime finding does not expose it.

The remaining daemon lifecycle, approval, kit, MCP, template, secret, platform and runtime catalog contours are not yet instrumented by this change.

# Changelog

## Unreleased

## v0.0.56 — 2026-11-15

### Added

- Centralize network policy evaluation in the pure `orgpolicy.Apply` evaluator used by every create, start and policy-update path. Organization deny rules keep precedence over local rules, local allows and denies are preserved, organization allows stay advisory so they can never widen access, and duplicate targets are removed deterministically.
- Accept registry endpoints with an explicit non-default port and IPv4 or IPv6 literals in registry credentials, private-registry settings, realm/redirect configuration, and broker request routing. Authorities are normalized with bracketed IPv6 literals, and ambiguous forms with userinfo, paths, schemes, wildcards, or invalid ports are rejected.
- Evaluate registry egress policy against the exact normalized host and TCP port the broker dials, so a custom-port registry cannot reuse a rule for port 443.

### Fixed

- Apply the effective global, organization and sandbox egress policy when `exec` auto-starts a stopped sandbox. Auto-start now shares the same policy resolution as an explicit start and fails closed if the global policy cannot be loaded.

### Security and limitations

- When organization policy enforcement is enabled, a missing or unparsable stored bundle still fails closed with a typed `ErrBundleMissing` or `ErrBundleInvalid` conflict before any sandbox start reaches the runtime.
- The broker keeps HTTPS-only forwarding, DNS hostname verification, exact host-header routing, and exact redirect/realm authority matching. IP-literal registries verify the certificate IP SAN and do not invent an SNI name.
- Live VM pull/push acceptance for custom-port and IP-literal registries remains unverified.
- Expose the effective organization policy through `SandboxService.GetOrgPolicy`.
  The read-only view reports the organization, bundle schema version and
  revision, a SHA-256 payload fingerprint, enforcement state, load and expiry
  times, and parsed network allow/deny rules marked enforced or advisory. It
  never returns signatures, tokens or other secret material and fails closed
  with typed gRPC statuses for missing or invalid bundles.
- Annotate local network rules with `origin = "local"` so clients can
  distinguish them from organization rules once the API contract is bumped.
- Depend on `github.com/rheic/sandboxes-api` v0.0.26. That release carries the
  additive `GetOrgPolicy` RPC and `NetworkRule.origin`; downstream modules must
  bump the API contract together.

## v0.0.52 — 2026-11-11

### Fixed

- Open daemon and control-plane SQLite databases using escaped file URLs so URI characters in filesystem paths cannot alter the selected database or PRAGMA settings.

### Security and limitations

- SQLite secure deletion does not erase old APFS snapshots or storage-device remanence; same-UID filesystem races remain inside the host user's trust boundary.
- This patch does not close full Docker Sandboxes parity or the independent M7 security review gate.

## v0.0.51 — 2026-11-11

### Changed

- Update the runtime dependency to v0.0.30, bringing the experimental Linux ARM64 runtime build into the daemon release graph.

### Security and limitations

- Linux VM support remains experimental and limited to privileged rootful acceptance in a macOS-hosted Ubuntu ARM64 VM. Native Linux-host and rootless acceptance remain open.
- This dependency update does not establish full Docker Sandboxes parity or independent M7 security review.


## v0.0.50 — 2026-11-09

- Reject all static remote MCP headers and require host-vault placeholders for every header value.
- Migrate schema-v2 registry rows and managed backups to schema v3, removing static values before serving RPC.
- Update the sandboxes-api module dependency to v0.0.24.
- Bind vault header injection to the approved HTTPS host and port; validate stored remote URL syntax before serving.
- Enforce private Unix daemon state-directory permissions before opening SQLite.

## v0.0.49 — 2026-11-08
- Bind M7 release and image publication approval to the exact reviewed commit.
- Add typed host-vault-backed remote MCP headers, validate and persist only placeholder references, and resolve values at request time.
- Version the persisted MCP registry and run a forward migration at daemon startup. Legacy remote static `headers` are removed before any RPC is served because an old value may be a persisted credential; server records, destinations, vault placeholder templates, stdio entries and unrelated settings are preserved. The same legacy static `headers` are scrubbed in place from pre-upgrade `.pre-v<version>-*.bak` database backups beside the active database, without deleting the backups. SQLite secure deletion overwrites removed bytes; a one-time active-database vacuum removes old freelist remnants, then startup checkpoints/truncates the WAL before serving RPCs. The vacuum may require temporary space proportional to the database size. Migration or backup-sanitization failure aborts startup and is retried on restart. The change is an intentional alpha compatibility break and old static header values cannot be restored automatically.
- Include the normalized remote destination and value-free header scope (name and host-vault placeholder identifiers) in trusted MCP registration and call approvals. Header values and resolved secrets are never exposed to the approval provider; pending calls are invalidated if the destination or header configuration changes during approval.
- Align API, gateway and runtime dependencies with the latest released modules, including the IPv6 RA refresh fix in runtime v0.0.29.
- Update host keyring and SQLite dependencies to their latest compatible releases.
- Update golang.org/x/sys from v0.49.0 to v0.50.0.

# Changelog

## Unreleased

### Fixed

- Docker account sign-in no longer collapses every failure into
  `OAuth login failed; no credentials were returned`. Existing Docker
  credentials and an unreachable host keychain now produce distinct actionable
  messages, and the host keychain sentinel (`ErrHostKeychainUnavailable`) is
  propagated from the vault instead of being reported as "no credentials".

## v0.0.62 — 2026-11-16

### Removed

- Remove unused compatibility helpers left by the custom-registry-port work:
  the old host/port splitter, the authority-string dial wrapper, and the
  duplicate registry-host validator. Registry endpoint normalization continues
  to use `ParseRegistryEndpoint`.
- Remove the unused exported `RegistryEndpoint.DialAuthority` helper. Callers
  already dial the normalized `Hostname` and `PortString`.
- Drop a stale build-output ignore entry for the retired helper binary name;
  current helper assets build under `bin/` or an explicit output path.

### Changed

- Update API to v0.0.28, core to v0.0.13, gateway to v0.0.21, and runtime to v0.0.34.

- Release workflows no longer require the M7 external security review
  environment or an exact-SHA M7 approval variable. Release candidate
  validation, full CI on the candidate SHA, immutable tag creation, tag
  ancestry checks and release asset immutability remain mandatory. This follows
  the owner decision of 2026-11-16 that external review and separate approval
  are not required for release after fully green mandatory CI.

## v0.0.61 — 2026-11-16

### Changed

- New sandboxes default to the allow-all egress profile, matching the Docker
  sbx baseline. Explicit deny rules, organization deny precedence and every
  fail-closed control are unchanged; `deny-all` remains selectable through
  `--policy-profile` and settings.

### Added

- Policy engine evaluates HTTP conditions (`method`, `path` glob, `query`) with
  deny precedence, and same-scope allow/deny conflicts are rejected with a typed
  error naming both rules.

## v0.0.60 — 2026-11-16

### Added

- Depend on gateway `v0.0.20`, which evaluates HTTP policy conditions
  (`method`, `path` glob, `query`) on the bounded request head with deny
  precedence and fail-closed handling of unevaluable conditions.

### Security and limitations

- Conflicts between allow and deny rules in the same scope are rejected with a
  typed error naming both rules.
- A rule whose conditions cannot be evaluated does not match; it never falls
  back to matching everything.
### Security

- Match the Docker sbx baseline for new sandboxes: the default network policy
  profile is now `allow-all` (TCP and UDP to `0.0.0.0/0`) instead of `deny-all`.
  This is an explicit owner decision (2026-11-16) to avoid diverging from sbx
  defaults "for now". `--policy-profile deny-all`, `--policy deny-all`,
  `rsbx policy init deny-all` and `default_policy_profile = "deny-all"` still
  select default-deny. The resolved profile is logged at sandbox creation.
  Explicit deny rules, organization deny precedence, DNS fail-closed behavior,
  host-service/registry restrictions and loopback-only published ports are
  unchanged; an unenforceable organization domain deny still fails creation
  closed.

## v0.0.59 — 2026-11-16

## v0.0.58 — 2026-11-16

### Added

- Return non-secret secret-inventory metadata over the local RPC so JSON
  inventories can match the Docker `sbx secret ls --json` shape: creation and
  update times, source kind, refresh policy and capability, coarse secret type,
  and origin for service secrets; creation and update times and origin for
  registry credentials. Responses never carry a secret value, reference,
  command, password, or environment value.
- Advance the persisted SQLite schema to version 5 with additive secret-index
  metadata columns. Existing rows are preserved; service creation time is
  backfilled from the existing update time when available.
- Depend on `github.com/rheic/sandboxes-api` v0.0.27, the additive local RPC
  contract carrying the secret metadata fields. Downstream modules must use the
  same contract release.
- Add a local daemon lifecycle control surface. The daemon now writes a private
  `daemon.installation`, `daemon.control.json` and `daemon.loglevel.json` in its
  state directory after the socket is listening, removes the control record on
  graceful shutdown, and applies `general`/`proxy` log-level changes without a
  restart. `sandboxesd --policy allow-all|balanced|deny-all` initializes the
  global policy profile used by `rsbx daemon start --policy`.
- Add process-start identity checks and installation/socket matching before a
  supervisor may signal the daemon. Linux uses the boot ID plus `/proc` start
  ticks, macOS uses `kern.proc.pid` start time, and Windows uses process
  creation time; missing or unverifiable identity fails closed.

## v0.0.57 — 2026-11-15

### Fixed

- Make sandbox creation crash-safe. `Create` now persists a `creating` intent row before allocating the Docker volume, starting the proxy or creating the VM, and commits the running/stopped state and completed operation atomically at the end. A crash at any point leaves a row that `Reconcile` can find; reconcile removes the runtime, proxy state, volume, settings and intent row for an interrupted create, so a running VM can no longer outlive its record. A create that fails before starting the VM is cleaned the same way, and cleanup retries are idempotent.
- Paginate global policy refreshes across every sandbox instead of silently stopping at the first page. `RefreshPolicies` and the live refresh used by global-policy mutations now reuse the full-list pager, and a failure to update any sandbox is returned as an error naming that sandbox while the applied count remains available.
- Make sandbox deletion durable and retryable. `Delete` now marks the sandbox as deleting, removes secrets, registry credentials, proxy state, settings and the Docker volume before atomically deleting the row, and records a failed delete operation when cleanup fails instead of dropping the row. `Reconcile` finishes pending deletes left by an interrupted cleanup, and every cleanup step is idempotent so retries remove each host resource exactly once.
- Build alias service proxy routes such as `github-web` and `cursor-api3` by resolving the shared credential service instead of validating the alias name against the service secret store. Rotating or removing a shared credential now updates or removes every live alias route without a sandbox restart, and a route that cannot apply a credential update is stopped rather than continuing to serve the previous credential.
### Security

- Require a random per-sandbox token on the managed clone Git endpoint. The
  guest `git daemon` now runs with an `--access-hook` that rejects every request
  whose path is not `/<token>/<repository>`, compares the token in constant time,
  and fails closed when the token material is missing. The token is generated
  from the operating system CSPRNG for every create and start, remains only in
  daemon state for the sandbox lifetime, is removed from the guest and the
  stored endpoint on stop/delete, and is redacted from clone errors. A
  loopback process can no longer fetch a private clone without the token.

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

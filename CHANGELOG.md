# Changelog

## v0.0.85 — 2026-11-23

### Fixed

- Consume runtime v0.0.54: template diff planning skips unchanged links
  and directories and no longer attaches payload readers to non-regular
  entries, fixing the `entry "bin" of type "symlink" must not carry a
  reader` failure of `template save` against alpine-family bases.

## v0.0.84 — 2026-11-23

### Fixed

- Consume runtime v0.0.53: template base listing now decodes compressed
  registry layer blobs (tar+gzip/tar+zstd), fixing the
  `archive/tar: invalid tar header` failure of `template save` against
  every real Docker Hub base image.

## v0.0.83 — 2026-11-23

### Fixed

- Consume runtime v0.0.52: template base resolution now follows
  multi-platform OCI indexes (registry images ship per-arch manifests
  plus attestation entries), so `template save` can read the base image
  of any registry-pulled sandbox; ambiguous indexes still fail closed.

## v0.0.82 — 2026-11-23

### Fixed

- Consume runtime v0.0.51: the template capture index no longer rejects
  guest paths containing `x` or `0`, so `template save` can complete
  against a live guest (the v0.0.81 capture finished the tar but the
  index step refused ordinary paths).

## v0.0.81 — 2026-11-22

### Fixed

- Shared skills for an agent without a guest skills directory (e.g.
  `shell`) are now a no-op instead of a `conflict` error, matching live
  `sbx run shell` behavior with the sbx-default `skills.defaultMode`
  readonly. Nothing is mounted, so the path stays fail closed; readwrite,
  empty-mode and off-with-path requests are still rejected before the
  agent check. This completes the skills default-mode pairing with CLI
  v0.0.65+ (`prepareSkillsOption`), whose catalog-default resolution made
  `rsbx run shell` fail against daemons without this fix.
- Consume runtime v0.0.50: template capture now excludes guest virtual
  filesystems (`proc`, `sys`, `dev`, `run/bundles`) and reports bounded
  tar diagnostics, fixing the live `template save` exit-2 failure.

## v0.0.80 — 2026-11-22

### Added

- `TemplateService.Export` handler: exports a recorded template to a
  docker-save archive via the daemon service (exclusive-create) and
  reports the written size; unrecorded names map to NotFound. api pinned
  to v0.0.35 (contract 0.0.35).

## v0.0.79 — 2026-11-22

### Added

- Local `TemplateService` (ADR-0008): save records a template from a
  stopped or running sandbox (stopped sandboxes are booted only for the
  capture and restored to stopped afterwards; running sandboxes are
  captured in place; transient states are refused), load imports OCI or
  docker-save archives with digest recording, remove is guarded against
  sandbox references even with force, list/inspect read the stored
  records and merge the live boot document (env names only, presence
  contract). Templates DDL ships in schema v6 with the standard pre-
  migration backup.

### Compatibility

- Requires runtime v0.0.49 (public `runtime.TemplateBackend`); the
  service refuses template operations with a conflict error on
  backends without the capability.

## v0.0.78 — 2026-11-22

### Changed

- Release notes tooling only: the extractor requires a section named for the
  tag being cut. v0.0.75 and v0.0.76 shipped tags without matching sections
  and their GitHub Releases could not be published; v0.0.78 carries the
  same daemon tree as v0.0.77 plus this notes fix and publishes normally.
  No functional change relative to v0.0.77.

## v0.0.76 — 2026-11-22

### Added

- HTTP L7 policy conditions end to end (contracts 0.0.31/0.0.32): stored and
  live rules carry canonical `Methods`, `Path` and `Query` selectors
  validated by the gateway grammar; content-derived rule IDs change with
  conditions while L4-only IDs keep their historical hashes; `CheckPolicy`
  accepts absolute HTTP(S) URL targets with an optional method (credentials,
  fragments and non-HTTP schemes are refused, the query string never
  reaches logs or reasons). Registry proxy decisions evaluate the same
  conditions.

## v0.0.75 — 2026-11-22

### Added

- Transient create pull progress published through `Watch` as advisory
  `operation` events (never persisted; cleared on success and abort).
- Docker account identity (`signed in as <user>`) resolved from the
  global-scoped Docker Hub index entry; presence-only, no token material.
- sbx sandbox naming rules enforced at creation.
- Skills requests for agents without a guest directory become a no-op mount
  instead of a conflict; readwrite/empty-mode/off-with-path still rejected
  before the agent check (fail closed preserved).

### Compatibility

- Watch consumers must ignore unknown event types; daemons pair with CLI
  companions at or above this release for skills default parity.

## v0.0.74 — 2026-11-19

### Fixed

- Consume runtime v0.0.41 so a restarted daemon can reattach and clean a
  macOS private shared-skills snapshot as well as the Linux bind pin.


## v0.0.73 — 2026-11-19

### Fixed

- Consume runtime v0.0.40, which preserves and cleans the shared-skills pin
  across a daemon restart. A restarted daemon can now reattach the pin after
  the sandbox is moved out of `unknown` state, and delete removes the pin.


## v0.0.72 — 2026-11-19

### Fixed

- Include bounded guest-helper stderr/stdout in shared-skills startup errors so
  a failed linker is actionable instead of a bare exit status.
- Consume runtime v0.0.39, which exports the fd-pinned store through a private
  bind mount. This fixes `open /run/rheic/agent-skills: input/output error` on a
  real Linux KVM host.


## v0.0.71 — 2026-11-19

### Added

- Accept the shared skills options on create, validate the fixed host store and
  a static Linux guest helper, and pass a read-only mount to the runtime.
- Run the guest linker as the sandbox user after start and replay it on later
  starts from the persisted mode.
- Allow additional read-only clone reference workspaces mounted by host path.

### Security

- Custom guest paths for additional clone workspaces are rejected before any
  mount because an image symlink can only be observed after the mount exists.
- Read-write shared skills remain fail closed.


## v0.0.70 — 2026-11-19

### Security

- Require a trusted host approval provider before storing or executing a
  persistent secret-source command. The provider receives the exact command,
  service, scope, and sandbox name; a missing provider or denied approval fails
  closed before the command runs. `NoVerify` cannot bypass consent.
- Require explicit runtime artifact verification mode: `--artifact-digests` plus
  at least one `--runtime-artifact name=absolute-path`, or an explicit
  `--allow-unmanaged-runtime` opt-in. Verified artifacts are passed to the
  runtime backend before create/start.

### Tests

- Cover missing, denied, and exact-binding host-command approvals, including a
  marker-file negative control.
- Cover the managed/unmanaged runtime verification matrix and Windows absolute
  paths.

## v0.0.68 — 2026-11-19

### Security

- Serve the per-sandbox secret proxy through the peer-checking listener instead
  of the raw Unix listener, so the same-owner peer check and rejected-peer
  counter are actually applied.
- Fail closed when POSIX peer credentials cannot be read on Linux or Darwin;
  previously an unverifiable peer was accepted. Transports without POSIX peer
  credentials, such as Windows named pipes, keep their platform ACL model.

### Tests

- Add a wiring test that requires `StartUnixRoutes` to expose the
  `peerCheckingListener`, and change the unverifiable-peer test to require
  rejection with a rejected-counter increment.

## v0.0.67 — 2026-11-18

### Changed

- Route the daemon's default text logger through the released
  `github.com/rheic/slogx` module while preserving live level changes from the
  lifecycle log controller. Record formatting stays text on stderr; masking and
  context behavior use slogx defaults. Require Go 1.27.4 and update
  OpenTelemetry to v1.47.0.

### Tests

- Cover the level-controller adapter: debug records stay hidden at info and
  appear after the live level changes to debug.

## v0.0.66 — 2026-11-18

### Added

- Discover the static Linux guest proxy helper without consulting `PATH` when
  `--proxy-helper` is empty. The daemon checks
  `rheic-proxy-helper-linux-<goarch>` next to the running executable and in a
  `bin/` subdirectory. An explicit `--proxy-helper` still wins. Every candidate
  and the explicit path use the existing static-ELF validator; a missing,
  relative, symlinked, non-executable, wrong-architecture or dynamically linked
  helper makes proxy-backed create/start/exec fail closed with an actionable
  error that lists the searched locations.

### Security

- Track hijacked/upgraded service-proxy connections explicitly. An active Codex
  WebSocket or registry CONNECT tunnel is now closed when its sandbox policy
  revision changes, when the backing credential route is revoked, and when the
  proxy channel is torn down. This is fail-closed: a long-lived stream can no
  longer outlive the policy or credential under which it was authorized. Only
  the affected sandbox is selected, and normal HTTP request/response handling is
  unchanged.
- Add a deterministic synthetic Codex transport-evidence harness. Test-only
  counters report whether the real Codex client used an upgraded WebSocket or
  HTTP fallback; no production tracing is added and no credential value is
  recorded.

### Tests

- Cover policy-revision closure of an active upgrade, unaffected normal HTTP
  responses, hijacked-connection cleanup after peer close and teardown, and
  sandbox-scoped revocation (no cross-sandbox closure).

## v0.0.65 — 2026-11-18

### Fixed

- Accept static Linux AMD64 guest proxy helpers in addition to ARM64. The AMD64
  helper is published as a release asset, but the validator previously rejected
  it, so x86_64 hosts could not use the released artifact. Other architectures
  and dynamically linked helpers remain rejected.
- Document that downloaded helpers need `chmod +x` and an absolute
  `--proxy-helper` path.

## v0.0.64 — 2026-11-18

- Route the OpenAI OAuth broker to the scoped ChatGPT Codex endpoint and support WebSocket upgrades on that route.
- Include Linux proxy helper binaries in release assets.

## v0.0.63 — 2026-11-17

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

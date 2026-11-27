# Changelog

## v0.0.108 — 2026-11-28

### Added

- Settings key `network.publish.allowedCIDRs` grants non-loopback host port
  binds for exact CIDR prefixes (strict `net/netip` parsing, no host bits,
  single-host `/32` and `/128` accepted). The default stays loopback-only; an
  absent, empty, or malformed list fails closed with `BIND_FORBIDDEN`. Wildcard
  bind requests (`0.0.0.0`, `::`) remain forbidden even under `0.0.0.0/0`.
  Every granted non-loopback publish emits `gyrel.port.publish-granted`, stored
  ports are re-authorized on each start, and the key is restart-required.

## v0.0.107 — 2026-11-28

### Fixed

- Adopted runtime v0.1.4: a failed create now retires its journal record and
  stale pending records are reclaimed on retry, so a same-name recreate after
  a mid-create failure no longer blocks on `start create journal … file
  exists` (J-1, reproduced live during r7 acceptance).

## v0.0.106 — 2026-11-27

### Security

- Sandbox labels: create validates through the core grammar and refuses with
  `LABEL_INVALID` before any state mutation; schema v9 persists labels;
  corrupted stored records classify `UNKNOWN_STATE` ahead of ownership checks.
  Get/List return labels with nil omitted; create-replay compares the map.
- Test infrastructure: a redaction assertion harness with a mandatory
  self-detection control covers the verb paths (X-3).

## v0.0.105 — 2026-11-27

### Security

- Sandbox inventory rows now carry persisted ownership (`owner_uid` + `install_id`,
  schema v8, backfilled in the migration transaction). A single classifier gates
  Get/List/Stop/Delete/UpdatePorts/reconcile: foreign or malformed records refuse
  with stable machine codes (`NOT_OWNED`, `PATH_ESCAPE`, `UNKNOWN_STATE`); a
  database file copied to another installation fails closed for every row.
  List reports hidden-row counts via the `sandbox-hidden-count` response header.
- Refusals across the eight verb RPC paths attach stable reason codes carried in
  `google.rpc.ErrorInfo` alongside legacy gRPC codes.

## v0.0.104 — 2026-11-26

### Fixed

- Strip the product header namespace from brokered egress: the tunnel route
  marker now travels as a request-context value (never on the wire), and
  guest-forged `X-Gyrel-*` / `X-Rheic-*` headers are dropped before upstream.

## v0.0.103 — 2026-11-26

### Fixed

- Write structured JSON daemon logs so the diagnostic archive guard can distinguish startup field names from their digest values.

## Unreleased

### Changed

- Rename the brand from Rheic to Gyrel (breaking, pre-1.0 alpha policy): module
  path `github.com/rheic/sandboxes-daemon` → `github.com/gyrel/sandboxes-daemon`
  and the dependency chain (api v0.0.39, core v0.1.0, gateway v0.1.0, runtime
  v0.1.0, slogx v0.3.0). gRPC correlation metadata keys `rheic-op-id`,
  `rheic-req-id`, `rheic-parent-req-id` become `gyrel-*`; event names move to the
  `gyrel.*` prefix via slogx v0.3.0; `RHEIC_*` test canary environment variables
  become `GYREL_*`. On-disk identifiers (`com.rheic.*` keychain services,
  `rheic-keychain-chunks-v1` manifest prefix, `~/.config/rheic/settings.toml`,
  the skills store, the control-plane `rheic-server.db`, and the policy signing
  domain `rheic-policy-payload`) are retained for data-migration safety and
  flagged for a follow-up ruling.

## v0.0.98 — 2026-11-24

### Fixed

- Pass the daemon state directory into the runtime backend options so
  ADR-0009 journal recovery roots at the real state dir instead of the
  default /var/lib/rheic (which logged a fail-closed recovery warning on
  every start).

## v0.0.97 — 2026-11-24

### Added

- Daemon implementation of MCP management RPCs (api v0.0.38): `MCPLoadServer`,
  `MCPUnloadServer`, `InspectMCPServer`, `GetMCPAuthStatus`, `RemoveMCPAuth`,
  and `StartMCPAuth`. Load/unload track per-sandbox gateway attachment state;
  inspect returns a sanitized `MCPServerDetail` (identity display fields only);
  auth status maps stored OAuth vault state to the contract enum; remove-auth
  deletes vault records and drops cached sessions without removing registrations.
- Registration accepts and validates OAuth fields 8-15 (authorization server URL
  without userinfo/query, client id, resource, scopes/no_scope exclusivity,
  skip_auth, callback port bounds, disable_http2) and stores them in the registry.

### Notes

- Interactive OAuth discovery/DCR/browser flow and live gateway tool
  notifications are not implemented in this daemon; `StartMCPAuth` returns
  `FAILED_PRECONDITION` and unload reports detachment on next attach. These
  seams are left for the architect.

## v0.0.96 — 2026-11-24

### Added

- ADR-0009 step 5: the gateway network adapter implements
  `runtime.NetworkAttester` (token-bound starts; attachment state
  absent/owned/foreign, fail-closed for unknown), and the daemon
  reconciles runtime create journals at startup via
  `Service.RecoverRuntimeJournal` before serving RPCs. Individual
  LEAVE-decisions are logged as findings; systemic recovery errors are
  logged loudly without bricking startup (journals persist for the next
  start). Stale proxy socket/directory removal paths already enforce
  lstat+uid+live-listener checks (verified, unchanged).


## v0.0.95 — 2026-11-24

### Fixed

- Consume runtime v0.0.61: `create` starts the VM network only after proxy
  and skills validation, so a failed create no longer leaks a network
  attachment.

## v0.0.94 — 2026-11-24

### Added

- `KitPolicyService` (api v0.0.37): `CheckKit` and `GetKitPolicyConfig` RPCs
  registered like sibling services. `CheckKit` validates source kind and
  source references (userinfo/query rejected as `INVALID_REFERENCE` without
  echoing the reference), applies local kit settings and managed organization
  policy (managed deny is sticky), and returns fail-closed decisions.
- Settings keys `kit.allowedSources` (directory/zip/git/oci; default
  directory+zip), `kit.allowLocalKits` (default true) and `kit.requireSignature`
  (default false) with strict validation.
- Exported `Service.CheckKitSource` for the future kit install path.

## v0.0.93 — 2026-11-24

### Added

- `ApprovalService` (api v0.0.36): in-memory pending-approval store with
  `List`, `Inspect` and `Respond`. Entries carry only the contract disclosure
  fields; secret material is unrepresentable. IDs are generated with
  crypto/rand. Resolved approvals are retained for 24 hours or 100 entries,
  whichever bound is hit first.
- `SetApprovalProvider` seam on `Service`. The daemon ships without a trusted
  OS-backed provider, so every `APPROVE` and every `EXACT` persist fails
  closed with `FAILED_PRECONDITION`. `DENY` is always accepted for a pending
  approval. `UNSPECIFIED` decision is `INVALID_ARGUMENT`; unspecified persist
  means `ONCE`.
- `SecretService.SetCustom` reference and command sources now create a pending
  approval (command -> `HOST_COMMAND`, reference -> `OTHER`) and return
  `approval_required=true` with an `approval_id`, storing nothing secret-side.
  Inline values are unchanged.
- Host-command secret sources register a pending approval when they challenge,
  so `policy approval ls` observes them. Exact command/service/scope binding
  and `NoVerify` semantics are unchanged.

### Not yet available

- Trusted OS-backed approval provider (P1.3) and granting on approval.
- MCP registration/call challenges are tracked in the same store, but their
  resolution still uses the MCP approval endpoints.
- Custom secret reference/command sources store nothing until a future
  provider grants approval.

## v0.0.92 — 2026-11-24

### Added

- `SecretService.SetCustom` (api v0.0.36): a custom secret binds a
  sandbox-visible placeholder to a host-vault value and a set of destination
  host patterns. Inline values are stored only in the OS keychain. SQLite keeps
  the masked placeholder, host patterns and environment name. Responses return
  the full placeholder once on write and never the value.
- Host patterns accept exact DNS names, IP literals, `*` (one label) and `**`
  (one or more labels). URLs, userinfo, ports, paths and bare wildcard suffixes
  are rejected.
- Proxy substitution: on an https route, a placeholder in a guest request header
  is replaced with the matching host-vault value before the request is
  forwarded. A resolver error, an ambiguous placeholder set or a plaintext route
  never substitutes and fails closed.
- Custom secrets with an environment name inject the placeholder into the
  sandbox environment at create. Only the placeholder is injected.
- `SecretService.List` returns custom secrets. `SecretService.Remove` removes
  them and closes streams authorized under them.
- Values larger than one keychain item use the shared chunked format
  (`rheic-keychain-chunks-v1:`), now in `internal/keychainchunks`.

### Not yet available

- `reference` and `command` sources return `FAILED_PRECONDITION`. Approval
  requires a trusted OS-backed provider and an ApprovalService, neither of
  which exists in this daemon yet.
- Custom substitution applies only on proxy channels that already exist for the
  sandbox. A sandbox with no brokered route for a host does not substitute for
  that host.

### Changed

- Consume sandboxes-api v0.0.36 for `SetCustom` and the custom
  `SecretSummary` fields.
- Store schema v7 adds `custom_secret_index`. The migration runs in one
  transaction, and the pre-upgrade backup is taken as for earlier versions.

## v0.0.91 — 2026-11-24

### Fixed

- Consume runtime v0.0.60: template imports register under the exact
  normalized name (`--base-name` plus the OCI index ref-name annotation)
  instead of containerd's generated `import-<date>` reference, so
  `template save` completes import verification. Templates saved by
  older runtimes carry annotation-less archives; re-save them.

## v0.0.90 — 2026-11-24

### Fixed

- Consume runtime v0.0.59: template capture excludes are root-anchored
  (`./proc`, `./sys`, `./dev`, `./run`), so nested directories with those
  names stay in the capture, `/run` runtime state no longer enters
  templates, and deleted base directories fold into one whiteout instead
  of whiteouts inside a whiteout that the erofs differ rejected with
  `Not a directory`.

## v0.0.89 — 2026-11-23

### Fixed

- Consume runtime v0.0.58: template assembly keeps the base config
  `rootfs.diff_ids` instead of rebuilding them from layer descriptors,
  so `ctr images import` no longer rejects registry-shaped layers with
  `wrong diff id calculated on extraction` during `template save`.

## v0.0.88 — 2026-11-23

### Fixed

- Consume runtime v0.0.57: `ctr images import` passes the configured
  platform and snapshotter like the pull path, so template save can
  record the image against the managed containerd (which defines no
  default unpack platforms).

## v0.0.87 — 2026-11-23

### Fixed

- Consume runtime v0.0.56: capture indexing skips the archive root
  marker (`./`), fixing the live `template save` failure
  `plan references 1 entries absent from capture (first: [])`.

## v0.0.86 — 2026-11-23

### Fixed

- Consume runtime v0.0.55: hardlink targets are canonicalized across
  capture/base/stream and diff layers are guaranteed self-contained
  (emitted hardlinks drag their target; dangling, virtual or
  excluded-directory targets fail closed), fixing the live
  `bad hardlink target on usr/bin/perl5.40.1` save failure.

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

package settings

// KeyMetadata describes one supported host settings key and how a change takes
// effect. The daemon has no settings hot-reload path: every key is read while
// the process starts, so every key is restart-required. kit.*, log.* and
// network.publish.* follow the same rule.
type KeyMetadata struct {
	Key     string
	Restart bool
}

// keyCatalog is the canonical key list. Aliases accepted by parse are folded
// into their canonical dotted key.
var keyCatalog = []KeyMetadata{
	{Key: "dns_upstream", Restart: true},
	{Key: "mcp.remote.allowedHosts", Restart: true},
	{Key: "default_policy_profile", Restart: true},
	{Key: settingDefaultCPUs, Restart: true},
	{Key: "default_memory_mib", Restart: true},
	{Key: "docker_volume_size", Restart: true},
	{Key: "org_policy.enforce", Restart: true},
	{Key: "org_policy.org", Restart: true},
	{Key: "policy_sync.url", Restart: true},
	{Key: "policy_sync.org", Restart: true},
	{Key: "policy_sync.public_key_file", Restart: true},
	{Key: "policy_sync.token_file", Restart: true},
	{Key: "policy_sync.interval", Restart: true},
	{Key: settingRegistryDockerGrants, Restart: true},
	{Key: "registry_private_grants", Restart: true},
	{Key: settingRegistryPrivateHost, Restart: true},
	{Key: settingRegistryPrivateService, Restart: true},
	{Key: settingRegistryPrivateRealms, Restart: true},
	{Key: settingRegistryPrivateRedirects, Restart: true},
	{Key: settingRegistryPrivateCA, Restart: true},
	{Key: "network.publish.allowedCIDRs", Restart: true},
	{Key: "kit.allowedSources", Restart: true},
	{Key: "kit.allowLocalKits", Restart: true},
	{Key: "kit.requireSignature", Restart: true},
	{Key: "log.maxSizeMiB", Restart: true},
	{Key: "log.maxFiles", Restart: true},
	{Key: "log.totalCapMiB", Restart: true},
}

// Catalog returns the canonical key metadata in declaration order.
func Catalog() []KeyMetadata {
	return append([]KeyMetadata(nil), keyCatalog...)
}

// RequiresRestart reports whether key is known and whether it takes effect only
// after a daemon restart.
func RequiresRestart(key string) (restart, known bool) {
	for _, metadata := range keyCatalog {
		if metadata.Key == key {
			return metadata.Restart, true
		}
	}
	return false, false
}

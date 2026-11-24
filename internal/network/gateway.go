// Package network adapts the gateway manager to the runtime network contract.
package network

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	gateway "github.com/rheic/sandboxes-gateway"
	"github.com/rheic/sandboxes-gateway/policy"
	runtime "github.com/rheic/sandboxes-runtime"
)

// Manager is the subset of the gateway manager used by the adapter.
type Manager interface {
	Start(ctx context.Context, p policy.Policy) (gateway.Network, error)
	Reload(ctx context.Context, p policy.Policy) error
	SetPorts(ctx context.Context, name string, ports []policy.Port) error
	Stop(ctx context.Context, name string) error
}

// Adapter supplies default-deny gateway attachments to the runtime.
type Adapter struct {
	manager  Manager
	auditDir string
	mu       sync.Mutex
	owned    map[string]string
}

// New creates a gateway network adapter.
func New(manager Manager, auditDir string) *Adapter {
	return &Adapter{manager: manager, auditDir: auditDir, owned: make(map[string]string)}
}

// Start starts a gateway with a default-deny policy.
func (a *Adapter) Start(ctx context.Context, sandbox string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	attachment, err := a.start(ctx, sandbox, ports, allow, deny)
	if err == nil {
		// Running, but not bound to any journal token: recovery must treat
		// it as foreign rather than assume it is its own.
		a.owned[sandbox] = foreignBinding
	}
	return attachment, err
}

func (a *Adapter) start(ctx context.Context, sandbox string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	net, err := a.manager.Start(ctx, policy.Policy{
		// The start policy uses the same monotonic generation as later
		// reloads so an audit revision never jumps backwards.
		Revision:  int(time.Now().UnixNano()),
		SandboxID: sandbox,
		AuditPath: filepath.Join(a.auditDir, sandbox+".audit.jsonl"),
		Ports:     policyPorts,
		Allow:     toPolicyRules(allow, policy.Allow),
		Deny:      toPolicyRules(deny, policy.Deny),
	})
	if err != nil {
		return runtime.NetworkAttachment{}, err
	}
	return runtime.NetworkAttachment{
		SocketPath:   net.SocketPath,
		QEMUEndpoint: net.QEMUEndpoint,
		MAC:          net.MAC,
		DeviceIP:     net.DeviceIP,
		GatewayIP:    net.GatewayIP,
		Annotations:  net.Annotations,
	}, nil
}

// StartOwned binds a successful start to its journal token for this process.
func (a *Adapter) StartOwned(ctx context.Context, sandbox, token string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	if token == "" {
		return runtime.NetworkAttachment{}, runtime.ErrOwnershipUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	attachment, err := a.start(ctx, sandbox, ports, allow, deny)
	if err == nil {
		a.owned[sandbox] = token
	}
	return attachment, err
}

// Binding sentinels distinguish a gateway this process confirmed stopped
// (absent) from one running without a journal token (foreign). Unknown
// sandboxes (e.g. after a daemon restart) stay foreign: fail closed.
const (
	absentBinding  = "\x00absent"
	foreignBinding = "\x00foreign"
)

// AttachmentState maps the adapter's binding table to the runtime tri-state.
func (a *Adapter) AttachmentState(_ context.Context, sandbox, token string) (runtime.AttachmentState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bound, ok := a.owned[sandbox]
	if !ok {
		return runtime.AttachmentForeign, nil
	}
	if bound == absentBinding {
		return runtime.AttachmentAbsent, nil
	}
	if token != "" && bound == token {
		return runtime.AttachmentOwned, nil
	}
	return runtime.AttachmentForeign, nil
}

// UpdatePolicy updates the sandbox gateway policy.
func (a *Adapter) UpdatePolicy(ctx context.Context, sandbox string, ports []runtime.Port, allow, deny []runtime.Rule, revision int) error {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	return a.manager.Reload(ctx, policy.Policy{
		Revision:  revision,
		SandboxID: sandbox,
		AuditPath: filepath.Join(a.auditDir, sandbox+".audit.jsonl"),
		Ports:     policyPorts,
		Allow:     toPolicyRules(allow, policy.Allow),
		Deny:      toPolicyRules(deny, policy.Deny),
	})
}

func (a *Adapter) UpdatePorts(ctx context.Context, sandbox string, ports []runtime.Port) error {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	return a.manager.SetPorts(ctx, sandbox, policyPorts)
}

func (a *Adapter) Stop(ctx context.Context, sandbox string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	err := a.manager.Stop(ctx, sandbox)
	if err == nil {
		a.owned[sandbox] = absentBinding
	}
	return err
}

// SetGitDaemon exposes only the gateway's verified, sandbox-owned Git forward.
// Managers without this optional capability fail closed.
func (a *Adapter) SetGitDaemon(ctx context.Context, sandbox string, enabled bool) (uint16, error) {
	forwarder, ok := a.manager.(runtime.GitDaemonForwarder)
	if !ok {
		return 0, errors.New("gateway manager does not support managed Git daemon forwarding")
	}
	return forwarder.SetGitDaemon(ctx, sandbox, enabled)
}

var _ runtime.NetworkAttester = (*Adapter)(nil)
var _ runtime.Network = (*Adapter)(nil)
var _ runtime.GitDaemonForwarder = (*Adapter)(nil)

func toPolicyRules(rules []runtime.Rule, action policy.Action) []policy.Rule {
	out := make([]policy.Rule, 0, len(rules))
	for i := range rules {
		out = append(out, policy.Rule{ID: rules[i].ID, Action: action, Protocol: rules[i].Protocol, CIDR: rules[i].CIDR, Port: rules[i].Port, Domain: rules[i].Domain, Methods: rules[i].Methods, Path: rules[i].Path, Query: policyQueryConditions(rules[i].Query)})
	}
	return out
}

func policyQueryConditions(conditions []runtime.QueryCondition) []policy.QueryParam {
	if len(conditions) == 0 {
		return nil
	}
	out := make([]policy.QueryParam, 0, len(conditions))
	for _, c := range conditions {
		out = append(out, policy.QueryParam{Name: c.Name, Value: c.Value})
	}
	return out
}

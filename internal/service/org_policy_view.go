package service

import (
	"context"
	"fmt"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/orgpolicy"
)

// OrgPolicyRule is one non-secret rule in the effective organization policy
// view. Enforced reflects the current org_policy.enforce setting; Advisory
// rules are display-only and grant or deny nothing.
type OrgPolicyRule struct {
	RuleID         string
	Action         string
	Source         string
	ResourceType   string
	Protocol       string
	CIDR           string
	Domain         string
	Port           uint16
	Enforced       bool
	AdvisoryReason string
}

// OrgPolicyView is a read-only, non-secret snapshot of the stored
// organization policy bundle. It never contains the stored signature, tokens,
// vault references or any other secret material.
type OrgPolicyView struct {
	OrgID              string
	SchemaVersion      int
	Revision           uint64
	BundleID           string
	EnforcementEnabled bool
	LoadedAt           time.Time
	IssuedAt           time.Time
	ExpiresAt          time.Time
	IgnoredRules       int
	Rules              []OrgPolicyRule
}

// GetOrgPolicy loads the stored bundle and returns its effective view. Reads
// are side-effect free. A missing or invalid bundle fails closed with a typed
// orgpolicy error; callers must not substitute an empty policy.
func (s *Service) GetOrgPolicy(ctx context.Context) (OrgPolicyView, error) {
	org := s.OrgPolicyOrg
	view, err := orgpolicy.Inspect(ctx, s.store, org, s.now().UTC())
	if err != nil {
		return OrgPolicyView{}, fmt.Errorf("read organization policy: %w", err)
	}
	out := OrgPolicyView{
		OrgID:              view.OrgID,
		SchemaVersion:      view.SchemaVersion,
		Revision:           view.Revision,
		BundleID:           view.BundleID,
		EnforcementEnabled: s.OrgPolicyEnforce,
		LoadedAt:           view.LoadedAt,
		IssuedAt:           view.IssuedAt,
		ExpiresAt:          view.ExpiresAt,
		IgnoredRules:       view.IgnoredRules,
		Rules:              make([]OrgPolicyRule, 0, len(view.Rules)),
	}
	for i := range view.Rules {
		rule := &view.Rules[i]
		enforced := s.OrgPolicyEnforce && rule.Enforceable
		reason := rule.AdvisoryReason
		if rule.Enforceable && !s.OrgPolicyEnforce {
			reason = "org_policy.enforce is disabled"
		}
		out.Rules = append(out.Rules, OrgPolicyRule{
			RuleID:         rule.RuleID,
			Action:         rule.Action,
			Source:         rule.Source,
			ResourceType:   rule.ResourceType,
			Protocol:       rule.Protocol,
			CIDR:           rule.CIDR,
			Domain:         rule.Domain,
			Port:           rule.Port,
			Enforced:       enforced,
			AdvisoryReason: reason,
		})
	}
	return out, nil
}

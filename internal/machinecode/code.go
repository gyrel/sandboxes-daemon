// Package machinecode defines stable reasons for daemon refusals.
package machinecode

import "errors"

type Code string

const (
	NotOwned         Code = "NOT_OWNED"
	PathEscape       Code = "PATH_ESCAPE"
	PartialRemoval   Code = "PARTIAL_REMOVAL"
	Stale            Code = "STALE"
	SpecInvalid      Code = "SPEC_INVALID"
	PolicyDeny       Code = "POLICY_DENY"
	UnknownState     Code = "UNKNOWN_STATE"
	NotFound         Code = "NOT_FOUND"
	NameInvalid      Code = "NAME_INVALID"
	NameConflict     Code = "NAME_CONFLICT"
	EnvInvalid       Code = "ENV_INVALID"
	Busy             Code = "BUSY"
	QuotaExceeded    Code = "QUOTA_EXCEEDED"
	BindForbidden    Code = "BIND_FORBIDDEN"
	PortInUse        Code = "PORT_IN_USE"
	ProbeUnavailable Code = "PROBE_UNAVAILABLE"
	SessionUnreaped  Code = "SESSION_UNREAPED"
)

// All returns the registered reasons in declaration order.
func All() []Code {
	return []Code{NotOwned, PathEscape, PartialRemoval, Stale, SpecInvalid, PolicyDeny, UnknownState, NotFound, NameInvalid, NameConflict, EnvInvalid, Busy, QuotaExceeded, BindForbidden, PortInUse, ProbeUnavailable, SessionUnreaped}
}

type refusal struct {
	code  Code
	cause error
}

func (r *refusal) Error() string { return r.cause.Error() }
func (r *refusal) Unwrap() error { return r.cause }

// Attach preserves the original message and error chain.
func Attach(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &refusal{code, err}
}

// Of finds a reason through wrapping and joined causes.
func Of(err error) (Code, bool) {
	var r *refusal
	if errors.As(err, &r) {
		return r.code, true
	}
	return "", false
}

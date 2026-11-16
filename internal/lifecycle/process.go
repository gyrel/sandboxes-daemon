package lifecycle

import "os"

// ProcessInspector proves that a PID still names the process recorded in the
// control file. Implementations must return ErrProcessNotFound when the PID no
// longer exists and any other error when identity cannot be proven.
type ProcessInspector interface {
	StartIdentity(pid int) (string, error)
}

// SystemInspector reads process identity from the operating system.
type SystemInspector struct{}

// StartIdentity returns an opaque token that changes whenever a PID is reused.
func (SystemInspector) StartIdentity(pid int) (string, error) {
	return startIdentity(pid)
}

// CurrentProcessStartID returns the identity token of this process.
func CurrentProcessStartID() (string, error) {
	return startIdentity(os.Getpid())
}

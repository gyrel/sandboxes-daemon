//go:build darwin || linux

package servicesecrets

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

func hostShellArgv(command string) []string {
	return []string{"/bin/sh", "-c", command}
}

func hostShellCommand(ctx context.Context, command string) *exec.Cmd {
	argv := hostShellArgv(command)
	//nolint:gosec // Explicit --command source requires a trusted host approval bound to this exact argv.
	return exec.CommandContext(ctx, argv[0], argv[1:]...)
}

func startResolverProcess(command *exec.Cmd) (func() error, func() error, error) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	terminate := func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return terminate, terminate, nil
}

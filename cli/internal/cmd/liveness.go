package cmd

import (
	"errors"
	"os"
	"syscall"
)

// processAlive is lock.go's staleness accelerator; every uncertain answer is
// "alive", since os.FindProcess never fails and Signal(0) is the real check.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	switch err = p.Signal(syscall.Signal(0)); {
	case err == nil:
		return true
	case errors.Is(err, os.ErrProcessDone), errors.Is(err, syscall.ESRCH):
		return false
	default:
		// EPERM: another user's process, which exists; "cannot tell" so alive.
		return true
	}
}

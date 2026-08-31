package cmd

import (
	"errors"
	"os"
	"syscall"
)

// processAlive is the staleness accelerator described at the top of lock.go, and
// every uncertain answer is "alive".
//
// os.FindProcess never fails — it does not look the pid up — so the question is
// entirely Signal(0)'s to answer.
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
		// EPERM: another user's process, which exists. "Cannot tell" is
		// reported as alive so the heartbeat decides instead.
		return true
	}
}

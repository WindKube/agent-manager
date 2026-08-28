package cmd

import (
	"errors"
	"syscall"
)

// errorInvalidParameter is what OpenProcess returns for a pid that does not
// exist. syscall declares it unexported (_ERROR_INVALID_PARAMETER), so the
// number is repeated here rather than reached for.
const errorInvalidParameter = syscall.Errno(87)

// processAlive is the staleness accelerator described at the top of lock.go, and
// every uncertain answer is "alive".
//
// Windows needs its own implementation, and NOT because Signal is unsupported —
// because the generic version silently reports every Windows process as alive:
//
//   - os.FindProcess wraps OpenProcess, which SUCCEEDS for a process that has
//     already exited while any handle to it remains open (the usual case for a
//     child whose parent has not waited on it). So a failed FindProcess is a
//     sound "gone", but a successful one is not "alive".
//   - Process.Signal then returns EINVAL for anything but Kill, which the
//     generic switch reads as "cannot tell" and reports as alive.
//
// Together those made the accelerator dead code on Windows: a killed amctl held
// its home for the full lockStaleAfter window. The Windows CI leg measured that.
//
// WaitForSingleObject with a zero timeout is the poll that actually answers the
// question: a process handle becomes signalled when the process exits, so
// WAIT_OBJECT_0 means gone and WAIT_TIMEOUT means running. GetExitCodeProcess
// would be the other candidate and is deliberately not used — a process can
// legitimately exit with code 259, which is indistinguishable from its
// STILL_ACTIVE sentinel.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// Only "no such pid" is a sound "gone". Access denied means the process
		// exists and belongs to someone else, which must read as alive — the
		// generic implementation's `return false` here would declare a live
		// holder dead, the one direction the heartbeat cannot recover from.
		return !errors.Is(err, errorInvalidParameter)
	}
	defer func() { _ = syscall.CloseHandle(h) }()

	event, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return true
	}
	return event != syscall.WAIT_OBJECT_0
}

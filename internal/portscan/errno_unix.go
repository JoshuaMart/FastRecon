//go:build unix

package portscan

import "syscall"

// Running out of file descriptors is a local limit, not a verdict about the
// target, so a probe that hits one is retried rather than recorded as closed.
var (
	syscallEMFILE error = syscall.EMFILE
	syscallENFILE error = syscall.ENFILE
)

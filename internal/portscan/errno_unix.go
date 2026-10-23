//go:build unix

package portscan

import (
	"errors"
	"syscall"
)

// Running out of file descriptors or ephemeral ports is a local limit, not a
// verdict about the target, so a probe that hits one is retried rather than
// recorded as closed.
var (
	syscallEMFILE        error = syscall.EMFILE
	syscallENFILE        error = syscall.ENFILE
	syscallEADDRNOTAVAIL error = syscall.EADDRNOTAVAIL
	// No route from here: says something about the scanner's network, not
	// about the port.
	syscallENETUNREACH error = syscall.ENETUNREACH
	// Something on the path answered for the target and refused to deliver,
	// which is what a filter looks like from the outside.
	syscallEHOSTUNREACH error = syscall.EHOSTUNREACH
)

// isRefused reports a connection the target itself turned down.
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

//go:build !unix

package portscan

import "errors"

// No portable equivalent outside unix; the sentinels simply never match.
var (
	syscallEMFILE = errors.New("emfile")
	syscallENFILE = errors.New("enfile")
)

//go:build !unix

package portscan

import "errors"

// No portable equivalent outside unix; the sentinels simply never match.
var (
	syscallEMFILE        = errors.New("emfile")
	syscallENFILE        = errors.New("enfile")
	syscallEADDRNOTAVAIL = errors.New("eaddrnotavail")
	syscallENETUNREACH   = errors.New("enetunreach")
	syscallEHOSTUNREACH  = errors.New("ehostunreach")
)

// isRefused cannot tell a refusal apart from other dial errors here, so it
// keeps treating every conclusive failure as one.
func isRefused(error) bool { return true }

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// terminate asks the wrapped server to stop. SIGTERM lets it clean up; the client
// closing our stdin is the usual path and normally gets there first.
func terminate(p *os.Process) {
	_ = p.Signal(syscall.SIGTERM)
}

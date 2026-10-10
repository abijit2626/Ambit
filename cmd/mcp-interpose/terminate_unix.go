//go:build !windows

package main

import (
	"os"
	"syscall"
)

func terminate(p *os.Process) {
	_ = p.Signal(syscall.SIGTERM)
}

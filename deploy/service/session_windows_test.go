//go:build windows

package service

import (
	"os/exec"
	"syscall"
)

func newSession() *syscall.SysProcAttr { return nil }

func stopSession(c *exec.Cmd) {
	if c.Process != nil {
		_ = c.Process.Kill()
	}
}

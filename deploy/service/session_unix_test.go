//go:build !windows

package service

import (
	"os/exec"
	"syscall"
)

func newSession() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

func stopSession(c *exec.Cmd) {
	if c.Process != nil {
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		_, _ = c.Process.Wait()
	}
}

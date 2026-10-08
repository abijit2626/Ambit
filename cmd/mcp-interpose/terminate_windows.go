//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func terminate(p *os.Process) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	taskkill := filepath.Join(root, "System32", "taskkill.exe")
	if err := exec.Command(taskkill, "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run(); err != nil {
		_ = p.Kill()
	}
}

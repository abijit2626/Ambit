//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// terminate stops the wrapped server and the processes it started.
//
// Windows has no SIGTERM: os.Process.Signal returns an error for everything except
// Kill. And the usual way to wrap an MCP server there is `npx` or a .cmd shim, so the
// process we started is a shell and the server is its child; killing only the shell
// would orphan the server, which is the outcome the signal forwarding exists to
// prevent. taskkill /T ends the whole tree. It is invoked by absolute path under
// SystemRoot for the same reason fsperm invokes icacls that way.
//
// It addresses the process by PID, so it must only be called while the process is
// known to be alive and unreaped; run() guarantees that. The job object in
// jobobject_windows.go covers the cases where this never runs at all.
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

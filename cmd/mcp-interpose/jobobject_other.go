//go:build !windows

package main

// killChildrenOnExit has nothing to do on Unix: a SIGTERM reaches us and terminate
// forwards it, and a server whose parent has gone sees its stdin close.
func killChildrenOnExit() error { return nil }

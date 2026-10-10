//go:build !windows

package fsperm

func restrict(string) error { return nil }

func checkExisting(string) error { return nil }

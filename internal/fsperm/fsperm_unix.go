//go:build !windows

package fsperm

// restrict has nothing to add on Unix: Mkdir(dir, 0o700) already made the directory
// owner-only, and the files inside are created 0o600.
func restrict(string) error { return nil }

// checkExisting has nothing to add on Unix either. The files ambit creates are 0o600
// whatever the directory's mode, so a directory somebody else made more permissive
// does not expose them, and tightening it is not ours to do.
func checkExisting(string) error { return nil }

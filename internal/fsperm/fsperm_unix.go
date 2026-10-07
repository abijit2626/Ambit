//go:build !windows

package fsperm

// restrict has nothing to add on Unix: MkdirAll(dir, 0o700) already made the
// directory owner-only, and the files inside are created 0o600.
func restrict(string) error { return nil }

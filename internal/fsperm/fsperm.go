// Package fsperm creates the directories ambit keeps private.
//
// The spool holds prompt text, the events sink holds metadata an external firm will
// read a filtered copy of, the fingerprint key must never be readable by another
// account, and the MCP baseline store is what an attacker would rewrite to make a rug
// pull read as approved. On Unix a 0700 directory is the whole control. On Windows
// the mode bits mean nothing — os.Mkdir(0o700) creates a directory that inherits
// whatever its parent allows, and under C:\ProgramData that includes every local
// user — so the same intent needs an ACL.
package fsperm

import "os"

// PrivateDir creates dir and any missing parents. If dir did not already exist, it is
// left readable only by its owner and, on Windows, by SYSTEM and Administrators (the
// Wazuh agent runs as SYSTEM and has to read events.jsonl).
//
// A directory that already exists is never changed. Tightening a directory somebody
// else created would be a surprise at best and, for a path like C:\ProgramData, a
// way to lock every other program out of it, so the caller's own permissions on an
// existing directory stand.
func PrivateDir(dir string) error {
	_, statErr := os.Stat(dir)
	existed := statErr == nil
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if existed {
		return nil
	}
	return restrict(dir)
}

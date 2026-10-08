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

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotPrivate is returned, wrapped, for a directory that already exists and that
// ambit cannot treat as private.
var ErrNotPrivate = errors.New("directory is not private")

// restrictDir is restrict, replaceable so a test can make it fail on any platform.
var restrictDir = restrict

// PrivateDir makes sure dir exists and is private. Every directory it has to create,
// parents included, is left readable only by its owner and, on Windows, by SYSTEM and
// Administrators (the Wazuh agent runs as SYSTEM and has to read events.jsonl).
// Parents matter: a leaf restricted under a parent created with the inherited ACL
// would leave the parent listable and replaceable by every local user, and a later
// run, finding the parent already there, would never fix it.
//
// If restricting a directory fails, everything this call created is removed again. A
// directory left behind with its inherited ACL would be found by the next run, taken
// for somebody else's, and trusted.
//
// A directory that already exists is never changed. Tightening a directory somebody
// else created would be a surprise at best and, for a path like C:\ProgramData, a
// way to lock every other program out of it. But it is not trusted blindly either:
// on Windows, where there is no per-file mode to fall back on, an existing directory
// that other accounts can read, or that another account owns, is refused with
// ErrNotPrivate rather than quietly filled with prompt text and key material. See
// checkExisting.
func PrivateDir(dir string) error {
	dir = filepath.Clean(dir)
	missing, err := missingDirs(dir)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return checkExisting(dir)
	}

	var made []string
	undo := func() {
		for i := len(made) - 1; i >= 0; i-- {
			_ = os.Remove(made[i])
		}
	}
	for _, d := range missing {
		if err := os.Mkdir(d, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				// Another ambit process (ambitd and mcp-interpose start independently)
				// created it since we looked. It is somebody else's now.
				if cerr := checkExisting(d); cerr != nil {
					undo()
					return cerr
				}
				continue
			}
			undo()
			return err
		}
		made = append(made, d)
		if err := restrictDir(d); err != nil {
			undo()
			return err
		}
	}
	return nil
}

// missingDirs returns the directories from dir upward that do not exist yet,
// outermost first. It fails if an existing path component is not a directory.
func missingDirs(dir string) ([]string, error) {
	var missing []string
	for d := dir; ; {
		st, err := os.Stat(d)
		if err == nil {
			if !st.IsDir() {
				return nil, fmt.Errorf("fsperm: %s exists and is not a directory", d)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, d)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}
	return missing, nil
}

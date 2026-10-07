//go:build windows

package fsperm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Well-known SIDs, which are the same on every Windows machine and in every locale,
// unlike the names "SYSTEM" and "Administrators".
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// restrict replaces dir's ACL with full control for the current user, SYSTEM and
// Administrators, inherited by everything created inside, and removes every
// inherited entry — which is what grants BUILTIN\Users read access under
// C:\ProgramData.
//
// It shells out to icacls rather than calling SetNamedSecurityInfo because ambitd has
// no third-party dependencies by design, and the standard library's syscall package
// does not expose ACL editing. icacls is invoked by absolute path under SystemRoot so
// a hostile PATH cannot substitute it: this binary runs on the same endpoint the
// threat model says may already be compromised.
func restrict(dir string) error {
	user, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("fsperm: current user: %w", err)
	}
	args := []string{dir, "/inheritance:r"}
	for _, sid := range []string{user, sidSystem, sidAdministrators} {
		args = append(args, "/grant:r", "*"+sid+":(OI)(CI)F")
	}
	out, err := exec.Command(icacls(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fsperm: icacls %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func icacls() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "icacls.exe")
}

func currentUserSID() (string, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}
